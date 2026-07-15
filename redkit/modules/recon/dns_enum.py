"""DNS enumeration module for redkit (recon phase).

Enumerates DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA), performs threaded
subdomain brute forcing and optionally tests each authoritative name server
for an unrestricted zone transfer (AXFR).

Design constraints (redkit invariants):
  * Pure standard library. ``dig`` / ``nslookup`` are used opportunistically
    when present, but are never required -- the module transparently degrades
    to ``socket``-based A/AAAA resolution when no external resolver tool is
    available.
  * No AI/LLM usage and no network egress beyond ordinary DNS resolution of
    the operator-supplied domain.
  * Imports cleanly on Windows and Linux; no OS-specific calls at import time.
  * Bounded timeouts and a thread pool capped at 100 workers.

This is for AUTHORIZED security testing only.
"""
from __future__ import annotations

import json
import random
import re
import socket
import string
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeout,
    as_completed,
)
from pathlib import Path
from typing import Dict, List, Tuple

from redkit.core import config
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
MAX_THREADS = 100
_RESOLVE_TIMEOUT = 3.0  # per-lookup socket timeout (best effort)


# --------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------
def _normalise_domain(value: str) -> str:
    """Trim a user-supplied domain: drop scheme, path, trailing dot, case."""
    d = (value or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", d)  # strip URL scheme if pasted
    d = d.split("/", 1)[0]                        # drop any path component
    if "@" in d:                                  # tolerate an email address
        d = d.split("@", 1)[-1]
    return d.strip().rstrip(".")


def _clean_host(value: str) -> str:
    """Normalise a hostname from record output (strip trailing dot / space)."""
    return (value or "").strip().rstrip(".").strip()


def _is_ip(value: str) -> bool:
    """True if ``value`` is a valid IPv4 or IPv6 literal."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except (OSError, ValueError, TypeError):
            continue
    return False


def _load_wordlist(value: str) -> List[str]:
    """Resolve the ``wordlist`` option to an ordered, de-duplicated list.

    ``value`` may be a filesystem path or the name of a bundled wordlist
    (resolved via :func:`redkit.core.config.wordlist`).
    """
    path: Path
    if value and Path(value).is_file():
        path = Path(value)
    else:
        path = config.wordlist(value or "subdomains-top.txt")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    seen: set = set()
    out: List[str] = []
    for line in text.splitlines():
        label = line.strip()
        if not label or label.startswith("#"):
            continue
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _resolve_all(name: str) -> List[str]:
    """Return sorted unique IPs (v4 + v6) for ``name``; [] on any failure."""
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        return []
    ips: set = set()
    for info in infos:
        sockaddr = info[4] if len(info) > 4 else None
        if sockaddr and sockaddr[0]:
            ips.add(sockaddr[0])
    return sorted(ips)


# --------------------------------------------------------------------------
# external-tool query backends (optional; guarded by ctx.runner.have)
# --------------------------------------------------------------------------
def _dig(ctx, domain: str, rtype: str, resolver: str, timeout: float = 15.0) -> List[str]:
    """Query one record type with ``dig +short``. Returns [] on timeout."""
    cmd = ["dig", "+short", "+tries=2", "+time=3"]
    if resolver:
        cmd.append(f"@{resolver}")
    cmd += [domain, rtype]
    res = ctx.runner.run(cmd, timeout=timeout)
    if res.timed_out:
        return []
    out: List[str] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            out.append(line)
    return out


def _nslookup(ctx, domain: str, rtype: str, resolver: str, timeout: float = 20.0) -> List[str]:
    """Query one record type via ``nslookup`` and parse its output."""
    cmd = ["nslookup", f"-type={rtype}", domain]
    if resolver:
        cmd.append(resolver)
    res = ctx.runner.run(cmd, timeout=timeout)
    if res.timed_out:
        return []
    return _parse_nslookup(res.text, rtype)


def _parse_nslookup(text: str, rtype: str) -> List[str]:
    """Best-effort parse of ``nslookup`` output across Windows/Unix formats."""
    lines = text.splitlines()
    out: List[str] = []

    if rtype in ("A", "AAAA"):
        # Only collect addresses that appear after the answer's "Name:" marker,
        # which reliably excludes the leading resolver "Server/Address" block.
        seen_name = False
        for line in lines:
            s = line.strip()
            low = s.lower()
            if low.startswith("name:"):
                seen_name = True
                continue
            if seen_name and (low.startswith("address:") or low.startswith("addresses:")):
                val = s.split(":", 1)[1].strip()
                for ip in re.split(r"[,\s]+", val):
                    ip = ip.strip()
                    if ip and _is_ip(ip):
                        out.append(ip)
        return out

    patterns = {
        "MX": re.compile(r"mail exchanger\s*=\s*(?:(\d+)\s+)?(\S+)", re.I),
        "NS": re.compile(r"nameserver\s*=\s*(\S+)", re.I),
        "CNAME": re.compile(r"canonical name\s*=\s*(\S+)", re.I),
        "TXT": re.compile(r'text\s*=\s*"?(.*?)"?\s*$', re.I),
        "SOA": re.compile(r"(?:origin|primary name server)\s*=\s*(\S+)", re.I),
    }
    pat = patterns.get(rtype)
    if pat is None:
        return out
    for line in lines:
        m = pat.search(line)
        if not m:
            continue
        if rtype == "MX":
            pref, host = m.group(1), m.group(2)
            out.append((f"{pref} {host}" if pref else host).strip())
        else:
            out.append((m.group(m.lastindex or 1) or "").strip())
    return out


def _axfr(ctx, ns: str, domain: str, timeout: float = 30.0) -> Tuple[List[str], str]:
    """Attempt ``dig ... AXFR`` against ``ns``. Returns (records, raw_output)."""
    cmd = ["dig", "+nocmd", "+tries=1", "+time=5", f"@{ns}", domain, "AXFR"]
    res = ctx.runner.run(cmd, timeout=timeout)
    raw = res.stdout or ""
    if res.timed_out:
        return [], raw
    records: List[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if re.search(r"\bIN\b", s):
            records.append(s)
    return records, raw


# --------------------------------------------------------------------------
# module
# --------------------------------------------------------------------------
@register
class DnsEnum(Module):
    """DNS record enumeration, subdomain brute force and AXFR testing."""

    name = "recon.dns_enum"
    description = "DNS record enumeration, subdomain brute force and zone-transfer testing"
    phase = "recon"
    options = [
        Option("domain", help="Target domain, e.g. example.com", required=True),
        Option("wordlist", default="subdomains-top.txt",
               help="Subdomain wordlist (bundled name or filesystem path)"),
        Option("threads", default=50, help="Concurrent resolver threads (capped at 100)"),
        Option("do_axfr", default=True, help="Attempt DNS zone transfer (AXFR) against each NS"),
        Option("resolver", default="", help="Optional DNS resolver IP for dig/nslookup queries"),
    ]
    requires_tools = []  # dig / nslookup are optional; socket fallback always works
    references = [
        "https://datatracker.ietf.org/doc/html/rfc5936",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]

    def run(self, opts, ctx) -> Result:
        domain = _normalise_domain(opts["domain"])
        if not domain or "." not in domain:
            return Result(ok=False, summary=f"invalid domain: {opts['domain']!r}")

        resolver = (opts.get("resolver") or "").strip()
        do_axfr = bool(opts.get("do_axfr"))
        threads = max(1, min(int(opts.get("threads") or 1), MAX_THREADS))

        ctx.console.banner("DNS enumeration", domain)

        # -- choose a record-query backend ---------------------------------
        have_dig = ctx.runner.have("dig")
        have_nslookup = ctx.runner.have("nslookup")
        if have_dig:
            method = "dig"
        elif have_nslookup:
            method = "nslookup"
        else:
            method = "socket"
        ctx.console.info(f"record backend: {method}")

        records: Dict[str, List[str]] = {rt: [] for rt in RECORD_TYPES}
        if method == "socket":
            for ip in _resolve_all(domain):
                records["AAAA" if ":" in ip else "A"].append(ip)
        else:
            for rt in RECORD_TYPES:
                try:
                    if method == "dig":
                        records[rt] = _dig(ctx, domain, rt, resolver)
                    else:
                        records[rt] = _nslookup(ctx, domain, rt, resolver)
                except Exception as exc:  # never let one bad query kill the run
                    ctx.console.debug(f"{rt} query failed: {exc}")

        # Fallback resolution if the tool produced no address records.
        if not records["A"] and not records["AAAA"]:
            for ip in _resolve_all(domain):
                records["AAAA" if ":" in ip else "A"].append(ip)

        # -- persist apex + name/mail servers into the engagement ----------
        apex_ips = [ip for ip in (records["A"] + records["AAAA"]) if _is_ip(ip)]
        for ip in apex_ips:
            ctx.engagement.add_host(ip, hostname=domain)

        ns_hosts = sorted({_clean_host(x) for x in records.get("NS", []) if _clean_host(x)})
        for ns in ns_hosts:
            for ip in _resolve_all(ns):
                if _is_ip(ip):
                    ctx.engagement.add_host(ip, hostname=ns)
                    ctx.engagement.add_service(ip, 53, proto="udp", service="dns", product=ns)

        mx_hosts: List[str] = []
        for entry in records.get("MX", []):
            parts = entry.split()
            host = _clean_host(parts[-1]) if parts else ""
            if host and host not in mx_hosts:
                mx_hosts.append(host)
        for mx in mx_hosts:
            for ip in _resolve_all(mx):
                if _is_ip(ip):
                    ctx.engagement.add_host(ip, hostname=mx)
                    ctx.engagement.add_service(ip, 25, proto="tcp", service="smtp", product=mx)

        ctx.console.table(
            ["type", "records"],
            [(rt, ", ".join(records[rt])[:100] if records[rt] else "-") for rt in RECORD_TYPES],
        )

        # -- subdomain brute force -----------------------------------------
        words = _load_wordlist(opts.get("wordlist"))
        found: Dict[str, List[str]] = {}
        wildcard_ips: List[str] = []
        if words:
            probe = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
            wildcard_ips = _resolve_all(f"{probe}.{domain}")
            if wildcard_ips:
                ctx.console.warn(
                    f"wildcard DNS detected ({', '.join(wildcard_ips)}); filtering matches"
                )
                ctx.engagement.add_note(
                    f"{domain}: wildcard DNS resolves to {', '.join(wildcard_ips)}"
                )
            found = self._brute(ctx, domain, words, threads, set(wildcard_ips))
            for sub, ips in found.items():
                for ip in ips:
                    ctx.engagement.add_host(ip, hostname=sub)
            ctx.console.good(
                f"resolved {len(found)} subdomain(s) from {len(words)} candidate(s)"
            )
        else:
            ctx.console.warn("no wordlist entries; skipping subdomain brute force")

        # -- zone transfer (AXFR) ------------------------------------------
        axfr_results: Dict[str, List[str]] = {}
        axfr_allowed = False
        axfr_attempted = bool(do_axfr and have_dig and ns_hosts)
        if do_axfr:
            if not have_dig:
                ctx.console.warn(
                    "do_axfr requested but 'dig' not found; install dnsutils/bind-utils to enable AXFR"
                )
                ctx.engagement.add_note(f"{domain}: AXFR skipped (dig not installed)")
            elif not ns_hosts:
                ctx.console.warn("do_axfr requested but no NS records discovered; skipping AXFR")
            else:
                for ns in ns_hosts:
                    try:
                        recs, _raw = _axfr(ctx, ns, domain)
                    except Exception as exc:
                        ctx.console.debug(f"axfr @{ns} failed: {exc}")
                        continue
                    if not recs:
                        ctx.console.info(f"zone transfer refused by {ns}")
                        continue
                    axfr_allowed = True
                    axfr_results[ns] = recs
                    ctx.console.bad(f"zone transfer ALLOWED by {ns} ({len(recs)} records)")
                    ctx.engagement.add_finding(
                        title="DNS zone transfer allowed",
                        severity="high",
                        host=ns,
                        description=(
                            f"The name server {ns} permitted a full AXFR zone transfer of "
                            f"{domain}, exposing {len(recs)} internal DNS records to an "
                            f"unauthenticated client."
                        ),
                        evidence="\n".join(recs[:50]),
                    )
                    ctx.engagement.add_loot(
                        ns, "dns-zone", f"AXFR {domain} ({len(recs)} records)",
                        source="recon.dns_enum",
                    )
                    # harvest A/AAAA records disclosed by the transfer
                    for line in recs:
                        parts = line.split()
                        if (len(parts) >= 5 and parts[-2].upper() in ("A", "AAAA")
                                and _is_ip(parts[-1])):
                            ctx.engagement.add_host(parts[-1], hostname=_clean_host(parts[0]))

        # -- assemble result ------------------------------------------------
        data = {
            "domain": domain,
            "method": method,
            "resolver": resolver or None,
            "records": records,
            "nameservers": ns_hosts,
            "mailservers": mx_hosts,
            "subdomains": found,
            "subdomain_count": len(found),
            "wildcard": wildcard_ips or None,
            "axfr": {
                "attempted": axfr_attempted,
                "allowed": axfr_allowed,
                "servers": {ns: len(r) for ns, r in axfr_results.items()},
            },
        }

        artifacts: List[str] = []
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain) or "domain"
        try:
            path = ctx.artifact_path(f"dns_enum_{safe}.json")
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(path))
        except OSError as exc:
            ctx.console.warn(f"could not write artifact: {exc}")

        rec_total = sum(len(v) for v in records.values())
        summary = (
            f"{domain}: {rec_total} DNS record(s) via {method}, "
            f"{len(found)} subdomain(s) resolved"
            + (", AXFR ALLOWED" if axfr_allowed else "")
        )
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # ----------------------------------------------------------------------
    def _brute(self, ctx, domain: str, words: List[str], threads: int,
               wildcard_ips: set) -> Dict[str, List[str]]:
        """Threaded getaddrinfo brute force over ``<word>.<domain>``.

        Returns a mapping of resolvable subdomain -> non-wildcard IPs. A
        wall-clock budget guards against a hung resolver stalling the run.
        """
        found: Dict[str, List[str]] = {}
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(_RESOLVE_TIMEOUT)
        budget = max(60.0, min(600.0, len(words) * 1.0))
        try:
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(_resolve_all, f"{w}.{domain}"): w for w in words}
                try:
                    for fut in as_completed(futures, timeout=budget):
                        word = futures[fut]
                        try:
                            ips = fut.result()
                        except Exception:
                            ips = []
                        real = [ip for ip in ips if ip not in wildcard_ips]
                        if not real:
                            continue
                        sub = f"{word}.{domain}"
                        found[sub] = real
                        ctx.console.good(f"  {sub} -> {', '.join(real)}")
                except FuturesTimeout:
                    ctx.console.warn(
                        "subdomain brute force hit time budget; returning partial results"
                    )
                for fut in futures:  # best-effort cancel of pending lookups
                    fut.cancel()
        finally:
            socket.setdefaulttimeout(old_timeout)
        return dict(sorted(found.items()))
