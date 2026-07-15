"""Virtual-host discovery via Host-header fuzzing.

Many servers host several distinct sites/applications behind a single IP,
routed by the ``Host`` header rather than by IP or port. This module probes a
single URL repeatedly, swapping only the ``Host`` header for each candidate
word (optionally appended to an operator-supplied base domain), and reports
any candidate whose response differs meaningfully from a baseline response
obtained with a random, almost-certainly-unmatched ``Host`` value.

Design constraints (redkit invariants):
    * NO AI/LLM usage -- every decision here is a deterministic, rule-based
      comparison of status code / body length / page title against a
      baseline.
    * Pure standard library. All HTTP goes through the shared
      :mod:`redkit.core.http` client (proxy, cookie, TLS, timeout support
      included for free).
    * Imports and runs on both Windows and Linux; no OS-specific calls.
    * Offline-first: candidate words come from the bundled wordlist data
      unless the operator points at their own file.
    * Safe defaults: every probe is a GET, the thread pool is capped at 20
      workers, and the candidate list is capped to keep the run bounded.
"""
from __future__ import annotations

import re
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from redkit.core import config
from redkit.core.http import WEB_COMMON_OPTIONS, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

MAX_THREADS = 20          # hard invariant: capped thread pool
MAX_CANDIDATES = 5000      # bound the total number of probes issued

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# A response is considered a distinct vhost if it differs from the baseline
# by more than this fraction of the baseline's body length, or by this many
# bytes -- whichever is larger. Purely deterministic, no learning involved.
_LEN_RATIO_THRESHOLD = 0.10
_LEN_ABS_FLOOR = 32


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #
def _extract_title(text: str) -> str:
    """Pull and normalize an HTML <title> for cheap fingerprint comparison."""
    if not text:
        return ""
    match = _TITLE_RE.search(text)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120]


def _load_words(path: Path) -> List[str]:
    """Read a wordlist, skipping blanks/comments, deduping, order-preserving."""
    words: List[str] = []
    seen: set = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip().strip(".").lower()
                if not word or word.startswith("#"):
                    continue
                if word not in seen:
                    seen.add(word)
                    words.append(word)
    except OSError:
        return []
    return words


def _build_vhost(word: str, domain: str) -> str:
    """Combine a candidate word with the base domain, if one was supplied."""
    word = (word or "").strip().strip(".")
    if not word:
        return ""
    return f"{word}.{domain}" if domain else word


def _random_host(domain: str) -> str:
    """A Host value that should never match a real vhost -- the baseline."""
    label = f"redkit-vhost-{uuid.uuid4().hex[:16]}"
    return f"{label}.{domain}" if domain else f"{label}.invalid"


def _differs(entry: Dict[str, object], baseline: Dict[str, object]) -> bool:
    """Deterministic rule set: status change, body-length shift, or title change."""
    if entry["status"] != baseline["status"]:
        return True
    base_len = int(baseline["length"])  # type: ignore[arg-type]
    delta = abs(int(entry["length"]) - base_len)  # type: ignore[arg-type]
    threshold = max(_LEN_ABS_FLOOR, int(base_len * _LEN_RATIO_THRESHOLD))
    if delta > threshold:
        return True
    entry_title, base_title = entry.get("title"), baseline.get("title")
    if entry_title and base_title and entry_title != base_title:
        return True
    return False


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class VhostFuzz(Module):
    """Discover hidden virtual hosts by fuzzing the HTTP ``Host`` header."""

    name = "web.vhost"
    description = "Virtual-host discovery via Host-header fuzzing against a single URL"
    phase = "web"
    options = [
        Option("url", help="target URL (or bare IP/host) every probe is sent to", required=True),
        Option("domain", default="", help="base domain appended to each word, e.g. example.com -> word.example.com"),
        Option("wordlist", default="subdomains-top.txt", help="bundled wordlist name or path with candidate vhost words"),
        Option("threads", default=20, help="concurrent probe workers (capped at 20)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
        "https://portswigger.net/web-security/host-header",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts["url"]).strip()
        if not raw_url:
            return Result(ok=False, summary="url is required")
        url = raw_url if "://" in raw_url else f"http://{raw_url}"
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r} (expected http(s)://host)")
        target_host = parsed.hostname

        domain = str(opts.get("domain") or "").strip().strip(".").lower()
        threads = max(1, min(int(opts["threads"]), MAX_THREADS))

        data: Dict[str, object] = {
            "url": url,
            "domain": domain,
            "candidates_tried": 0,
            "baseline": None,
            "vhosts": [],
        }

        words = self._resolve_wordlist(str(opts["wordlist"]), ctx)
        if not words:
            return Result(ok=False, summary="no wordlist candidates available", data=data)

        candidates: List[str] = []
        seen: set = set()
        for word in words[:MAX_CANDIDATES]:
            host = _build_vhost(word, domain)
            if host and host not in seen:
                seen.add(host)
                candidates.append(host)
        if not candidates:
            return Result(ok=False, summary="wordlist produced no usable vhost candidates", data=data)

        client = client_from_opts(opts)
        baseline_host = _random_host(domain)
        console.info(
            f"vhost fuzz {url}  (baseline Host: {baseline_host}, "
            f"{len(candidates)} candidate(s), {threads} threads)"
        )

        baseline_resp = client.get(url, headers={"Host": baseline_host}, allow_redirects=False)
        if baseline_resp.status == 0:
            console.bad(f"target unreachable: {baseline_resp.error}")
            ctx.engagement.add_note(f"vhost: {url} unreachable ({baseline_resp.error})")
            return Result(ok=False, summary=f"{url} unreachable: {baseline_resp.error}", data=data)

        baseline = {
            "host": baseline_host,
            "status": baseline_resp.status,
            "length": baseline_resp.length,
            "title": _extract_title(baseline_resp.text),
        }
        data["baseline"] = baseline
        console.debug(
            f"baseline -> status={baseline['status']} length={baseline['length']} title={baseline['title']!r}"
        )

        data["candidates_tried"] = len(candidates)
        results = self._fuzz(client, url, candidates, baseline, threads, console)
        for entry in results:
            self._record(entry, baseline, target_host, url, ctx)

        data["vhosts"] = [
            {"host": e["host"], "status": e["status"], "length": e["length"]} for e in results
        ]
        artifacts = self._write_artifact(ctx, data, target_host)

        summary = f"{url}: {len(results)} distinct vhost(s) found out of {len(candidates)} tried"
        ctx.engagement.add_note(f"vhost: {summary}")
        if results:
            console.good(summary)
        else:
            console.info(summary)
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # -------------------------------------------------------- internals -- #
    def _resolve_wordlist(self, wordlist_name: str, ctx) -> List[str]:
        """Resolve to a word list, offline-first (bundled name or a real path)."""
        name = (wordlist_name or "").strip() or "subdomains-top.txt"
        candidates = []
        raw = Path(name)
        if raw.is_absolute() or raw.exists():
            candidates.append(raw)
        candidates.append(config.wordlist(name))
        for path in candidates:
            try:
                if path.exists():
                    words = _load_words(path)
                    if words:
                        return words
            except OSError:
                continue
        ctx.console.warn(
            f"wordlist '{name}' not found (looked in cwd and bundled data); skipping vhost fuzz"
        )
        return []

    def _fuzz(self, client, url, candidates, baseline, threads, console) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        workers = max(1, min(threads, MAX_THREADS, len(candidates)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(self._probe, client, url, host): host for host in candidates}
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    resp = future.result()
                except Exception:  # noqa: BLE001 - a single probe must never abort the run
                    continue
                if resp is None or resp.status == 0:
                    continue  # transport error / timeout on this candidate -- not a signal
                entry = {
                    "host": host,
                    "status": resp.status,
                    "length": resp.length,
                    "title": _extract_title(resp.text),
                }
                if _differs(entry, baseline):
                    results.append(entry)
        results.sort(key=lambda e: str(e["host"]))
        console.info(f"{len(results)} candidate(s) differed from baseline")
        return results

    @staticmethod
    def _probe(client, url: str, host: str):
        return client.get(url, headers={"Host": host}, allow_redirects=False)

    @staticmethod
    def _record(entry: Dict[str, object], baseline: Dict[str, object], target_host: str, url: str, ctx) -> None:
        status = int(entry["status"])  # type: ignore[arg-type]
        severity = "low" if 200 <= status < 300 else "info"
        title = f"Possible virtual host discovered: {entry['host']}"
        description = (
            f"Host header '{entry['host']}' returned HTTP {status} / {entry['length']} bytes "
            f"(baseline was HTTP {baseline['status']} / {baseline['length']} bytes) when sent to {url}."
        )
        ctx.engagement.add_finding(
            title,
            severity=severity,
            host=target_host,
            description=description,
            evidence=url,
        )
        ctx.engagement.add_loot(target_host, "vhost", str(entry["host"]), source="vhost-fuzz")

    @staticmethod
    def _write_artifact(ctx, data: Dict[str, object], target_host: str) -> List[str]:
        import json

        artifacts: List[str] = []
        safe_host = (target_host or "target").replace(":", "_")
        try:
            path = ctx.artifact_path(f"vhost_{safe_host}.json")
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(path))
        except OSError:
            pass
        return artifacts
