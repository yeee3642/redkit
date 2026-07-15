"""Live host discovery over a CIDR, range, or comma list.

Three deterministic, rule-based discovery methods -- no AI, no external
scanner required for the default path:

``tcp``
    Pure-python connect scan. A host is considered alive if a TCP handshake
    completes to *any* of the probe ports. Open ports are recorded as
    services in the engagement so later modules can pick them up.
``ping``
    Shell out to the OS ``ping`` binary (``ping -n 1 -w <ms>`` on Windows,
    ``ping -c 1 -W <s>`` elsewhere) via ``ctx.runner``. Falls back to the
    ``tcp`` method if no ``ping`` binary is present.
``arp``
    Parse ``arp -a`` output (available on both Windows and Linux/macOS) to
    enumerate already-known layer-2 neighbours. No probing -- reads the local
    ARP cache and filters entries down to the requested scope.

Everything is standard library and bounded: the target expansion is capped,
the thread pool is capped at 100, and every socket / subprocess call has a
finite timeout so an unreachable network cannot hang the run.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Hard ceiling on how many hosts we will ever materialise / probe. A /16 is
# 65536 addresses; anything larger is almost certainly a misconfigured scope
# and would blow up memory and runtime, so we refuse it with a clear message.
MAX_HOSTS = 65536

# Cap on distinct probe ports per host for the tcp method, to keep the total
# connection fan-out sane even on a large scope.
MAX_PORTS = 128

# Absolute cap on the worker pool regardless of what the operator requests.
MAX_THREADS = 100

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")


# --------------------------------------------------------------------------- #
# Target parsing helpers                                                       #
# --------------------------------------------------------------------------- #
def _parse_range(token: str) -> Tuple[int, int]:
    """Parse an IPv4 range token into inclusive ``(start_int, end_int)``.

    Accepts both ``10.0.0.1-50`` (short form, replaces the final octet) and
    ``10.0.0.1-10.0.0.50`` (explicit end address). Raises ``ValueError`` on
    anything malformed.
    """
    left, right = token.split("-", 1)
    left, right = left.strip(), right.strip()
    start = ipaddress.IPv4Address(left)
    if "." in right:
        end = ipaddress.IPv4Address(right)
    else:
        base = ".".join(str(start).split(".")[:3])
        end = ipaddress.IPv4Address(f"{base}.{int(right)}")
    start_i, end_i = int(start), int(end)
    if end_i < start_i:
        raise ValueError(f"range end precedes start: {token}")
    return start_i, end_i


def _token_count(token: str) -> int:
    """Upper-bound host count a token expands to (used for the cap check)."""
    token = token.strip()
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        return net.num_addresses
    if "-" in token:
        start_i, end_i = _parse_range(token)
        return end_i - start_i + 1
    ipaddress.ip_address(token)  # validate; raises on garbage
    return 1


def _expand_token(token: str) -> List[str]:
    """Expand a single validated token into a list of IP strings."""
    token = token.strip()
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        # /31 and /32 (and IPv6 equivalents) have no usable-host subset, so
        # enumerate every address; otherwise skip network + broadcast.
        if net.num_addresses <= 2:
            return [str(a) for a in net]
        return [str(a) for a in net.hosts()]
    if "-" in token:
        start_i, end_i = _parse_range(token)
        return [str(ipaddress.IPv4Address(i)) for i in range(start_i, end_i + 1)]
    return [str(ipaddress.ip_address(token))]


def expand_targets(spec: str, max_hosts: int = MAX_HOSTS) -> Tuple[List[str], List[str], Optional[str]]:
    """Expand a target spec into a de-duplicated, order-preserving IP list.

    Returns ``(ips, errors, cap_error)``:

    * ``ips``       -- expanded, de-duplicated host list (may be empty)
    * ``errors``    -- human-readable notes about tokens that failed to parse
    * ``cap_error`` -- non-empty string if the scope exceeds ``max_hosts``
      (in which case ``ips`` is meaningless and the caller must abort)
    """
    errors: List[str] = []
    tokens = [t.strip() for t in str(spec).split(",") if t.strip()]
    running = 0
    valid_tokens: List[str] = []

    for token in tokens:
        try:
            count = _token_count(token)
        except ValueError as exc:
            errors.append(f"{token}: {exc}")
            continue
        running += count
        if running > max_hosts:
            return [], errors, (
                f"target '{spec}' expands to more than {max_hosts} hosts; "
                "refusing. Narrow the scope (e.g. use a smaller CIDR/range)."
            )
        valid_tokens.append(token)

    seen = set()
    ips: List[str] = []
    for token in valid_tokens:
        for ip in _expand_token(token):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips, errors, None


class _ScopeMatcher:
    """Membership test for the ARP path without materialising the scope.

    Lets a wide target (e.g. a whole ``/16``) act purely as a filter over the
    ARP cache instead of forcing full host expansion.
    """

    def __init__(self, spec: str):
        self.networks: List = []
        self.ranges: List[Tuple[int, int]] = []
        self.singles: set = set()
        self.match_all = True
        for token in (t.strip() for t in str(spec).split(",")):
            if not token:
                continue
            try:
                if "/" in token:
                    self.networks.append(ipaddress.ip_network(token, strict=False))
                elif "-" in token:
                    self.ranges.append(_parse_range(token))
                else:
                    self.singles.add(str(ipaddress.ip_address(token)))
                self.match_all = False
            except ValueError:
                # Ignore unparseable tokens; a fully unparseable spec simply
                # leaves match_all True and lets every neighbour through.
                continue

    def contains(self, ip: str) -> bool:
        if self.match_all:
            return True
        if ip in self.singles:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        ival = int(addr)
        for start_i, end_i in self.ranges:
            if start_i <= ival <= end_i:
                return True
        for net in self.networks:
            try:
                if addr in net:
                    return True
            except TypeError:
                # v4 address vs v6 network or vice-versa
                continue
        return False


# --------------------------------------------------------------------------- #
# Probe helpers                                                                #
# --------------------------------------------------------------------------- #
def _parse_ports(spec: str) -> List[int]:
    """Parse a ``80,443,22`` / ``8000-8010`` port spec into a bounded list."""
    ports: List[int] = []
    seen = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    lo, hi = hi, lo
                rng = range(lo, hi + 1)
            else:
                rng = [int(part)]
        except ValueError:
            continue
        for p in rng:
            if 0 < p < 65536 and p not in seen:
                seen.add(p)
                ports.append(p)
                if len(ports) >= MAX_PORTS:
                    return ports
    return ports


def _tcp_probe(ip: str, ports: List[int], timeout: float) -> Tuple[str, List[int]]:
    """Return ``(ip, open_ports)``; a non-empty list means the host is alive."""
    open_ports: List[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except (OSError, socket.timeout, ValueError, OverflowError):
            continue
    return ip, open_ports


def _ping_command(ip: str, timeout: int) -> List[str]:
    """Build the platform-appropriate single-echo ping command."""
    if os.name == "nt":
        wait_ms = max(1, int(timeout)) * 1000
        return ["ping", "-n", "1", "-w", str(wait_ms), ip]
    # Linux / macOS / other POSIX. -W units differ (Linux: seconds,
    # BSD/macOS: milliseconds) but a value of 1 is a sane, portable timeout.
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]


def _ping_alive(text: str, returncode: int, timed_out: bool) -> bool:
    """Interpret ping output/return code into a liveness verdict."""
    if timed_out:
        return False
    low = text.lower()
    # Strong positive signal present in replies on every platform/locale.
    if "ttl=" in low:
        return True
    negatives = ("unreachable", "100% packet loss", "100% loss",
                 "request timed out", "request timeout", "could not find host",
                 "unknown host", "0 received", "0 packets received")
    if any(neg in low for neg in negatives):
        return False
    return returncode == 0


@register
class HostDiscovery(Module):
    """Discover live hosts across a CIDR / range / list via tcp, ping or arp."""

    name = "recon.host_discovery"
    description = "Live host discovery over a CIDR/range/list (tcp, ping, or arp)"
    phase = "recon"
    options = [
        Option("target", required=True,
               help="CIDR (10.0.0.0/24), range (10.0.0.1-50 or 10.0.0.1-10.0.0.50), "
                    "or comma-separated list of the above / single IPs"),
        Option("method", default="tcp", choices=["tcp", "ping", "arp"],
               help="Discovery technique: tcp connect, system ping, or arp cache"),
        Option("ports", default="80,443,22,445,3389",
               help="Ports to probe for the tcp method (comma list or lo-hi ranges)"),
        Option("threads", default=100, help="Worker pool size (capped at 100)"),
        Option("timeout", default=1,
               help="Per-host connect/ping timeout in seconds"),
    ]
    requires_tools = []  # tcp is pure-python; ping/arp are OS built-ins
    references = [
        "https://nmap.org/book/host-discovery.html",
    ]

    # -- entrypoint -------------------------------------------------------- #
    def run(self, opts: Dict, ctx) -> Result:
        target = str(opts["target"]).strip()
        method = opts["method"]
        threads = max(1, min(int(opts["threads"]), MAX_THREADS))
        timeout = max(1, int(opts["timeout"]))

        ctx.console.banner("host discovery", f"{method} :: {target}")

        if method == "arp":
            return self._run_arp(target, ctx)

        ips, errors, cap_error = expand_targets(target)
        for err in errors:
            ctx.console.warn(f"skipping target token -> {err}")
        if cap_error:
            ctx.console.bad(cap_error)
            return Result(ok=False, summary=cap_error,
                          data={"method": method, "alive": []})
        if not ips:
            msg = "no valid hosts to scan after parsing target"
            ctx.console.bad(msg)
            return Result(ok=False, summary=msg,
                          data={"method": method, "alive": []})

        ctx.console.info(f"expanded target to {len(ips)} host(s); method={method}, "
                         f"threads={threads}, timeout={timeout}s")

        if method == "ping":
            return self._run_ping(ips, ctx, threads, timeout)
        return self._run_tcp(ips, opts, ctx, threads, timeout)

    # -- tcp connect scan -------------------------------------------------- #
    def _run_tcp(self, ips: List[str], opts: Dict, ctx, threads: int, timeout: int) -> Result:
        ports = _parse_ports(opts["ports"])
        if not ports:
            msg = f"no valid probe ports parsed from '{opts['ports']}'"
            ctx.console.bad(msg)
            return Result(ok=False, summary=msg, data={"method": "tcp", "alive": []})

        ctx.console.info(f"tcp probing ports: {', '.join(str(p) for p in ports)}")
        alive: List[str] = []
        open_map: Dict[str, List[int]] = {}

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_tcp_probe, ip, ports, timeout): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    _, open_ports = fut.result()
                except Exception as exc:  # never let one host kill the sweep
                    ctx.console.debug(f"{ip}: probe error {exc!r}")
                    continue
                if open_ports:
                    alive.append(ip)
                    open_map[ip] = open_ports
                    ctx.engagement.add_host(ip)
                    for port in open_ports:
                        ctx.engagement.add_service(ip, port, proto="tcp")
                    ctx.console.good(f"{ip} alive (open: {', '.join(map(str, open_ports))})")

        return self._finish(ctx, "tcp", ips, alive,
                            extra={"ports": ports, "open_ports": open_map})

    # -- system ping sweep ------------------------------------------------- #
    def _run_ping(self, ips: List[str], ctx, threads: int, timeout: int) -> Result:
        if not ctx.runner.have("ping"):
            ctx.console.warn("no 'ping' binary found in PATH; falling back to tcp method")
            return self._run_tcp(ips, {"ports": "80,443,22,445,3389"}, ctx, threads, timeout)

        run_timeout = timeout + 3  # headroom over ping's own -w/-W

        def _probe(ip: str) -> Tuple[str, bool]:
            res = ctx.runner.run(_ping_command(ip, timeout), timeout=run_timeout)
            return ip, _ping_alive(res.text, res.returncode, res.timed_out)

        alive: List[str] = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_probe, ip): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    _, is_alive = fut.result()
                except Exception as exc:
                    ctx.console.debug(f"{ip}: ping error {exc!r}")
                    continue
                if is_alive:
                    alive.append(ip)
                    ctx.engagement.add_host(ip)
                    ctx.console.good(f"{ip} alive (icmp echo)")

        return self._finish(ctx, "ping", ips, alive)

    # -- arp cache read ---------------------------------------------------- #
    def _run_arp(self, target: str, ctx) -> Result:
        if not ctx.runner.have("arp"):
            msg = ("'arp' utility not found in PATH; install net-tools (Linux) "
                   "or use the built-in arp on Windows, or pick method=tcp/ping")
            ctx.console.bad(msg)
            return Result(ok=False, summary=msg, data={"method": "arp", "alive": []})

        res = ctx.runner.run(["arp", "-a"], timeout=20)
        if res.timed_out:
            msg = "'arp -a' timed out"
            ctx.console.bad(msg)
            return Result(ok=False, summary=msg, data={"method": "arp", "alive": []})
        if not res.text.strip():
            msg = "'arp -a' returned no output (empty ARP cache?)"
            ctx.console.warn(msg)
            return Result(ok=True, summary=msg,
                          data={"method": "arp", "alive": [], "neighbors": []})

        scope = _ScopeMatcher(target)
        alive: List[str] = []
        neighbors: List[Dict[str, Optional[str]]] = []
        seen = set()

        for line in res.text.splitlines():
            m = _IPV4_RE.search(line)
            if not m:
                continue
            ip = m.group(0)
            # Skip obviously non-host entries.
            if ip in ("0.0.0.0", "255.255.255.255") or ip.endswith(".255"):
                continue
            try:
                addr = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if addr.is_multicast or addr.is_unspecified:
                continue
            if ip in seen or not scope.contains(ip):
                continue
            mac_m = _MAC_RE.search(line)
            mac = mac_m.group(0) if mac_m else None
            # Skip incomplete cache entries (no resolved MAC / all-zero MAC).
            if mac and set(mac.replace(":", "").replace("-", "")) == {"0"}:
                mac = None
            seen.add(ip)
            alive.append(ip)
            neighbors.append({"ip": ip, "mac": mac})
            ctx.engagement.add_host(ip)
            if mac:
                ctx.engagement.add_loot(ip, "mac", mac, source="arp")
            ctx.console.good(f"{ip} known neighbor" + (f" ({mac})" if mac else ""))

        return self._finish(ctx, "arp", None, alive,
                            extra={"neighbors": neighbors})

    # -- shared finish / reporting ---------------------------------------- #
    def _finish(self, ctx, method: str, scanned: Optional[List[str]],
                alive: List[str], extra: Optional[Dict] = None) -> Result:
        alive_sorted = _sort_ips(alive)
        data: Dict = {
            "method": method,
            "scanned": (len(scanned) if scanned is not None else None),
            "alive_count": len(alive_sorted),
            "alive": alive_sorted,
        }
        if extra:
            data.update(extra)

        artifacts: List[str] = []
        if alive_sorted:
            try:
                path = ctx.artifact_path(f"host_discovery_{method}_alive.txt")
                path.write_text("\n".join(alive_sorted) + "\n", encoding="utf-8")
                artifacts.append(str(path))
            except OSError as exc:
                ctx.console.warn(f"could not write artifact: {exc}")

        scope = "ARP cache" if scanned is None else f"{len(scanned)} host(s)"
        summary = f"{method}: {len(alive_sorted)} alive of {scope}"
        ctx.engagement.add_note(f"host_discovery ({method}) found {len(alive_sorted)} live host(s)")

        if alive_sorted:
            ctx.console.raw("")
            ctx.console.table(["alive host"], [[ip] for ip in alive_sorted])
            ctx.console.good(summary)
        else:
            ctx.console.warn(summary)

        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)


def _sort_ips(ips: List[str]) -> List[str]:
    """Numeric-aware sort that tolerates hostnames / IPv6 gracefully."""
    def key(ip: str):
        try:
            return (0, int(ipaddress.ip_address(ip)))
        except ValueError:
            return (1, ip)
    return sorted(set(ips), key=key)
