"""TCP port scanner (recon.port_scan).

A dependency-free, threaded TCP *connect* scanner. The default code path uses
only the Python standard library (``socket`` + ``concurrent.futures``) so it
runs identically on Windows and Linux with nothing installed.

If ``nmap`` happens to be on ``PATH`` *and* the operator sets ``use_nmap=true``,
the module shells out to ``nmap -sV`` and parses its output for richer service
and version detection. nmap is a soft dependency only: importing this module
never requires it, and the pure-python path is always available as a fallback.

Discovered open ports are persisted to the shared engagement store via
``ctx.engagement.add_service`` so downstream modules (and the report phase) can
see them. NO AI/LLM usage; everything here is deterministic and rule-based.
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Hard ceiling on the worker pool regardless of operator input (safe default).
MAX_THREADS = 100
# Absolute bound on how many bytes we read for a service banner.
BANNER_BYTES = 256
MAX_BANNER_LEN = 200

# A compact, curated "top ~100" TCP port list (nmap-style frequency ordering,
# sorted here for determinism). Used when ``ports=top``.
TOP_PORTS: List[int] = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    123, 135, 137, 139, 143, 161, 179, 199, 389, 427, 443, 444, 445, 465, 500,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1080, 1110, 1194, 1433, 1434, 1521, 1720, 1723, 1883,
    2000, 2001, 2049, 2121, 2181, 2375, 3000, 3128, 3268, 3306, 3389, 3690,
    4444, 4786, 5000, 5060, 5432, 5555, 5601, 5900, 5985, 6000, 6379, 6443,
    6667, 7001, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9092, 9200,
    10000, 11211, 27017, 50000,
]

# Inline common-port -> service-name map (best-effort guess for the connect
# scanner; nmap supplies its own names on the ``use_nmap`` path).
COMMON_SERVICES: Dict[int, str] = {
    7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    37: "time", 43: "whois", 53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp",
    79: "finger", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
    389: "ldap", 427: "svrloc", 443: "https", 445: "microsoft-ds", 464: "kpasswd",
    465: "smtps", 500: "isakmp", 513: "login", 514: "syslog", 515: "printer",
    543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp", 587: "submission",
    593: "http-rpc-epmap", 631: "ipp", 636: "ldaps", 873: "rsync", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle", 1701: "l2tp", 1720: "h323",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2121: "ftp-alt", 2181: "zookeeper", 2375: "docker", 2376: "docker-ssl",
    3000: "http-alt", 3128: "squid-http", 3268: "globalcat-ldap", 3306: "mysql",
    3389: "ms-wbt-server", 3690: "svn", 4444: "metasploit", 4786: "smi",
    5000: "upnp", 5060: "sip", 5432: "postgresql", 5555: "freeciv", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "wsman", 5986: "wsmans", 6000: "x11",
    6379: "redis", 6443: "kubernetes", 6667: "irc", 7001: "weblogic",
    8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
    8081: "http-alt", 8083: "http", 8086: "influxdb", 8088: "http",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra",
    9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
    11211: "memcache", 27017: "mongodb", 27018: "mongodb", 50000: "sap",
}

# Plaintext HTTP-ish ports where an unsolicited HEAD request usefully elicits a
# server banner (skip TLS ports; a raw request there just yields noise).
HTTP_PROBE_PORTS = {80, 81, 591, 2082, 3000, 8000, 8008, 8080, 8081, 8083, 8086,
                    8088, 8888, 9000, 10000}

# Parse nmap normal-output service lines, e.g.:
#   22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
#   80/tcp   open  http    nginx 1.18.0
_NMAP_LINE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*\S))?\s*$", re.MULTILINE)


def _parse_ports(spec: str) -> List[int]:
    """Expand a port spec into a sorted, de-duplicated list of ints.

    Accepts ``"top"`` (the bundled top list), comma lists (``"22,80,443"``),
    ranges (``"1-1024"``), and any mix (``"22,80,8000-8010"``). Ports outside
    ``1..65535`` are dropped. Raises ``ValueError`` on non-numeric tokens.
    """
    spec = str(spec).strip().lower()
    if not spec:
        raise ValueError("empty port specification")
    if spec == "top":
        return sorted(set(TOP_PORTS))

    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, hi + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        raise ValueError("port specification resolved to zero valid ports")
    return sorted(ports)


def _clean_banner(raw: bytes) -> str:
    """Reduce a raw banner to a single printable, length-capped line."""
    if not raw:
        return ""
    text = raw.decode("latin-1", "replace")
    # Collapse to printable ASCII (plus tab); newlines become spaces.
    kept = []
    for ch in text:
        if ch in "\r\n":
            kept.append(" ")
        elif ch == "\t" or 32 <= ord(ch) < 127:
            kept.append(ch)
    cleaned = " ".join("".join(kept).split())
    return cleaned[:MAX_BANNER_LEN]


@register
class PortScan(Module):
    """Threaded TCP connect scanner with optional nmap-backed service detection."""

    name = "recon.port_scan"
    description = "Threaded TCP connect port scanner (pure-python; optional nmap -sV)"
    phase = "recon"
    options = [
        Option("target", help="Single IP address or hostname to scan", required=True),
        Option("ports", default="1-1024",
               help="Ports: range '1-1024', list '22,80,443', or 'top' for the bundled top list"),
        Option("threads", default=100, help="Concurrent connections (capped at 100)"),
        Option("timeout", default=1, help="Per-connect socket timeout in seconds"),
        Option("banner", default=True, help="Grab a short banner from each open port"),
        Option("use_nmap", default=False,
               help="If nmap is installed, use 'nmap -sV' instead of the socket scanner"),
    ]
    requires_tools = ["nmap"]  # soft/optional dependency
    references = [
        "https://nmap.org/book/man-port-scanning-techniques.html",
        "https://datatracker.ietf.org/doc/html/rfc793",
    ]

    # ------------------------------------------------------------------ run
    def run(self, opts: Dict, ctx) -> Result:
        target = str(opts["target"]).strip()
        if not target:
            return Result(ok=False, summary="no target specified")

        # Expand the port specification early so bad input fails fast.
        try:
            ports = _parse_ports(opts["ports"])
        except ValueError as exc:
            return Result(ok=False, summary=f"invalid ports '{opts['ports']}': {exc}")

        # Resolve the target to an IPv4 address (nmap can resolve on its own, but
        # we want a canonical IP for the engagement store either way).
        ip = self._resolve(target)
        if ip is None:
            return Result(ok=False, summary=f"could not resolve target: {target}")

        timeout = max(1, int(opts["timeout"]))
        want_banner = bool(opts["banner"])
        threads = max(1, min(int(opts["threads"]), MAX_THREADS, len(ports)))

        ctx.console.info(
            f"scanning {ip} ({target}) : {len(ports)} port(s), "
            f"{threads} thread(s), timeout={timeout}s"
        )
        ctx.engagement.add_host(ip, hostname=(target if target != ip else None))

        # -- nmap path (only when explicitly requested AND available) -------
        if bool(opts["use_nmap"]):
            if ctx.runner.have("nmap"):
                return self._run_nmap(ip, target, ports, ctx)
            ctx.console.warn("use_nmap set but nmap not found in PATH; "
                             "falling back to the built-in socket scanner")

        # -- pure-python connect scan (default) -----------------------------
        return self._run_socket(ip, target, ports, timeout, want_banner, threads, ctx)

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _resolve(target: str) -> Optional[str]:
        """Return an IPv4 address for ``target`` or ``None`` on failure."""
        try:
            # getaddrinfo copes with both literal IPs and hostnames.
            infos = socket.getaddrinfo(target, None, family=socket.AF_INET,
                                       type=socket.SOCK_STREAM)
            if infos:
                return infos[0][4][0]
        except (socket.gaierror, socket.error, UnicodeError):
            pass
        # Last resort: maybe it is already a literal address of some kind.
        # gethostbyname can raise UnicodeError (subclass of ValueError, not
        # OSError) when the name fails IDNA encoding, so catch it explicitly.
        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, socket.error, UnicodeError):
            return None

    def _scan_one(self, ip: str, port: int, timeout: int,
                  want_banner: bool) -> Tuple[int, bool, str]:
        """Connect to one port; return (port, is_open, banner)."""
        banner = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        is_open = False
        try:
            if sock.connect_ex((ip, port)) == 0:
                is_open = True
                if want_banner:
                    banner = self._grab_banner(sock, ip, port, timeout)
        except OSError:
            is_open = False
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return port, is_open, banner

    @staticmethod
    def _grab_banner(sock: socket.socket, ip: str, port: int, timeout: int) -> str:
        """Best-effort short banner read from an already-connected socket."""
        try:
            sock.settimeout(timeout)
            if port in HTTP_PROBE_PORTS:
                try:
                    sock.sendall(
                        f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii", "ignore")
                    )
                except OSError:
                    return ""
            data = sock.recv(BANNER_BYTES)
        except (socket.timeout, OSError):
            return ""
        return _clean_banner(data)

    def _run_socket(self, ip: str, target: str, ports: List[int], timeout: int,
                    want_banner: bool, threads: int, ctx) -> Result:
        """Execute the threaded pure-python connect scan."""
        open_ports: List[Dict] = []
        try:
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {
                    pool.submit(self._scan_one, ip, p, timeout, want_banner): p
                    for p in ports
                }
                for fut in as_completed(futures):
                    try:
                        port, is_open, banner = fut.result()
                    except Exception:  # a single socket failure must not abort the scan
                        continue
                    if not is_open:
                        continue
                    service = COMMON_SERVICES.get(port)
                    open_ports.append({
                        "port": port, "proto": "tcp",
                        "service": service, "banner": banner or None,
                    })
                    ctx.engagement.add_service(
                        ip, port, "tcp", service=service, banner=(banner or None)
                    )
                    label = service or "unknown"
                    extra = f"  {banner}" if banner else ""
                    ctx.console.good(f"{ip}:{port}/tcp open  {label}{extra}")
        except (OSError, RuntimeError) as exc:
            # Even if the pool blows up, report whatever we found.
            ctx.console.bad(f"scan pool error: {exc}")

        open_ports.sort(key=lambda d: d["port"])
        return self._finish(ip, target, ports, open_ports, "socket-connect", ctx)

    def _run_nmap(self, ip: str, target: str, ports: List[int], ctx) -> Result:
        """Wrap ``nmap -sV`` and parse open ports from its normal output."""
        port_arg = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-sV", "-Pn", "-p", port_arg, ip]
        # Scale the timeout with the number of ports; -sV probing is slow.
        est = min(900, max(120, len(ports) // 2 + 60))
        ctx.console.info(f"running: nmap -sV -p <{len(ports)} ports> {ip}")
        proc = ctx.runner.run(cmd, timeout=est)

        if proc.timed_out:
            ctx.console.warn("nmap timed out; partial output (if any) parsed below")
        if proc.returncode not in (0, -1) and not proc.stdout:
            return Result(
                ok=False,
                summary=f"nmap failed (rc={proc.returncode}): {proc.stderr.strip()[:200]}",
            )

        open_ports: List[Dict] = []
        for match in _NMAP_LINE.finditer(proc.stdout or ""):
            port = int(match.group(1))
            service = match.group(2) or None
            product = (match.group(3) or "").strip() or None
            open_ports.append({
                "port": port, "proto": "tcp",
                "service": service, "banner": product,
            })
            ctx.engagement.add_service(
                ip, port, "tcp", service=service, product=product, banner=product
            )
            label = service or "unknown"
            extra = f"  {product}" if product else ""
            ctx.console.good(f"{ip}:{port}/tcp open  {label}{extra}")

        open_ports.sort(key=lambda d: d["port"])

        # Persist the raw nmap output as an artifact for later review.
        artifacts: List[str] = []
        try:
            out_path = ctx.artifact_path(f"nmap_{ip.replace(':', '_')}.txt")
            out_path.write_text(proc.text, encoding="utf-8")
            artifacts.append(str(out_path))
        except OSError:
            pass

        return self._finish(ip, target, ports, open_ports, "nmap-sV", ctx,
                            artifacts=artifacts)

    @staticmethod
    def _finish(ip: str, target: str, ports: List[int], open_ports: List[Dict],
                method: str, ctx, artifacts: Optional[List[str]] = None) -> Result:
        """Assemble the final Result and emit a summary table."""
        n_open = len(open_ports)
        if n_open:
            ctx.console.table(
                ["port", "proto", "service", "banner"],
                [[d["port"], d["proto"], d.get("service") or "unknown",
                  d.get("banner") or ""] for d in open_ports],
            )
            ctx.engagement.add_note(
                f"port_scan[{method}] {ip}: {n_open} open of {len(ports)} scanned"
            )
        summary = (f"{n_open} open port(s) on {ip} "
                   f"(scanned {len(ports)}, method={method})")
        return Result(
            ok=True,
            summary=summary,
            data={
                "target": target,
                "ip": ip,
                "method": method,
                "scanned": len(ports),
                "open_count": n_open,
                "open_ports": open_ports,
            },
            artifacts=artifacts or [],
        )
