"""access.default_creds -- default-credential checker.

Cross-references the bundled default-credentials database
(``config.creds_file("default-creds.json")``) against the open services
recorded in the engagement and reports every well-known default login that
*could* apply. Optionally (``test=true``) it will actually attempt a single,
lockout-aware login for the protocols we can safely drive with the standard
library / an optional pure-python SSH client:

    * ftp   -> ftplib            (stdlib)
    * http  -> urllib basic-auth (stdlib)
    * ssh   -> paramiko          (optional; skipped with a note if absent)

Design invariants:
    * NO AI/LLM anywhere -- purely rule-based matching.
    * Pure standard library by default. ``paramiko`` is imported lazily inside
      the SSH attempt and its absence only disables SSH testing.
    * Imports cleanly on Windows and Linux (no OS-specific calls at import).
    * ``test=false`` performs ZERO network authentication -- it only reads the
      engagement state and the offline creds DB.
    * Lockout-aware: exactly one attempt per (host, port, user, password),
      short bounded timeouts, capped thread pool.
"""
from __future__ import annotations

import base64
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register
from redkit.core import config


# --------------------------------------------------------------------------- #
# Service classification helpers
# --------------------------------------------------------------------------- #

# Canonical service class -> its conventional default port (used when we have a
# host but no recorded port to hang the check off of).
_DEFAULT_PORT: Dict[str, int] = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "http": 80,
    "mysql": 3306,
    "postgresql": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "vnc": 5900,
    "oracle": 1521,
    "rtsp": 554,
    "smb": 445,
}

# Port number -> (canonical class, tls?) fallback when the service name is
# missing or unhelpful.
_PORT_CLASS: Dict[int, Tuple[str, bool]] = {
    21: ("ftp", False),
    22: ("ssh", False),
    23: ("telnet", False),
    25: ("smtp", False),
    80: ("http", False),
    110: ("pop3", False),
    143: ("imap", False),
    443: ("http", True),
    445: ("smb", False),
    554: ("rtsp", False),
    1521: ("oracle", False),
    3306: ("mysql", False),
    3389: ("rdp", False),
    5432: ("postgresql", False),
    5900: ("vnc", False),
    5901: ("vnc", False),
    6379: ("redis", False),
    8000: ("http", False),
    8080: ("http", False),
    8081: ("http", False),
    8443: ("http", True),
    8888: ("http", False),
    9200: ("http", False),
    27017: ("mongodb", False),
    27018: ("mongodb", False),
}

# Service-name synonyms -> (canonical class, tls?).
_SERVICE_SYNONYM: Dict[str, Tuple[str, bool]] = {
    "http": ("http", False),
    "www": ("http", False),
    "http-proxy": ("http", False),
    "http-alt": ("http", False),
    "http-manager": ("http", False),
    "https": ("http", True),
    "https-alt": ("http", True),
    "ssl/http": ("http", True),
    "ssl": ("http", True),
    "ssh": ("ssh", False),
    "ftp": ("ftp", False),
    "ftp-data": ("ftp", False),
    "telnet": ("telnet", False),
    "mysql": ("mysql", False),
    "postgresql": ("postgresql", False),
    "postgres": ("postgresql", False),
    "redis": ("redis", False),
    "mongodb": ("mongodb", False),
    "mongod": ("mongodb", False),
    "vnc": ("vnc", False),
    "oracle": ("oracle", False),
    "oracle-tns": ("oracle", False),
    "tns": ("oracle", False),
    "rtsp": ("rtsp", False),
    "smb": ("smb", False),
    "microsoft-ds": ("smb", False),
    "netbios-ssn": ("smb", False),
    "rdp": ("rdp", False),
    "ms-wbt-server": ("rdp", False),
}

# Words dropped when tokenising a DB product name for banner matching.
_PRODUCT_STOPWORDS = {"generic", "db", "server", "the", "and", "raspbian", "kali"}

# Which service classes we are actually able to authenticate against.
_TESTABLE = {"ftp", "http", "ssh"}


def _normalize_service(name: Optional[str]) -> Tuple[Optional[str], bool]:
    """Map a raw service string to (canonical class, tls?)."""
    if not name:
        return None, False
    key = str(name).strip().lower()
    if key in _SERVICE_SYNONYM:
        return _SERVICE_SYNONYM[key]
    # tolerate values like "http?" or "ssl/https"
    for token in key.replace("/", " ").replace("?", " ").split():
        if token in _SERVICE_SYNONYM:
            return _SERVICE_SYNONYM[token]
    return None, False


def _classify(service: Optional[str], port: Optional[int]) -> Tuple[Optional[str], bool]:
    """Best-effort (class, tls) for an open port using service name then port."""
    cls, tls = _normalize_service(service)
    if cls:
        return cls, tls
    if port is not None:
        try:
            p = int(port)
        except (TypeError, ValueError):
            p = None
        if p in _PORT_CLASS:
            return _PORT_CLASS[p]
    return None, False


def _product_tokens(product: str) -> List[str]:
    """Significant lowercase tokens of a DB product name for banner matching."""
    cleaned = []
    for raw in product.lower().replace("(", " ").replace(")", " ").replace("/", " ").split():
        tok = raw.strip()
        if len(tok) >= 3 and tok not in _PRODUCT_STOPWORDS:
            cleaned.append(tok)
    return cleaned


def _product_matches(product: str, haystack: str) -> bool:
    """True if a DB product name plausibly matches a recorded product/banner."""
    if not product or not haystack:
        return False
    for tok in _product_tokens(product):
        if tok in haystack:
            return True
    return False


# --------------------------------------------------------------------------- #
# Login probes (only invoked when test=true)
# --------------------------------------------------------------------------- #

def _try_ftp(ip: str, port: int, user: str, password: str, timeout: float) -> str:
    """Attempt a single FTP login. Returns success|rejected|unreachable."""
    import ftplib

    ftp = ftplib.FTP()
    try:
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(user or "anonymous", password or "")
    except ftplib.error_perm:
        return "rejected"
    except ftplib.all_errors:
        return "unreachable"
    except OSError:
        return "unreachable"
    else:
        try:
            ftp.quit()
        except Exception:  # noqa: BLE001 -- best-effort teardown
            try:
                ftp.close()
            except Exception:  # noqa: BLE001
                pass
        return "success"


def _http_status(url: str, auth: Optional[Tuple[str, str]], timeout: float, ctx) -> Optional[int]:
    """GET ``url`` (optionally with basic-auth) and return the HTTP status."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "redkit/default_creds")
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
        req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.getcode()
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError, ValueError):
        return None


def _try_http(ip: str, port: int, tls: bool, user: str, password: str, timeout: float) -> str:
    """Attempt HTTP basic-auth. Returns success|rejected|inconclusive|unreachable.

    We only claim success when the endpoint first challenges with 401 and then
    accepts the credentials (non-401). If the root does not require auth we
    cannot validate form-based logins and report ``inconclusive`` rather than a
    false positive.
    """
    ctx = None
    if tls:
        try:
            import ssl

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:  # noqa: BLE001 -- ssl always present in CPython stdlib
            ctx = None
    scheme = "https" if tls else "http"
    url = f"{scheme}://{ip}:{port}/"

    base = _http_status(url, None, timeout, ctx)
    if base is None:
        return "unreachable"
    if base != 401:
        return "inconclusive"
    authed = _http_status(url, (user, password), timeout, ctx)
    if authed is None:
        return "unreachable"
    if authed != 401:
        return "success"
    return "rejected"


def _try_ssh(ip: str, port: int, user: str, password: str, timeout: float) -> str:
    """Attempt one SSH login via paramiko. Returns success|rejected|unreachable|skip."""
    try:
        import paramiko
    except ImportError:
        return "skip"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip,
            port=port,
            username=user,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
    except paramiko.AuthenticationException:
        return "rejected"
    except Exception:  # noqa: BLE001 -- network/proto errors are "unreachable"
        return "unreachable"
    else:
        return "success"
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


@register
class DefaultCredsModule(Module):
    """Report (and optionally test) default credentials against open services."""

    name = "access.default_creds"
    description = "Check open services against the bundled default-credentials DB"
    phase = "access"
    options = [
        Option(
            "host",
            help="Target host/IP. Empty => iterate every host with open ports "
            "recorded in the engagement.",
            default="",
        ),
        Option(
            "service",
            help="Filter by service class, e.g. ssh/http/ftp/mysql. Empty => all.",
            default="",
        ),
        Option(
            "test",
            help="If true, attempt a single lockout-aware login per candidate "
            "(ftp/http/ssh only). If false, only REPORT candidates -- no auth.",
            default=False,
        ),
        Option(
            "threads",
            help="Max concurrent login attempts when test=true (capped at 100).",
            default=20,
        ),
        Option(
            "timeout",
            help="Per-attempt network timeout in seconds.",
            default=6,
        ),
    ]
    requires_tools: List[str] = []
    references = [
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
        "https://cwe.mitre.org/data/definitions/1392.html",
    ]

    # -- DB loading -------------------------------------------------------- #
    @staticmethod
    def _load_db() -> List[Dict[str, Any]]:
        """Load and lightly validate the offline default-creds database."""
        path = config.creds_file("default-creds.json")
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = raw.get("entries", []) if isinstance(raw, dict) else []
        clean: List[Dict[str, Any]] = []
        for ent in entries:
            if not isinstance(ent, dict):
                continue
            clean.append(
                {
                    "product": str(ent.get("product", "") or ""),
                    "service": str(ent.get("service", "") or ""),
                    "username": "" if ent.get("username") is None else str(ent.get("username")),
                    "password": "" if ent.get("password") is None else str(ent.get("password")),
                }
            )
        return clean

    # -- target enumeration ----------------------------------------------- #
    @staticmethod
    def _collect_targets(ctx, host: str, filt_cls: Optional[str]) -> List[Dict[str, Any]]:
        """Build the list of open services to check from engagement state.

        Each target: {ip, port, proto, service, product, banner, cls, tls}.
        """
        targets: List[Dict[str, Any]] = []
        hosts = ctx.engagement.hosts()
        for ip, hdata in hosts.items():
            if host and ip != host:
                continue
            for _key, svc in (hdata.get("ports") or {}).items():
                port = svc.get("port")
                proto = svc.get("proto", "tcp")
                service = svc.get("service")
                product = svc.get("product")
                banner = svc.get("banner")
                cls, tls = _classify(service, port)
                if filt_cls and cls != filt_cls:
                    continue
                targets.append(
                    {
                        "ip": ip,
                        "port": int(port) if port is not None else None,
                        "proto": proto,
                        "service": service,
                        "product": product,
                        "banner": banner,
                        "cls": cls,
                        "tls": tls,
                    }
                )
        # Standalone convenience: a host was named but the engagement has no
        # matching open port for it -- synthesise one on the default port so the
        # operator can run `-o host=x -o service=ssh` without prior recon.
        if host and not targets and filt_cls and filt_cls in _DEFAULT_PORT:
            targets.append(
                {
                    "ip": host,
                    "port": _DEFAULT_PORT[filt_cls],
                    "proto": "tcp",
                    "service": filt_cls,
                    "product": None,
                    "banner": None,
                    "cls": filt_cls,
                    "tls": False,
                }
            )
        return targets

    # -- candidate matching ------------------------------------------------ #
    @staticmethod
    def _candidates_for(target: Dict[str, Any], db: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match DB entries to a single open service target."""
        cls = target["cls"]
        haystack = f"{target.get('product') or ''} {target.get('banner') or ''}".lower()
        out: List[Dict[str, Any]] = []
        for ent in db:
            ent_cls, _ = _normalize_service(ent["service"])
            reason: Optional[str] = None
            if _product_matches(ent["product"], haystack):
                reason = "product"
            elif cls and ent_cls == cls:
                reason = "service"
            if not reason:
                continue
            out.append(
                {
                    "host": target["ip"],
                    "port": target["port"],
                    "proto": target["proto"],
                    "service": cls or (target.get("service") or "unknown"),
                    "tls": target["tls"],
                    "product": ent["product"],
                    "username": ent["username"],
                    "password": ent["password"],
                    "match": reason,
                }
            )
        return out

    # -- login dispatch ---------------------------------------------------- #
    @staticmethod
    def _attempt(cand: Dict[str, Any], timeout: float) -> str:
        cls = cand["service"]
        ip = cand["host"]
        port = cand["port"]
        user = cand["username"]
        pw = cand["password"]
        if port is None:
            return "unreachable"
        if cls == "ftp":
            return _try_ftp(ip, port, user, pw, timeout)
        if cls == "http":
            return _try_http(ip, port, bool(cand.get("tls")), user, pw, timeout)
        if cls == "ssh":
            return _try_ssh(ip, port, user, pw, timeout)
        return "skip"

    # -- entry point ------------------------------------------------------- #
    def run(self, opts: Dict[str, Any], ctx) -> Result:
        host = (opts.get("host") or "").strip()
        service = (opts.get("service") or "").strip()
        do_test = bool(opts.get("test"))
        threads = max(1, min(int(opts.get("threads", 20) or 20), 100))
        timeout = float(opts.get("timeout", 6) or 6)
        if timeout <= 0:
            timeout = 6.0

        # Normalise the service filter to a canonical class if we recognise it.
        filt_cls: Optional[str] = None
        if service:
            norm, _ = _normalize_service(service)
            filt_cls = norm or service.lower()

        ctx.console.banner("default-creds", host or "all engagement hosts")

        # Load the offline DB.
        try:
            db = self._load_db()
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return Result(
                ok=False,
                summary=f"could not load default-creds DB: {exc}",
                data={"candidates": [], "valid": []},
            )
        if not db:
            return Result(
                ok=False,
                summary="default-creds DB is empty or malformed",
                data={"candidates": [], "valid": []},
            )

        # Enumerate targets from engagement state.
        targets = self._collect_targets(ctx, host, filt_cls)
        if not targets:
            msg = "no matching open services in engagement (run a recon/scan first)"
            ctx.console.warn(msg)
            ctx.engagement.add_note(f"default_creds: {msg}")
            return Result(ok=True, summary=msg, data={"candidates": [], "valid": []})

        # Build the deduplicated candidate list.
        seen: set = set()
        candidates: List[Dict[str, Any]] = []
        for tgt in targets:
            for cand in self._candidates_for(tgt, db):
                key = (cand["host"], cand["port"], cand["service"], cand["username"], cand["password"])
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(cand)

        ctx.console.info(
            f"{len(targets)} service(s) -> {len(candidates)} default-cred candidate(s)"
        )
        if candidates:
            ctx.console.table(
                ["host", "port", "service", "product", "user", "password", "match"],
                [
                    [
                        c["host"],
                        c["port"],
                        c["service"],
                        c["product"],
                        c["username"] or "(blank)",
                        c["password"] or "(blank)",
                        c["match"],
                    ]
                    for c in candidates
                ],
            )

        valid: List[Dict[str, Any]] = []

        if not do_test:
            # Persist candidates as an informational finding so the report module
            # can surface "these default creds are worth trying".
            if candidates:
                ctx.engagement.add_finding(
                    title="Default-credential candidates identified",
                    severity="info",
                    host=host or None,
                    description=(
                        f"{len(candidates)} well-known default credential(s) map to "
                        "open services. Re-run with test=true to validate."
                    ),
                    evidence=json.dumps(candidates[:50]),
                )
            artifacts = self._write_report(ctx, candidates, valid)
            return Result(
                ok=True,
                summary=(
                    f"{len(candidates)} default-cred candidate(s) across "
                    f"{len(targets)} service(s); test disabled (no auth performed)"
                ),
                data={"tested": False, "candidates": candidates, "valid": valid},
                artifacts=artifacts,
            )

        # --- test=true: attempt logins for supported protocols only -------- #
        testable = [c for c in candidates if c["service"] in _TESTABLE and c["port"] is not None]
        skipped_classes = sorted({c["service"] for c in candidates if c["service"] not in _TESTABLE})
        if skipped_classes:
            ctx.console.info(
                "not auto-testable (report-only): " + ", ".join(skipped_classes)
            )

        # Detect paramiko availability once so we can annotate skipped SSH work.
        ssh_needed = any(c["service"] == "ssh" for c in testable)
        paramiko_ok = True
        if ssh_needed:
            try:
                import paramiko  # noqa: F401
            except ImportError:
                paramiko_ok = False
                note = "paramiko not installed -> SSH default-cred testing skipped (pip install paramiko)"
                ctx.console.warn(note)
                ctx.engagement.add_note(f"default_creds: {note}")

        if not testable:
            ctx.console.warn("no testable (ftp/http/ssh) candidates to attempt")
            artifacts = self._write_report(ctx, candidates, valid)
            return Result(
                ok=True,
                summary=f"{len(candidates)} candidate(s); none auto-testable",
                data={"tested": True, "candidates": candidates, "valid": valid},
                artifacts=artifacts,
            )

        ctx.console.info(
            f"attempting {len(testable)} login(s) with {threads} worker(s), "
            f"timeout={timeout:g}s (single attempt per cred)"
        )

        results: List[Tuple[Dict[str, Any], str]] = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            future_map = {
                pool.submit(self._attempt, cand, timeout): cand for cand in testable
            }
            for fut in as_completed(future_map):
                cand = future_map[fut]
                try:
                    status = fut.result()
                except Exception as exc:  # noqa: BLE001 -- worker must never crash run()
                    ctx.console.debug(f"attempt error {cand['host']}:{cand['port']} -> {exc}")
                    status = "unreachable"
                results.append((cand, status))

        # Apply engagement mutations on the main thread (Engagement isn't
        # guaranteed thread-safe).
        successes = 0
        for cand, status in results:
            if status == "success":
                successes += 1
                valid.append(
                    {
                        "host": cand["host"],
                        "port": cand["port"],
                        "service": cand["service"],
                        "product": cand["product"],
                        "username": cand["username"],
                        "password": cand["password"],
                    }
                )
                ctx.console.good(
                    f"VALID {cand['service']}://{cand['host']}:{cand['port']} "
                    f"{cand['username'] or '(blank)'}:{cand['password'] or '(blank)'}"
                )
                ctx.engagement.add_cred(
                    service=cand["service"],
                    host=cand["host"],
                    username=cand["username"],
                    password=cand["password"],
                    source="access.default_creds",
                )
                ctx.engagement.add_finding(
                    title="Default credentials accepted",
                    severity="high",
                    host=cand["host"],
                    description=(
                        f"Service {cand['service']} on {cand['host']}:{cand['port']} "
                        f"({cand['product']}) accepts default credentials "
                        f"'{cand['username']}' / '{cand['password']}'."
                    ),
                    evidence=(
                        f"{cand['service']}://{cand['host']}:{cand['port']} "
                        f"user={cand['username']!r} pass={cand['password']!r}"
                    ),
                )

        artifacts = self._write_report(ctx, candidates, valid)
        summary = (
            f"tested {len(testable)} candidate(s); {successes} valid default "
            f"login(s) found across {len(targets)} service(s)"
        )
        if ssh_needed and not paramiko_ok:
            summary += " (SSH skipped: paramiko missing)"
        ctx.console.good(summary) if successes else ctx.console.info(summary)
        return Result(
            ok=True,
            summary=summary,
            data={"tested": True, "candidates": candidates, "valid": valid},
            artifacts=artifacts,
        )

    # -- artifact ---------------------------------------------------------- #
    @staticmethod
    def _write_report(ctx, candidates: List[Dict[str, Any]], valid: List[Dict[str, Any]]) -> List[str]:
        """Write a JSON artifact of candidates + validated creds; never fatal."""
        try:
            path = ctx.artifact_path("default_creds.json")
            path.write_text(
                json.dumps({"candidates": candidates, "valid": valid}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return [str(path)]
        except OSError as exc:
            ctx.console.warn(f"could not write artifact: {exc}")
            return []
