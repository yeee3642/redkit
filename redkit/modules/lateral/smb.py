"""SMB enumeration and command-execution wrapper (lateral.smb).

A thin, offline, deterministic wrapper around whatever SMB tooling happens to
be installed on the operator's box. It never requires any external tool at
import time and never phones home; everything here is rule-based argv
construction plus output parsing. NO AI/LLM usage.

Tool preference (first present wins), matching common red-team box layouts:

  1. netexec / nxc            (share enum + command exec, ``-x``)
  2. crackmapexec / cme       (same CLI family as nxc)
  3. smbmap                   (script-friendly share/permission listing + ``-x``)
  4. impacket smbclient.py / smbexec.py   (share listing / command shell)
  5. smbclient (Samba)        (``-L`` share listing only; cannot exec)

Whichever tool is chosen, credentials are threaded through correctly:
password auth, NTLM pass-the-hash (``-H`` / ``-hashes`` / ``--pw-nt-hash``),
domain, and anonymous / null-session attempts (empty user + empty password).

Actions:
  * ``enum``   -> host info (where the tool provides it) plus share listing
  * ``shares`` -> share listing with access levels
  * ``exec``   -> run ``command`` on the target (requires credentials)

Everything discovered is persisted to the shared engagement store so the
report phase and other modules can see it: port 445 is recorded as an SMB
service, readable/writable shares and working null sessions become findings,
validated credentials are stored, and command output is saved as loot.

If no SMB tool is available at all, the module still records a port-445 note
and returns an actionable Result telling the operator what to install.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# A blank LM hash, prepended when the operator supplies a bare NT hash so that
# tools expecting the full ``LM:NT`` form (smbmap, impacket) are kept happy.
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

# Bounded, safe default runtime for any single SMB operation.
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 600

# nxc/crackmapexec share-table permission tokens.
_NXC_PERM = re.compile(r"^(READ|WRITE|READ,WRITE|WRITE,READ)$", re.IGNORECASE)
# smbmap permission column values.
_SMBMAP_PERM = re.compile(
    r"^(NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY|READ,WRITE)$", re.IGNORECASE
)
# nxc host banner enrichment, e.g.:
#   SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 ... (name:DC01) \
#        (domain:corp.local) (signing:True) (SMBv1:False)
_NXC_NAME = re.compile(r"\(name:([^)]*)\)")
_NXC_DOMAIN = re.compile(r"\(domain:([^)]*)\)")
_NXC_SIGNING = re.compile(r"\(signing:(True|False)\)", re.IGNORECASE)
_NXC_SMBV1 = re.compile(r"\(SMBv1:(True|False)\)", re.IGNORECASE)
_NXC_OS = re.compile(r"\[\*\]\s+(.*?)\s+\(name:")

# nxc/cme command-family binaries, in preference order.
_NXC_FAMILY = ["nxc", "netexec", "crackmapexec", "cme"]
_IMPACKET_LIST = ["smbclient.py", "impacket-smbclient"]
_IMPACKET_EXEC = ["smbexec.py", "impacket-smbexec"]


def _safe_name(value: str) -> str:
    """Turn a target string into a filesystem-safe artifact filename fragment."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def _split_hash(hashv: str) -> Tuple[str, str]:
    """Return ``(lm, nt)`` from an operator-supplied hash.

    Accepts either a full ``LM:NT`` pair or a bare NT hash (blank LM assumed).
    """
    hashv = (hashv or "").strip()
    if ":" in hashv:
        lm, nt = hashv.split(":", 1)
        return (lm.strip() or _EMPTY_LM), nt.strip()
    return _EMPTY_LM, hashv


class _Selected:
    """A chosen tool: its ``kind`` (parser family) and concrete command name."""

    def __init__(self, kind: str, cmd: str):
        self.kind = kind
        self.cmd = cmd


@register
class SmbLateral(Module):
    """Enumerate SMB shares / host info and optionally run remote commands."""

    name = "lateral.smb"
    description = "SMB enumeration & command exec wrapper (nxc/cme/smbmap/impacket/smbclient)"
    phase = "lateral"
    options = [
        Option("target", help="Target host/IP (SMB, tcp/445)", required=True),
        Option("username", default="", help="Username (empty = null/anonymous session)"),
        Option("password", default="", help="Password (empty for null session or hash auth)"),
        Option("hash", default="", help="NTLM hash for pass-the-hash ('NT' or 'LM:NT')"),
        Option("domain", default="", help="Authentication domain / workgroup"),
        Option("action", default="enum", choices=["enum", "shares", "exec"],
               help="enum/shares = list shares & access; exec = run 'command'"),
        Option("command", default="", help="Command to run for action=exec"),
        Option("timeout", default=DEFAULT_TIMEOUT,
               help="Per-operation timeout in seconds (bounded)"),
    ]
    requires_tools = ["nxc"]  # soft/optional; any of the supported tools works
    references = [
        "https://www.netexec.wiki/",
        "https://github.com/Porchetta-Industries/CrackMapExec",
        "https://github.com/ShawnDEvans/smbmap",
        "https://github.com/fortra/impacket",
    ]

    # ------------------------------------------------------------------ run
    def run(self, opts: Dict, ctx) -> Result:
        target = str(opts["target"]).strip()
        if not target:
            return Result(ok=False, summary="no target specified")

        username = str(opts.get("username") or "")
        password = str(opts.get("password") or "")
        hashv = str(opts.get("hash") or "").strip()
        domain = str(opts.get("domain") or "")
        action = str(opts.get("action") or "enum")
        command = str(opts.get("command") or "")
        timeout = max(5, min(int(opts.get("timeout") or DEFAULT_TIMEOUT), MAX_TIMEOUT))

        have_creds = bool(username) and (bool(password) or bool(hashv))
        is_null = not username and not password and not hashv

        # Fail fast on exec preconditions before touching any tool.
        if action == "exec":
            if not command:
                return Result(ok=False,
                              summary="action=exec requires the 'command' option")
            if not have_creds:
                return Result(
                    ok=False,
                    summary="action=exec requires credentials "
                            "(username + password, or username + hash)",
                )

        # Always mark the port so the engagement records the attempt.
        ctx.engagement.add_service(target, 445, "tcp", service="smb")

        selected, available = self._select_tool(ctx.runner, action)
        if selected is None:
            return self._no_tool_result(ctx, target, action, available, have_creds)

        ctx.console.info(
            f"smb {action} on {target} via {selected.cmd} "
            f"({'null-session' if is_null else (username or 'anonymous')})"
        )

        # Build argv (+ optional stdin) for the chosen tool/action.
        argv, stdin = self._build_command(
            selected, action, target, username, password, hashv, domain, command
        )
        if argv is None:
            return Result(ok=False,
                          summary=f"{selected.cmd} cannot perform action '{action}'")

        proc = ctx.runner.run(argv, timeout=timeout, input_data=stdin)
        raw = proc.text or ""

        # Persist raw output as evidence regardless of parse success.
        artifacts: List[str] = []
        try:
            out_path = ctx.artifact_path(f"smb_{action}_{_safe_name(target)}.txt")
            out_path.write_text(raw, encoding="utf-8")
            artifacts.append(str(out_path))
        except OSError:
            pass

        if proc.timed_out:
            ctx.console.warn(f"{selected.cmd} timed out after {timeout}s; "
                             "parsing partial output")

        if action == "exec":
            return self._handle_exec(
                ctx, selected, target, username, password, hashv, domain,
                command, proc, raw, artifacts,
            )
        return self._handle_enum(
            ctx, selected, target, username, password, hashv, domain,
            is_null, proc, raw, artifacts,
        )

    # -------------------------------------------------------- tool selection
    def _select_tool(self, runner, action: str) -> Tuple[Optional[_Selected], List[str]]:
        """Pick the best available tool for ``action``.

        Returns ``(selected_or_None, available_tool_names)``. The availability
        list is used to craft a precise "what to install" message when no
        suitable tool exists.
        """
        available: List[str] = []
        for name in _NXC_FAMILY + ["smbmap"] + _IMPACKET_LIST + _IMPACKET_EXEC + ["smbclient"]:
            if runner.have(name):
                available.append(name)

        # 1/2. nxc / crackmapexec family - full capability (enum, shares, exec).
        for name in _NXC_FAMILY:
            if runner.have(name):
                return _Selected("nxc", name), available

        # 3. smbmap - full capability, script-friendly.
        if runner.have("smbmap"):
            return _Selected("smbmap", "smbmap"), available

        # 4. impacket - action-specific script.
        if action == "exec":
            for name in _IMPACKET_EXEC:
                if runner.have(name):
                    return _Selected("impacket_exec", name), available
        else:
            for name in _IMPACKET_LIST:
                if runner.have(name):
                    return _Selected("impacket_list", name), available

        # 5. smbclient (Samba) - listing only, cannot exec.
        if action in ("enum", "shares") and runner.have("smbclient"):
            return _Selected("smbclient", "smbclient"), available

        return None, available

    def _no_tool_result(self, ctx, target: str, action: str,
                        available: List[str], have_creds: bool) -> Result:
        """Record a port-445 note and return install guidance."""
        if available and action == "exec":
            summary = (
                "action=exec needs netexec (nxc), crackmapexec, smbmap, or "
                "impacket smbexec.py; only found: " + ", ".join(available)
                + " (cannot exec over SMB)."
            )
        else:
            summary = (
                "No SMB tool found. Install one of: netexec "
                "('pipx install netexec'), crackmapexec, smbmap "
                "('pipx install smbmap'), impacket ('pipx install impacket'), "
                "or smbclient (Samba client)."
            )
        ctx.console.bad(summary)
        ctx.engagement.add_note(f"lateral.smb: {summary} target={target}:445")
        return Result(
            ok=False,
            summary=summary,
            data={"target": target, "action": action, "available_tools": available},
        )

    # ------------------------------------------------------- argv construction
    def _build_command(self, selected: _Selected, action: str, target: str,
                       username: str, password: str, hashv: str, domain: str,
                       command: str):
        """Return ``(argv, stdin)`` for the selected tool, or ``(None, None)``."""
        if selected.kind == "nxc":
            return self._build_nxc(selected.cmd, action, target, username,
                                   password, hashv, domain, command), None
        if selected.kind == "smbmap":
            return self._build_smbmap(action, target, username, password,
                                      hashv, domain, command), None
        if selected.kind == "impacket_list":
            return self._build_impacket_list(selected.cmd, target, username,
                                             password, hashv, domain)
        if selected.kind == "impacket_exec":
            return self._build_impacket_exec(selected.cmd, target, username,
                                             password, hashv, domain, command)
        if selected.kind == "smbclient":
            return self._build_smbclient(target, username, password, hashv,
                                         domain), None
        return None, None

    @staticmethod
    def _build_nxc(cmd: str, action: str, target: str, username: str,
                   password: str, hashv: str, domain: str, command: str) -> List[str]:
        """netexec/crackmapexec: ``<cmd> smb <target> -u U (-p P | -H HASH) ...``."""
        argv = [cmd, "smb", target, "-u", username]
        if hashv:
            argv += ["-H", hashv]
        else:
            argv += ["-p", password]
        if domain:
            argv += ["-d", domain]
        if action == "exec":
            argv += ["-x", command]
        else:  # enum / shares - --shares also prints the host banner line
            argv += ["--shares"]
        return argv

    @staticmethod
    def _build_smbmap(action: str, target: str, username: str, password: str,
                      hashv: str, domain: str, command: str) -> List[str]:
        """smbmap: ``-H HOST`` is the target; pass-the-hash rides in ``-p``."""
        argv = ["smbmap", "-H", target, "-u", username or ""]
        if hashv:
            lm, nt = _split_hash(hashv)
            argv += ["-p", f"{lm}:{nt}"]
        else:
            argv += ["-p", password or ""]
        if domain:
            argv += ["-d", domain]
        if action == "exec":
            argv += ["-x", command]
        # Default smbmap behaviour (no -x) lists shares with access levels.
        return argv

    @staticmethod
    def _impacket_target(username: str, password: str, hashv: str,
                         domain: str, target: str) -> str:
        """Build impacket's ``[domain/]user[:password]@target`` connection string."""
        userpart = ""
        if domain:
            userpart = domain + "/"
        userpart += username or ""
        if password and not hashv:
            userpart += ":" + password
        return (userpart + "@" + target) if userpart else target

    def _build_impacket_list(self, cmd: str, target: str, username: str,
                             password: str, hashv: str, domain: str):
        """impacket smbclient.py: feed ``shares`` over stdin to list shares."""
        argv = [cmd, self._impacket_target(username, password, hashv, domain, target)]
        if hashv:
            lm, nt = _split_hash(hashv)
            argv += ["-hashes", f"{lm}:{nt}"]
        if not username and not password and not hashv:
            argv += ["-no-pass"]
        return argv, "shares\nexit\n"

    def _build_impacket_exec(self, cmd: str, target: str, username: str,
                             password: str, hashv: str, domain: str, command: str):
        """impacket smbexec.py: feed the command over stdin to its shell."""
        argv = [cmd, self._impacket_target(username, password, hashv, domain, target)]
        if hashv:
            lm, nt = _split_hash(hashv)
            argv += ["-hashes", f"{lm}:{nt}"]
        return argv, f"{command}\nexit\n"

    @staticmethod
    def _build_smbclient(target: str, username: str, password: str,
                         hashv: str, domain: str) -> List[str]:
        """Samba smbclient: ``-L //target`` grepable share listing."""
        argv = ["smbclient", "-L", f"//{target}", "-g"]
        if not username and not password and not hashv:
            argv += ["-N"]  # anonymous / null session
            return argv
        userspec = (domain + "\\" if domain else "") + (username or "")
        if hashv:
            _lm, nt = _split_hash(hashv)
            argv += ["-U", f"{userspec}%{nt}", "--pw-nt-hash"]
        else:
            argv += ["-U", f"{userspec}%{password}"]
        return argv

    # ---------------------------------------------------------- enum handling
    def _handle_enum(self, ctx, selected: _Selected, target: str, username: str,
                     password: str, hashv: str, domain: str, is_null: bool,
                     proc, raw: str, artifacts: List[str]) -> Result:
        """Parse share/host output, persist services + findings, summarise."""
        host_info = self._parse_host_info(raw) if selected.kind == "nxc" else {}
        shares = self._parse_shares(selected.kind, raw)
        auth_ok = self._auth_succeeded(selected.kind, raw, proc, shares)

        # Persist the SMB service, enriching with any parsed host details.
        hostname = host_info.get("name")
        os_str = host_info.get("os")
        if hostname or os_str:
            ctx.engagement.add_host(target, hostname=hostname, os_=os_str)
        ctx.engagement.add_service(
            target, 445, "tcp", service="smb",
            product=os_str or None, banner=host_info.get("banner"),
        )

        # Record validated credentials.
        if auth_ok and not is_null and (username or password or hashv):
            ctx.engagement.add_cred(
                service="smb", host=target, username=username or None,
                password=password or None, secret_hash=hashv or None,
                source="lateral.smb",
            )

        findings = 0
        evidence = raw.strip()[:800] or None

        # Null-session enumeration is itself a finding.
        if is_null and shares:
            ctx.engagement.add_finding(
                "SMB null session permits share enumeration",
                severity="medium", host=target,
                description=f"Anonymous session listed {len(shares)} share(s) on "
                            f"{target} without credentials.",
                evidence=evidence,
            )
            findings += 1

        # Per-share access findings (writable > readable; ignore IPC$ READ noise).
        for share in shares:
            name = share.get("name", "")
            perms = (share.get("permissions") or "").upper()
            if "WRITE" in perms:
                ctx.engagement.add_finding(
                    f"Writable SMB share '{name}' on {target}",
                    severity="high", host=target,
                    description=f"Share '{name}' grants WRITE access "
                                f"({share.get('permissions')}).",
                    evidence=evidence,
                )
                findings += 1
            elif "READ" in perms and name.upper() not in ("IPC$",):
                ctx.engagement.add_finding(
                    f"Readable SMB share '{name}' on {target}",
                    severity="medium", host=target,
                    description=f"Share '{name}' grants READ access "
                                f"({share.get('permissions')}).",
                    evidence=evidence,
                )
                findings += 1

        # Admin access markers imply code execution is possible.
        if "Pwn3d!" in raw:
            ctx.engagement.add_finding(
                f"SMB administrative access on {target} (Pwn3d!)",
                severity="high", host=target,
                description="Supplied credentials have administrative access; "
                            "remote command execution is possible.",
                evidence=evidence,
            )
            findings += 1

        # Configuration weaknesses from the nxc host banner.
        if host_info.get("signing") is False:
            ctx.engagement.add_finding(
                f"SMB signing not required on {target}",
                severity="low", host=target,
                description="Server does not require SMB signing (relay risk).",
                evidence=host_info.get("banner"),
            )
            findings += 1
        if host_info.get("smbv1") is True:
            ctx.engagement.add_finding(
                f"SMBv1 enabled on {target}",
                severity="medium", host=target,
                description="Legacy SMBv1 is enabled (deprecated, exploitable).",
                evidence=host_info.get("banner"),
            )
            findings += 1

        # Console summary.
        if shares:
            ctx.console.good(f"{len(shares)} share(s) on {target}:")
            ctx.console.table(
                ["share", "access", "remark"],
                [[s.get("name", ""), s.get("permissions") or "",
                  s.get("remark") or ""] for s in shares],
            )
        elif proc.ok:
            ctx.console.info(f"no shares listed on {target}")
        else:
            ctx.console.warn(
                f"{selected.cmd} returned rc={proc.returncode}; "
                "target may be unreachable or auth failed"
            )

        ctx.engagement.add_note(
            f"lateral.smb enum {target} via {selected.cmd}: "
            f"{len(shares)} share(s), {findings} finding(s)"
        )

        ok = bool(shares) or auth_ok or proc.ok
        summary = (
            f"{len(shares)} share(s), {findings} finding(s) on {target} "
            f"(tool={selected.cmd}, auth={'ok' if auth_ok else 'n/a'})"
        )
        return Result(
            ok=ok,
            summary=summary,
            data={
                "target": target,
                "action": "enum",
                "tool": selected.cmd,
                "authenticated": auth_ok,
                "null_session": is_null,
                "shares": shares,
                "host_info": host_info,
                "findings": findings,
                "returncode": proc.returncode,
                "timed_out": proc.timed_out,
            },
            artifacts=artifacts,
        )

    # ---------------------------------------------------------- exec handling
    def _handle_exec(self, ctx, selected: _Selected, target: str, username: str,
                     password: str, hashv: str, domain: str, command: str,
                     proc, raw: str, artifacts: List[str]) -> Result:
        """Persist command output as loot + a high-severity finding."""
        output = self._extract_exec_output(selected.kind, raw)
        auth_ok = self._auth_succeeded(selected.kind, raw, proc, [])
        produced = bool(output.strip())

        if produced or auth_ok:
            ctx.engagement.add_cred(
                service="smb", host=target, username=username or None,
                password=password or None, secret_hash=hashv or None,
                source="lateral.smb",
            )
            ctx.engagement.add_loot(
                host=target, kind="command-output",
                value=(output.strip()[:4000] or raw.strip()[:4000]),
                source=f"lateral.smb:{selected.cmd}:{command}",
            )
            ctx.engagement.add_finding(
                f"Remote command execution via SMB on {target}",
                severity="high", host=target,
                description=f"Executed '{command}' via {selected.cmd} using the "
                            "supplied credentials.",
                evidence=(output.strip()[:800] or raw.strip()[:800]) or None,
            )
            ctx.console.good(f"exec ok on {target}; output captured")
            if output.strip():
                ctx.console.raw(output.strip()[:2000])
            summary = f"command executed on {target} via {selected.cmd}"
            ok = True
        else:
            ctx.console.warn(
                f"exec produced no output on {target} "
                f"(rc={proc.returncode}); auth may have failed"
            )
            summary = (f"exec via {selected.cmd} produced no output on {target} "
                       f"(rc={proc.returncode})")
            ok = False

        ctx.engagement.add_note(
            f"lateral.smb exec {target} via {selected.cmd}: "
            f"'{command}' -> {'output' if produced else 'no output'}"
        )
        return Result(
            ok=ok,
            summary=summary,
            data={
                "target": target,
                "action": "exec",
                "tool": selected.cmd,
                "command": command,
                "authenticated": auth_ok,
                "output": output.strip()[:4000],
                "returncode": proc.returncode,
                "timed_out": proc.timed_out,
            },
            artifacts=artifacts,
        )

    # ------------------------------------------------------------ parsers
    def _parse_shares(self, kind: str, text: str) -> List[Dict]:
        """Dispatch to the tool-specific share parser."""
        if kind == "nxc":
            return self._parse_nxc_shares(text)
        if kind == "smbmap":
            return self._parse_smbmap_shares(text)
        if kind == "smbclient":
            return self._parse_smbclient_shares(text)
        if kind == "impacket_list":
            return self._parse_impacket_shares(text)
        return []

    @staticmethod
    def _parse_nxc_shares(text: str) -> List[Dict]:
        """Parse the ``--shares`` table emitted by nxc / crackmapexec.

        Lines look like ``SMB host 445 HOST  ShareName  READ  Remark`` after a
        ``Share  Permissions  Remark`` header; the leading five metadata fields
        are stripped before column parsing.
        """
        shares: List[Dict] = []
        in_table = False
        for line in text.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            rest = parts[4].strip()
            low = rest.lower()
            if low.startswith("share") and "permission" in low:
                in_table = True
                continue
            if set(rest) <= set("- "):  # separator row
                continue
            if not in_table:
                continue
            tokens = rest.split()
            if not tokens:
                continue
            name = tokens[0]
            perm_tokens: List[str] = []
            i = 1
            while i < len(tokens) and _NXC_PERM.match(tokens[i]):
                perm_tokens.append(tokens[i].upper())
                i += 1
            remark = " ".join(tokens[i:])
            shares.append({
                "name": name,
                "permissions": " ".join(perm_tokens),
                "remark": remark,
            })
        return shares

    @staticmethod
    def _parse_smbmap_shares(text: str) -> List[Dict]:
        """Parse smbmap's ``Disk  Permissions  Comment`` share table."""
        shares: List[Dict] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            low = stripped.lower()
            if low.startswith("disk") or set(stripped) <= set("- "):
                continue
            m = re.match(
                r"^(\S+)\s+(NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY|READ,WRITE)"
                r"\s*(.*)$",
                stripped, re.IGNORECASE,
            )
            if not m:
                continue
            perms = m.group(2).upper()
            shares.append({
                "name": m.group(1),
                "permissions": "" if perms == "NO ACCESS" else perms,
                "remark": m.group(3).strip(),
            })
        return shares

    @staticmethod
    def _parse_smbclient_shares(text: str) -> List[Dict]:
        """Parse ``smbclient -L -g`` grepable output (``Disk|NAME|Comment``).

        smbclient does not report per-share access, only visibility, so
        ``permissions`` is left empty.
        """
        shares: List[Dict] = []
        for line in text.splitlines():
            line = line.strip()
            if "|" not in line:
                continue
            fields = line.split("|")
            if len(fields) < 2:
                continue
            stype, name = fields[0].strip(), fields[1].strip()
            if stype.lower() not in ("disk", "ipc", "printer"):
                continue
            if not name:
                continue
            shares.append({
                "name": name,
                "permissions": "",
                "remark": fields[2].strip() if len(fields) > 2 else "",
            })
        return shares

    @staticmethod
    def _parse_impacket_shares(text: str) -> List[Dict]:
        """Best-effort parse of impacket smbclient.py ``shares`` output.

        The interactive client prints one share name per line; noise lines
        (banners, prompts, errors) are filtered out.
        """
        shares: List[Dict] = []
        noise = ("impacket", "copyright", "[-]", "[*]", "[+]", "type help",
                 "error", "traceback", "#")
        for line in text.splitlines():
            token = line.strip()
            if not token:
                continue
            low = token.lower()
            if any(low.startswith(n) for n in noise):
                continue
            if " " in token or not re.match(r"^[A-Za-z0-9$._-]+$", token):
                continue
            shares.append({"name": token, "permissions": "", "remark": ""})
        return shares

    @staticmethod
    def _parse_host_info(text: str) -> Dict:
        """Extract OS / hostname / signing / SMBv1 from an nxc banner line."""
        info: Dict = {}
        for line in text.splitlines():
            if "(name:" not in line:
                continue
            m = _NXC_NAME.search(line)
            if m:
                info["name"] = m.group(1).strip() or None
            m = _NXC_DOMAIN.search(line)
            if m:
                info["domain"] = m.group(1).strip() or None
            m = _NXC_OS.search(line)
            if m:
                info["os"] = m.group(1).strip() or None
            m = _NXC_SIGNING.search(line)
            if m:
                info["signing"] = (m.group(1).lower() == "true")
            m = _NXC_SMBV1.search(line)
            if m:
                info["smbv1"] = (m.group(1).lower() == "true")
            info["banner"] = line.strip()[:300]
            break
        return info

    @staticmethod
    def _auth_succeeded(kind: str, text: str, proc, shares: List[Dict]) -> bool:
        """Heuristically decide whether authentication/enumeration worked."""
        if "Pwn3d!" in text:
            return True
        if kind == "nxc":
            # nxc marks a successful login with a green [+] line.
            for line in text.splitlines():
                if "[+]" in line and "smb" in line.lower():
                    return True
            return False
        if kind == "smbmap":
            return "[+] IP:" in text or bool(shares)
        if kind in ("smbclient", "impacket_list", "impacket_exec"):
            return bool(shares) or (proc.ok and "NT_STATUS" not in text)
        return proc.ok

    @staticmethod
    def _extract_exec_output(kind: str, text: str) -> str:
        """Pull command output out of a tool's decorated stdout."""
        if kind == "nxc":
            # nxc prefixes each output line with "SMB host 445 HOST ".
            lines: List[str] = []
            for line in text.splitlines():
                parts = line.split(None, 4)
                if len(parts) == 5 and parts[0].upper() == "SMB":
                    rest = parts[4]
                    if rest.lstrip().startswith("[") or "Pwn3d!" in rest:
                        continue
                    lines.append(rest)
            if lines:
                return "\n".join(lines)
            return text
        # smbmap / impacket: strip obvious banner/status noise, keep the rest.
        cleaned: List[str] = []
        for line in text.splitlines():
            low = line.strip().lower()
            if low.startswith(("impacket", "[+]", "[-]", "[*]", "copyright")):
                continue
            cleaned.append(line)
        return "\n".join(cleaned).strip() or text
