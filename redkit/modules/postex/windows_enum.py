"""Windows local privilege-escalation enumeration.

A deterministic, rule-based enumerator for classic Windows local privilege
escalation vectors. It shells out to *native* Windows commands only
(``whoami``, ``systeminfo``, ``wmic``/``sc``, ``reg``, ``schtasks``,
``cmdkey``) via :class:`redkit.core.runner.Runner`, parses their output with
simple heuristics, and records findings/loot into the shared engagement
state so the report module and other modules can consume them.

Design constraints honored here:

* **No AI / no network.** Everything is local command parsing and regexes.
* **Pure stdlib.** No third-party imports.
* **Cross-platform import.** No Windows-only APIs are touched at import time.
  When run off Windows (or with ``run_local=false``) the module still
  *succeeds*: it writes an offline enumeration checklist/script to the
  artifact so an operator can run the checks manually on a target host.
* **Non-destructive.** Read-only queries with bounded timeouts. The only
  write performed is a best-effort, self-cleaning writability probe used to
  detect user-writable ``PATH`` / service-binary directories (a standard
  privesc check); every probe file is uniquely named and removed.

Vectors enumerated on Windows:

* Current identity, groups and token privileges (``whoami /all``,
  ``whoami /priv``) - dangerous privileges such as ``SeImpersonatePrivilege``
  / ``SeAssignPrimaryTokenPrivilege`` (potato attacks) are flagged.
* OS name / build / installed hotfixes (``systeminfo``).
* Unquoted service paths (space in an unquoted ``BINARY_PATH_NAME``).
* Service binaries living in user-writable directories.
* ``AlwaysInstallElevated`` (HKLM **and** HKCU both set to 1).
* Autologon credentials stored in the Winlogon registry key.
* Stored credentials in the Credential Manager (``cmdkey /list``).
* Scheduled tasks (captured for review).
* Writable directories present on ``PATH`` (DLL/binary hijack surface).
"""
from __future__ import annotations

import os
import platform
import re
import uuid
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Token privileges that materially help local privilege escalation. Even when
# a privilege is reported "Disabled" the holder can enable it, so presence
# alone is worth flagging.
DANGEROUS_PRIVS: Dict[str, Tuple[str, str]] = {
    "SeImpersonatePrivilege": (
        "high",
        "Impersonation token privilege enables 'potato' SYSTEM escalation "
        "(JuicyPotato / PrintSpoofer / RoguePotato).",
    ),
    "SeAssignPrimaryTokenPrivilege": (
        "high",
        "Assign-primary-token privilege enables 'potato' style token "
        "escalation to SYSTEM.",
    ),
    "SeDebugPrivilege": (
        "high",
        "Debug privilege allows reading/injecting into any process "
        "(e.g. dumping LSASS).",
    ),
    "SeBackupPrivilege": (
        "medium",
        "Backup privilege grants read access to any file (SAM/SYSTEM hives).",
    ),
    "SeRestorePrivilege": (
        "medium",
        "Restore privilege grants write access to any file / registry key.",
    ),
    "SeTakeOwnershipPrivilege": (
        "medium",
        "Take-ownership privilege allows seizing any securable object.",
    ),
    "SeLoadDriverPrivilege": (
        "medium",
        "Load-driver privilege can load a vulnerable driver for kernel code exec.",
    ),
    "SeManageVolumePrivilege": (
        "medium",
        "Manage-volume privilege can be abused for arbitrary file write.",
    ),
    "SeTcbPrivilege": (
        "high",
        "Act-as-part-of-the-OS privilege is effectively SYSTEM-equivalent.",
    ),
}

# Directory prefixes considered OS-protected (not attacker-writable by default).
# Used to reduce false positives when flagging writable service/PATH dirs.
_PROTECTED_PREFIXES = (
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
)


@register
class WindowsEnum(Module):
    """Enumerate local Windows privilege-escalation opportunities."""

    name = "postex.windows_enum"
    description = "Windows local privilege-escalation enumeration (rule-based)"
    phase = "postex"
    options = [
        Option(
            "run_local",
            default=True,
            help="Run live enumeration when executing on this Windows host "
            "(otherwise write an offline checklist to the artifact).",
        ),
        Option(
            "out",
            default="windows_enum.txt",
            help="Artifact filename written inside the engagement workdir.",
        ),
    ]
    requires_tools: List[str] = []  # relies on built-in Windows commands only
    references = [
        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/"
        "Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md",
        "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation",
        "https://lolbas-project.github.io/",
    ]

    # -- entry point -------------------------------------------------------
    def run(self, opts: Dict[str, object], ctx) -> Result:
        out_name = str(opts.get("out") or "windows_enum.txt")
        run_local = bool(opts.get("run_local"))
        artifact = ctx.artifact_path(out_name)

        if not (run_local and os.name == "nt"):
            return self._offline_checklist(artifact, ctx, run_local)

        return self._enumerate_windows(artifact, ctx)

    # ------------------------------------------------------------------
    # Live Windows enumeration
    # ------------------------------------------------------------------
    def _enumerate_windows(self, artifact, ctx) -> Result:
        console = ctx.console
        console.info("running local Windows privilege-escalation enumeration")

        sections: List[Tuple[str, str]] = []  # (title, raw_output)
        findings: List[Dict[str, object]] = []
        data: Dict[str, object] = {"host": "localhost", "checks": {}}
        host = "localhost"

        def record(section: str, output: str) -> None:
            sections.append((section, output))

        def add_finding(title, severity, description, evidence=None) -> None:
            findings.append(
                {"title": title, "severity": severity, "description": description}
            )
            try:
                ctx.engagement.add_finding(
                    title,
                    severity=severity,
                    host=host,
                    description=description,
                    evidence=evidence,
                )
            except Exception:  # engagement writes must never crash enumeration
                pass

        # -- identity / privileges ------------------------------------
        whoami_all = self._cmd(ctx, ["whoami", "/all"], timeout=30)
        record("whoami /all", whoami_all)

        whoami_priv = self._cmd(ctx, ["whoami", "/priv"], timeout=30)
        record("whoami /priv", whoami_priv)
        priv_hits = self._parse_privileges(whoami_priv)
        data["checks"]["dangerous_privileges"] = priv_hits
        for priv in priv_hits:
            sev, desc = DANGEROUS_PRIVS[priv]
            add_finding(
                f"Dangerous token privilege held: {priv}",
                sev,
                desc,
                evidence=priv,
            )

        whoami_user = self._cmd(ctx, ["whoami"], timeout=15).strip()
        data["checks"]["whoami"] = whoami_user

        # -- OS / patch level -----------------------------------------
        systeminfo = self._cmd(ctx, ["systeminfo"], timeout=90)
        record("systeminfo", systeminfo)
        os_name, hotfix_count = self._parse_systeminfo(systeminfo)
        if not os_name:
            # systeminfo is localized on non-English Windows; fall back to the
            # (locale-independent) platform module so OS is still recorded.
            try:
                os_name = platform.platform() or None
            except Exception:
                os_name = None
        data["checks"]["os"] = os_name
        data["checks"]["hotfix_count"] = hotfix_count
        if os_name:
            try:
                ctx.engagement.add_host(host, os_=os_name)
            except Exception:
                pass
        if hotfix_count == 0 and systeminfo.strip():
            add_finding(
                "No hotfixes reported by systeminfo",
                "medium",
                "systeminfo lists zero installed hotfixes; host may be missing "
                "security patches (verify and cross-reference with a kernel "
                "exploit suggester offline).",
            )

        # -- services: unquoted paths + writable binaries -------------
        services, svc_raw = self._collect_services(ctx)
        record("services (name / startmode / path)", svc_raw)
        unquoted = []
        writable_bins = []
        for svc in services:
            path = svc.get("path", "")
            if self._is_unquoted_service_path(path):
                unquoted.append(svc)
            exe = self._service_exe(path)
            if exe and self._exe_dir_writable(exe):
                writable_bins.append({**svc, "exe": exe})

        data["checks"]["unquoted_service_paths"] = [
            {"name": s.get("name"), "path": s.get("path")} for s in unquoted
        ]
        for svc in unquoted:
            add_finding(
                f"Unquoted service path: {svc.get('name')}",
                "high",
                "Service binary path contains a space and is not quoted; a "
                "writable intermediate directory allows binary planting to run "
                "as the service account.",
                evidence=svc.get("path"),
            )

        data["checks"]["writable_service_binaries"] = [
            {"name": s.get("name"), "exe": s.get("exe")} for s in writable_bins
        ]
        for svc in writable_bins:
            add_finding(
                f"Writable service binary directory: {svc.get('name')}",
                "high",
                "Directory of the service executable is writable by the current "
                "user; the binary can be replaced to run as the service account.",
                evidence=svc.get("exe"),
            )

        # -- AlwaysInstallElevated ------------------------------------
        aie_hklm = self._cmd(
            ctx,
            [
                "reg", "query",
                r"HKLM\Software\Policies\Microsoft\Windows\Installer",
                "/v", "AlwaysInstallElevated",
            ],
            timeout=20,
        )
        aie_hkcu = self._cmd(
            ctx,
            [
                "reg", "query",
                r"HKCU\Software\Policies\Microsoft\Windows\Installer",
                "/v", "AlwaysInstallElevated",
            ],
            timeout=20,
        )
        record("AlwaysInstallElevated (HKLM)", aie_hklm)
        record("AlwaysInstallElevated (HKCU)", aie_hkcu)
        hklm_on = self._reg_dword_is_one(aie_hklm, "AlwaysInstallElevated")
        hkcu_on = self._reg_dword_is_one(aie_hkcu, "AlwaysInstallElevated")
        data["checks"]["always_install_elevated"] = {
            "hklm": hklm_on,
            "hkcu": hkcu_on,
        }
        if hklm_on and hkcu_on:
            add_finding(
                "AlwaysInstallElevated enabled (HKLM and HKCU)",
                "high",
                "Both AlwaysInstallElevated keys are set to 1; any MSI package "
                "installs with SYSTEM privileges (msfvenom/msiexec escalation).",
            )

        # -- Autologon credentials ------------------------------------
        winlogon = self._cmd(
            ctx,
            [
                "reg", "query",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            ],
            timeout=20,
        )
        record("Winlogon (autologon)", winlogon)
        autologon = self._parse_autologon(winlogon)
        data["checks"]["autologon"] = {
            k: v for k, v in autologon.items() if k != "DefaultPassword"
        }
        if autologon.get("DefaultPassword"):
            data["checks"]["autologon"]["DefaultPassword_present"] = True
            add_finding(
                "Autologon password stored in registry",
                "high",
                "Winlogon DefaultPassword is set in cleartext; recover a valid "
                "credential from HKLM Winlogon.",
                evidence=f"user={autologon.get('DefaultUserName')}",
            )
            try:
                ctx.engagement.add_cred(
                    "windows",
                    host=host,
                    username=autologon.get("DefaultUserName"),
                    password=autologon.get("DefaultPassword"),
                    source="winlogon-autologon",
                )
                ctx.engagement.add_loot(
                    host,
                    "credential",
                    f"{autologon.get('DefaultUserName')}:{autologon.get('DefaultPassword')}",
                    source="winlogon-autologon",
                )
            except Exception:
                pass

        # -- Stored credentials (Credential Manager) ------------------
        cmdkey = self._cmd(ctx, ["cmdkey", "/list"], timeout=20)
        record("cmdkey /list", cmdkey)
        targets = self._parse_cmdkey(cmdkey)
        data["checks"]["stored_credentials"] = targets
        if targets:
            add_finding(
                "Stored credentials present in Credential Manager",
                "medium",
                "cmdkey lists saved credentials that may be reusable for lateral "
                "movement (runas /savecred, WinRM, RDP).",
                evidence="; ".join(targets[:10]),
            )
            for tgt in targets:
                try:
                    ctx.engagement.add_loot(
                        host, "stored-credential", tgt, source="cmdkey"
                    )
                except Exception:
                    pass

        # -- Scheduled tasks (captured for review) --------------------
        schtasks = self._cmd(
            ctx, ["schtasks", "/query", "/fo", "LIST", "/v"], timeout=60
        )
        record("schtasks /query /fo LIST /v", schtasks)
        task_count = schtasks.count("TaskName:")
        data["checks"]["scheduled_task_count"] = task_count

        # -- Writable PATH directories --------------------------------
        path_dirs = self._writable_path_dirs()
        record(
            "writable PATH directories",
            "\n".join(path_dirs) if path_dirs else "(none detected)",
        )
        data["checks"]["writable_path_dirs"] = path_dirs
        if path_dirs:
            # One consolidated finding rather than one-per-directory: on dev
            # boxes many user-installed tool dirs (AppData, Python, node) sit on
            # PATH and are legitimately user-writable. It is a real DLL/binary
            # hijack vector but context-dependent, so report it once at medium.
            add_finding(
                f"User-writable director{'y' if len(path_dirs) == 1 else 'ies'} on PATH ({len(path_dirs)})",
                "medium",
                "One or more directories on the system/user PATH are writable by "
                "the current user, enabling binary/DLL hijack of programs launched "
                "without a full path. Review each and prioritise those ahead of "
                "system directories in PATH order.",
                evidence="; ".join(path_dirs),
            )

        # -- persist a rollup note & write the raw artifact -----------
        try:
            ctx.engagement.add_note(
                "postex.windows_enum: "
                f"{len(findings)} finding(s); "
                f"privs={priv_hits}; "
                f"unquoted={len(unquoted)}; writable_bins={len(writable_bins)}; "
                f"writable_path={len(path_dirs)}"
            )
        except Exception:
            pass

        written = self._write_artifact(artifact, sections, ctx)

        high = sum(1 for f in findings if f["severity"] in ("high", "critical"))
        summary = (
            f"Windows enum complete: {len(findings)} finding(s) "
            f"({high} high/critical). OS={os_name or 'unknown'}."
        )
        console.good(summary)
        artifacts = [str(written)] if written else []
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # ------------------------------------------------------------------
    # Offline / non-Windows path
    # ------------------------------------------------------------------
    def _offline_checklist(self, artifact, ctx, run_local: bool) -> Result:
        reason = (
            "run_local disabled"
            if (run_local is False and os.name == "nt")
            else f"not running on Windows (os.name={os.name!r})"
        )
        ctx.console.info(
            f"{reason}: writing offline Windows enumeration checklist"
        )
        content = _CHECKLIST_SCRIPT
        written = None
        try:
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(content, encoding="utf-8")
            written = artifact
        except OSError as exc:
            return Result(
                ok=False,
                summary=f"could not write checklist artifact: {exc}",
                data={"reason": reason},
            )
        try:
            ctx.engagement.add_note(
                f"postex.windows_enum: {reason}; wrote offline checklist to "
                f"{written}"
            )
        except Exception:
            pass
        summary = (
            "Offline mode: wrote Windows privilege-escalation enumeration "
            f"checklist ({reason}). Run it on the target host."
        )
        return Result(
            ok=True,
            summary=summary,
            data={"mode": "offline", "reason": reason},
            artifacts=[str(written)] if written else [],
        )

    # ------------------------------------------------------------------
    # Command helper
    # ------------------------------------------------------------------
    @staticmethod
    def _cmd(ctx, argv: List[str], timeout: int = 30) -> str:
        """Run a command via the runner, never raising. Returns combined text.

        A missing command (rc 127) or timeout yields an explanatory string so
        the artifact still documents that the check was attempted.
        """
        try:
            res = ctx.runner.run(argv, timeout=timeout)
        except Exception as exc:  # defensive: runner should not raise, but be safe
            return f"[error running {' '.join(argv)}: {exc}]"
        if res.timed_out:
            return f"[timed out after {timeout}s]\n{res.text}"
        if res.returncode == 127:
            return f"[command not available: {argv[0]}]"
        return res.text

    # ------------------------------------------------------------------
    # Parsers (pure, deterministic)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_privileges(text: str) -> List[str]:
        """Return dangerous privilege names present in ``whoami /priv`` output."""
        hits = []
        for name in DANGEROUS_PRIVS:
            # match at a word boundary; privilege appears as the first column
            if re.search(rf"\b{re.escape(name)}\b", text):
                hits.append(name)
        return hits

    @staticmethod
    def _parse_systeminfo(text: str) -> Tuple[Optional[str], int]:
        os_name = None
        hotfix_count = 0
        for line in text.splitlines():
            if os_name is None:
                m = re.match(r"\s*OS Name:\s*(.+?)\s*$", line, re.IGNORECASE)
                if m:
                    os_name = m.group(1).strip()
        # Hotfixes are listed as "KBnnnnnnn" entries in the Hotfix(s) block.
        hotfix_count = len(re.findall(r"\bKB\d{6,7}\b", text))
        return os_name, hotfix_count

    @staticmethod
    def _reg_dword_is_one(text: str, value_name: str) -> bool:
        """True if ``reg query`` output shows ``value_name`` REG_DWORD == 1."""
        m = re.search(
            rf"{re.escape(value_name)}\s+REG_DWORD\s+0x0*([0-9a-fA-F]+)",
            text,
        )
        if not m:
            return False
        try:
            return int(m.group(1), 16) == 1
        except ValueError:
            return False

    @staticmethod
    def _parse_autologon(text: str) -> Dict[str, str]:
        wanted = (
            "AutoAdminLogon",
            "DefaultUserName",
            "DefaultDomainName",
            "DefaultPassword",
        )
        out: Dict[str, str] = {}
        for line in text.splitlines():
            for key in wanted:
                m = re.search(
                    rf"\b{key}\s+REG_[A-Z_]+\s+(.*)$", line
                )
                if m:
                    out[key] = m.group(1).strip()
        return out

    @staticmethod
    def _parse_cmdkey(text: str) -> List[str]:
        """Extract 'Target:' entries from ``cmdkey /list`` output."""
        targets = []
        for line in text.splitlines():
            m = re.search(r"Target:\s*(.+?)\s*$", line)
            if m:
                targets.append(m.group(1).strip())
        return targets

    # ------------------------------------------------------------------
    # Service collection & path analysis
    # ------------------------------------------------------------------
    def _collect_services(self, ctx) -> Tuple[List[Dict[str, str]], str]:
        """Collect (name, startmode, path) triples.

        Prefers ``wmic service`` (list format is trivially parseable); falls
        back to ``sc query`` + ``sc qc`` when wmic is unavailable (Win11 has
        begun removing wmic). Returns the parsed services and a raw text dump.
        """
        # -- attempt wmic ---------------------------------------------
        wmic = self._cmd(
            ctx,
            [
                "wmic", "service", "get",
                "Name,PathName,StartMode", "/format:list",
            ],
            timeout=45,
        )
        services = self._parse_wmic_list(wmic)
        if services:
            return services, wmic

        # -- fall back to sc ------------------------------------------
        names = self._sc_service_names(ctx)
        raw_parts: List[str] = ["[wmic unavailable - using sc query/qc fallback]"]
        parsed: List[Dict[str, str]] = []
        # bound the number of per-service queries for safety
        for name in names[:200]:
            qc = self._cmd(ctx, ["sc", "qc", name], timeout=15)
            raw_parts.append(f"--- sc qc {name} ---\n{qc}")
            path = self._parse_sc_binpath(qc)
            if path:
                parsed.append(
                    {"name": name, "startmode": "", "path": path}
                )
        return parsed, "\n".join(raw_parts)

    @staticmethod
    def _parse_wmic_list(text: str) -> List[Dict[str, str]]:
        services: List[Dict[str, str]] = []
        cur: Dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                if cur.get("path"):
                    services.append(cur)
                cur = {}
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip().lower()
            val = val.strip()
            if key == "name":
                cur["name"] = val
            elif key == "pathname":
                cur["path"] = val
            elif key == "startmode":
                cur["startmode"] = val
        if cur.get("path"):
            services.append(cur)
        return services

    def _sc_service_names(self, ctx) -> List[str]:
        text = self._cmd(
            ctx,
            ["sc", "query", "type=", "service", "state=", "all"],
            timeout=45,
        )
        names = []
        for line in text.splitlines():
            m = re.match(r"\s*SERVICE_NAME:\s*(.+?)\s*$", line)
            if m:
                names.append(m.group(1).strip())
        return names

    @staticmethod
    def _parse_sc_binpath(text: str) -> str:
        m = re.search(r"BINARY_PATH_NAME\s*:\s*(.+?)\s*$", text, re.MULTILINE)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _is_unquoted_service_path(pathname: str) -> bool:
        """Heuristic: unquoted binary path with a space in the executable path.

        A path is exploitable when it is not wrapped in quotes and the portion
        up to (and including) the ``.exe`` contains a space, so Windows may
        resolve an attacker-controlled intermediate path first. Paths already
        quoted, or with no space before ``.exe``, or that are not filesystem
        paths (e.g. driver device paths) are ignored.
        """
        p = (pathname or "").strip()
        if not p or p.startswith('"'):
            return False
        low = p.lower()
        # driver / kernel service paths are not classic unquoted-path targets
        if low.startswith("\\systemroot") or low.startswith("\\??\\"):
            return False
        idx = low.find(".exe")
        exe = p if idx == -1 else p[: idx + 4]
        if " " not in exe:
            return False
        # must look like an absolute filesystem path: "X:\..." or UNC "\\..."
        if not (len(exe) >= 3 and (exe[1:3] == ":\\" or exe.startswith("\\\\"))):
            return False
        return True

    @staticmethod
    def _service_exe(pathname: str) -> str:
        """Extract the executable path from a service ``PathName`` string."""
        p = (pathname or "").strip()
        if not p:
            return ""
        if p.startswith('"'):
            end = p.find('"', 1)
            return p[1:end] if end != -1 else p[1:]
        low = p.lower()
        idx = low.find(".exe")
        if idx != -1:
            return p[: idx + 4]
        return p.split(" ", 1)[0]

    def _exe_dir_writable(self, exe: str) -> bool:
        """True if the directory holding ``exe`` is writable and not OS-protected."""
        try:
            d = os.path.dirname(exe)
            if not d or not os.path.isdir(d):
                return False
            low = d.lower().rstrip("\\")
            for prefix in _PROTECTED_PREFIXES:
                if low == prefix or low.startswith(prefix + "\\"):
                    return False
            return self._dir_writable(d)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # PATH analysis
    # ------------------------------------------------------------------
    def _writable_path_dirs(self) -> List[str]:
        dirs: List[str] = []
        seen = set()
        raw = os.environ.get("PATH", "")
        for entry in raw.split(os.pathsep):
            entry = entry.strip().strip('"')
            if not entry:
                continue
            key = entry.lower().rstrip("\\")
            if key in seen:
                continue
            seen.add(key)
            low = key
            protected = any(
                low == p or low.startswith(p + "\\") for p in _PROTECTED_PREFIXES
            )
            if protected:
                continue
            try:
                if os.path.isdir(entry) and self._dir_writable(entry):
                    dirs.append(entry)
            except Exception:
                continue
        return dirs

    @staticmethod
    def _dir_writable(path: str) -> bool:
        """Accurately test directory writability by a self-cleaning probe write.

        ``os.access(path, os.W_OK)`` is unreliable on Windows (ACLs vs. the
        read-only attribute), so we attempt to create and immediately delete a
        uniquely named probe file. Any error means "not writable". The probe
        file is always removed on success.
        """
        probe = os.path.join(path, f".redkit_wtest_{uuid.uuid4().hex}.tmp")
        try:
            with open(probe, "w", encoding="ascii") as fh:
                fh.write("redkit-writable-probe")
        except OSError:
            return False
        except Exception:
            return False
        finally:
            try:
                if os.path.exists(probe):
                    os.remove(probe)
            except OSError:
                pass
        return True

    # ------------------------------------------------------------------
    # Artifact writer
    # ------------------------------------------------------------------
    @staticmethod
    def _write_artifact(artifact, sections: List[Tuple[str, str]], ctx) -> Optional[object]:
        lines: List[str] = []
        lines.append("=" * 72)
        lines.append("redkit postex.windows_enum - raw enumeration output")
        lines.append("=" * 72)
        for title, output in sections:
            lines.append("")
            lines.append("#" * 72)
            lines.append(f"# {title}")
            lines.append("#" * 72)
            lines.append(output.rstrip("\n") if output else "(no output)")
        blob = "\n".join(lines) + "\n"
        try:
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(blob, encoding="utf-8", errors="replace")
            return artifact
        except OSError as exc:
            try:
                ctx.console.warn(f"could not write artifact: {exc}")
            except Exception:
                pass
            return None


# ---------------------------------------------------------------------------
# Offline enumeration checklist (written when not running live on Windows).
# Plain cmd.exe / reg / wmic commands an operator can paste on a target host.
# ---------------------------------------------------------------------------
_CHECKLIST_SCRIPT = r"""@echo off
REM ===================================================================
REM  redkit - Windows local privilege-escalation enumeration checklist
REM  Offline guidance. Run these on the TARGET Windows host (cmd.exe).
REM  All commands are read-only enumeration. Review output carefully.
REM ===================================================================

echo [*] Current identity, groups and privileges
whoami /all
whoami /priv
REM  ^ Look for SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
REM    (potato -> SYSTEM), SeDebugPrivilege, SeBackup/SeRestore, etc.

echo [*] OS name, build and installed hotfixes
systeminfo
REM  ^ Note "OS Name", "OS Version" and the Hotfix(s) list; compare against
REM    a kernel-exploit suggester OFFLINE (no network).

echo [*] Unquoted service paths (space in path, no quotes)
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\"
REM  wmic missing (newer Windows)? Use sc instead:
REM    for /f "tokens=2 delims=:" %%s in ('sc query state^= all ^| findstr SERVICE_NAME') do @sc qc %%s | findstr BINARY_PATH_NAME
REM  ^ Flag any BINARY_PATH_NAME with a space that is NOT wrapped in quotes.

echo [*] AlwaysInstallElevated (needs BOTH keys = 0x1 to be exploitable)
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
REM  ^ If both are 0x1: any MSI installs as SYSTEM (msfvenom -f msi + msiexec).

echo [*] Autologon credentials stored in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
REM  ^ Look for DefaultUserName / DefaultPassword / AutoAdminLogon.

echo [*] Stored credentials (Credential Manager)
cmdkey /list
REM  ^ Saved targets may be reusable: runas /savecred /user:USER "cmd".

echo [*] Scheduled tasks (review author, run-as user, and action path)
schtasks /query /fo LIST /v
REM  ^ Flag tasks running as SYSTEM whose action path is user-writable.

echo [*] PATH directories (test each for user write access = DLL/binary hijack)
echo %PATH%
REM  ^ For each PATH dir, test writability, e.g.:
REM      echo test > "C:\Some\PathDir\redkit_wtest.tmp" && del "C:\Some\PathDir\redkit_wtest.tmp"

echo [*] Additional useful checks (manual):
echo     - Weak service permissions:      accesschk.exe -uwcqv "Users" *  (Sysinternals)
echo     - Unquoted + writable dir combo:  correlate the two lists above
echo     - Startup / Run keys:             reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
echo     - Installed software (DLL hijack): wmic product get name,version
echo     - Saved WiFi keys:                netsh wlan show profiles

echo [*] Enumeration checklist complete.
"""
