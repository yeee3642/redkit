"""Linux local privilege-escalation enumeration.

A ``linpeas``-lite, pure-standard-library post-exploitation enumerator. When the
operator runs this *on* a Linux host it collects the usual local-privesc signal
(identity, ``sudo -l``, SUID/SGID binaries, world-writable directories, cron
jobs, kernel/OS version, listening sockets, capabilities, container hints, a
writable ``/etc/passwd`` check, and interesting environment variables), flags
notable results as engagement findings, and writes the full raw dump to an
artifact.

When it runs somewhere that is *not* Linux (a Windows or macOS operator box, or
when ``run_local`` is disabled) it still succeeds: instead of collecting it
writes a ready-to-run bash enumeration cheat-sheet to the artifact so the
operator can copy it onto the target.

Design invariants:

* **No AI/LLM, no network.** Everything is deterministic, rule-based, and local.
* **Pure stdlib.** External binaries (``find``, ``sudo``, ``ss`` ...) are used
  through ``ctx.runner`` only when present; every one has a pure-python or
  file-read fallback, and none is required at import time.
* **Cross-platform import.** OS-specific calls are guarded; importing this module
  never touches a Linux-only API.
* **Safe.** Read-only enumeration, bounded timeouts, no destructive action.
"""
from __future__ import annotations

import os
import platform
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register


# --------------------------------------------------------------------------- #
# Reference data (basenames only). Kept small and deterministic.
# --------------------------------------------------------------------------- #

# SUID/SGID binaries that legitimately ship setuid-root on mainstream distros.
# Presence of these is normal and should NOT be flagged.
_COMMON_SETUID = {
    "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn", "gpasswd",
    "newgrp", "ping", "ping6", "pkexec", "fusermount", "fusermount3",
    "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "chrome-sandbox", "snap-confine", "vmware-user-suid-wrapper", "Xorg.wrap",
    "sg", "expiry", "unix_chkpwd", "utempter", "ntfs-3g", "suexec",
    "pam_extrausers_chkpwd", "write", "wall", "bsd-write", "crontab", "at",
}

# GTFOBins-known binaries that hand you a shell / file read-write / privilege
# escalation when found setuid-root or with a dangerous capability. Flagged.
_GTFOBINS_SETUID = {
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ash",
    "aspell", "awk", "base32", "base64", "basenc", "bash", "bc", "busybox",
    "bzip2", "cat", "chmod", "chown", "chroot", "cmp", "column", "comm", "cp",
    "cpio", "cpulimit", "crash", "csh", "csplit", "cupsfilter", "curl", "cut",
    "dash", "date", "dd", "dialog", "diff", "dig", "dmsetup", "dosbox", "ed",
    "efax", "emacs", "env", "eqn", "expand", "expect", "file", "find", "flock",
    "fmt", "fold", "gawk", "gcore", "gdb", "gimp", "grep", "gtester", "gzip",
    "hd", "head", "hexdump", "highlight", "iconv", "install", "ionice", "ip",
    "ispell", "jjs", "join", "jq", "jrunscript", "ksh", "ld.so", "less", "logsave",
    "look", "lua", "make", "man", "mawk", "more", "mosquitto", "msgattrib",
    "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "mtr", "mv", "nano",
    "nawk", "nc", "ncftp", "nft", "nice", "nl", "nmap", "node", "nohup", "od",
    "openssl", "openvpn", "paste", "perl", "pexec", "pg", "php", "pico", "pr",
    "python", "python2", "python3", "readelf", "rlwrap", "rsync", "rtorrent",
    "rview", "rvim", "sed", "setarch", "shuf", "soelim", "socat", "sort",
    "sqlite3", "ss", "ssh-agent", "start-stop-daemon", "stdbuf", "strace",
    "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh",
    "tee", "tftp", "tic", "time", "timeout", "troff", "ul", "unexpand", "uniq",
    "unshare", "uudecode", "uuencode", "vi", "vim", "watch", "wc", "wget",
    "whiptail", "wish", "xargs", "xdotool", "xmodmap", "xxd", "xz", "yash",
    "zip", "zsh", "zsoelim",
}

# Linux capabilities that (alone) commonly enable privilege escalation.
_DANGEROUS_CAPS = (
    "cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override",
    "cap_dac_read_search", "cap_sys_ptrace", "cap_sys_module",
    "cap_dac_read_search", "cap_fowner", "cap_chown", "cap_sys_rawio",
)

# Directories whose being world-writable is expected (sticky-bit temp dirs).
_EXPECTED_WORLD_WRITABLE = {"/tmp", "/var/tmp", "/dev/shm", "/run/lock", "/run/shm"}

# Cap on lines we keep from potentially huge find outputs, to bound artifact size.
_MAX_LINES = 500

# The offline cheat-sheet written when we are not enumerating a live Linux host.
_CHEATSHEET = r"""#!/usr/bin/env bash
# redkit :: postex.linux_enum -- offline Linux privilege-escalation checklist
#
# This host is not a live Linux target (or run_local was disabled), so redkit
# could not collect locally. Copy this script onto the target and run it:
#     bash linux_enum.txt   (or: chmod +x linux_enum.txt && ./linux_enum.txt)
# It is read-only reconnaissance. Review before running in production.

set -u
line() { printf '\n===== %s =====\n' "$1"; }

line "IDENTITY";            id; whoami; groups
line "OS / KERNEL";         uname -a; cat /etc/os-release 2>/dev/null
line "SUDO RIGHTS";         sudo -n -l 2>&1 || echo '[!] sudo needs a password / not allowed'
line "SUID BINARIES";       find / -xdev -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
line "SGID BINARIES";       find / -xdev -perm -2000 -type f -exec ls -la {} \; 2>/dev/null
line "FILE CAPABILITIES";   getcap -r / 2>/dev/null
line "WORLD-WRITABLE DIRS";  find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
line "WORLD-WRITABLE FILES"; find / -xdev -type f -perm -0002 2>/dev/null | head -n 100
line "PASSWD/SHADOW PERMS";  ls -la /etc/passwd /etc/shadow 2>/dev/null
line "CRON: /etc/crontab";   cat /etc/crontab 2>/dev/null
line "CRON: /etc/cron.d";    ls -la /etc/cron.* 2>/dev/null; cat /etc/cron.d/* 2>/dev/null
line "USER CRONTABS";        ls -la /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
line "LISTENING SOCKETS";    (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null)
line "PROCESSES (root)";     ps -eo user,pid,cmd 2>/dev/null | grep -E '^root' | head -n 50
line "ENVIRONMENT";          env
line "PATH ENTRIES";         echo "$PATH" | tr ':' '\n'
line "CONTAINER HINTS";      ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|lxc|kube'
line "NFS no_root_squash";   cat /etc/exports 2>/dev/null
line "INTERESTING GROUPS";   id | grep -Eo 'docker|lxd|lxc|disk|adm|sudo|wheel|shadow'
line "PASSWORDS IN CONFIG";  grep -RiIl --include='*.conf' -e password /etc 2>/dev/null | head -n 40
line "SSH KEYS";             find / -xdev -name 'id_rsa' -o -name 'authorized_keys' 2>/dev/null | head -n 40
line "KERNEL EXPLOIT HINT";  echo 'compare `uname -r` against public LPE PoCs (e.g. dirtypipe, pwnkit, OverlayFS)'
echo; echo '[*] enumeration complete -- review SUID/GTFOBins, sudo NOPASSWD, caps, writable cron.'
"""


@register
class LinuxEnum(Module):
    """Collect Linux local privilege-escalation signal (or emit offline guidance)."""

    name = "postex.linux_enum"
    description = "Linux local privilege-escalation enumeration (SUID, sudo, caps, cron, ...)"
    phase = "postex"
    options = [
        Option(
            "run_local",
            default=True,
            help="If on a Linux host, actually collect locally. If false, only "
            "write the offline bash cheat-sheet.",
        ),
        Option(
            "out",
            default="linux_enum.txt",
            help="Artifact filename for the raw enumeration dump / cheat-sheet.",
        ),
    ]
    references = [
        "https://gtfobins.github.io/",
        "https://github.com/carlospolop/PEASS-ng",
        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
    ]

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #
    def run(self, opts, ctx) -> Result:
        out_name = str(opts.get("out") or "linux_enum.txt").strip() or "linux_enum.txt"
        run_local = bool(opts.get("run_local"))
        artifact = ctx.artifact_path(out_name)

        is_linux = os.name == "posix" and platform.system() == "Linux"

        if run_local and is_linux:
            return self._enumerate_local(artifact, ctx)
        return self._write_guidance(artifact, ctx, run_local, is_linux)

    # ------------------------------------------------------------------ #
    # Offline / non-Linux path: write a copy-paste enumeration script
    # ------------------------------------------------------------------ #
    def _write_guidance(self, artifact: Path, ctx, run_local: bool, is_linux: bool) -> Result:
        """Not a live Linux target: emit a self-contained bash checklist."""
        try:
            artifact.write_text(_CHEATSHEET, encoding="utf-8")
        except OSError as exc:
            return Result(
                ok=False,
                summary=f"could not write cheat-sheet to {artifact}: {exc}",
                data={"mode": "guidance", "error": str(exc)},
            )

        host_os = platform.system() or os.name
        if not is_linux:
            reason = f"operator host is {host_os or 'non-Linux'}, not a live Linux target"
        else:
            reason = "run_local=false, so local collection was skipped"

        ctx.console.info(
            f"linux_enum: {reason}; wrote offline enumeration cheat-sheet to {artifact}"
        )
        ctx.engagement.add_note(
            f"postex.linux_enum produced offline guidance ({reason}); "
            f"cheat-sheet at {artifact}"
        )
        return Result(
            ok=True,
            summary=(
                f"Offline guidance: {reason}. Wrote a ready-to-run bash "
                f"privilege-escalation checklist to {artifact.name} to run on the target."
            ),
            data={
                "mode": "guidance",
                "reason": reason,
                "host_os": host_os,
                "artifact": str(artifact),
            },
            artifacts=[str(artifact)],
        )

    # ------------------------------------------------------------------ #
    # Live Linux path: collect, flag, persist
    # ------------------------------------------------------------------ #
    def _enumerate_local(self, artifact: Path, ctx) -> Result:
        """Run the full local enumeration against the current Linux host."""
        hostname = _safe_hostname()
        sections: List[Tuple[str, str]] = []
        findings: List[Dict[str, str]] = []
        data: Dict[str, object] = {"mode": "local", "host": hostname}

        ctx.console.info(f"linux_enum: enumerating local host '{hostname}'")

        # Each collector is isolated so one failure never aborts the sweep.
        collectors = (
            ("identity", self._collect_identity),
            ("os_kernel", self._collect_os_kernel),
            ("sudo", self._collect_sudo),
            ("suid_sgid", self._collect_suid_sgid),
            ("capabilities", self._collect_capabilities),
            ("sensitive_files", self._collect_sensitive_files),
            ("world_writable", self._collect_world_writable),
            ("cron", self._collect_cron),
            ("sockets", self._collect_sockets),
            ("environment", self._collect_environment),
            ("containers", self._collect_containers),
        )
        for key, fn in collectors:
            try:
                title, body, found, summary = fn(ctx)
            except Exception as exc:  # a broken collector must not kill the run
                ctx.console.debug(f"linux_enum: collector '{key}' failed: {exc!r}")
                sections.append((key.upper(), f"[collector error: {exc}]"))
                continue
            sections.append((title, body))
            if summary is not None:
                data[key] = summary
            for f in found:
                findings.append(f)

        # Persist findings into the engagement so report/others can see them.
        for f in findings:
            ctx.engagement.add_finding(
                title=f["title"],
                severity=f.get("severity", "info"),
                host=hostname,
                description=f.get("description", ""),
                evidence=f.get("evidence"),
            )
            _echo_finding(ctx, f)

        raw = self._render_report(hostname, sections)
        try:
            artifact.write_text(raw, encoding="utf-8")
            artifacts = [str(artifact)]
        except OSError as exc:
            ctx.console.warn(f"linux_enum: could not write artifact: {exc}")
            artifacts = []

        sev_counts = _severity_counts(findings)
        data["findings"] = sev_counts
        data["finding_count"] = len(findings)

        ctx.engagement.add_note(
            f"postex.linux_enum on {hostname}: {len(findings)} finding(s) "
            f"({_fmt_counts(sev_counts)}); dump at {artifact}"
        )

        top = _top_severity(findings)
        summary = (
            f"Enumerated {hostname}: {len(findings)} finding(s)"
            + (f", highest severity {top}" if top else "")
            + f". Raw dump: {artifact.name}"
        )
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # ------------------------------------------------------------------ #
    # Collectors -- each returns (section_title, body_text, findings, summary)
    # ------------------------------------------------------------------ #
    def _collect_identity(self, ctx):
        lines: List[str] = []
        findings: List[Dict[str, str]] = []

        who = _run_text(ctx, ["whoami"]) or _py_whoami()
        idout = _run_text(ctx, ["id"]) or _py_id()
        groups = _run_text(ctx, ["groups"])
        lines.append(f"whoami: {who.strip()}")
        lines.append(f"id: {idout.strip()}")
        if groups:
            lines.append(f"groups: {groups.strip()}")

        uid = _safe_getuid()
        summary = {"user": who.strip(), "uid": uid, "id": idout.strip()}

        if uid == 0:
            findings.append({
                "title": "Session already running as root (uid 0)",
                "severity": "info",
                "description": "The current session is root; no escalation needed.",
                "evidence": idout.strip(),
            })

        # Membership in privileged groups is frequently a root-equivalent path.
        group_blob = (idout + " " + (groups or "")).lower()
        for grp, sev in (("docker", "high"), ("lxd", "high"), ("lxc", "high"),
                         ("disk", "high"), ("shadow", "high"), ("adm", "low"),
                         ("wheel", "low"), ("sudo", "low")):
            if _has_group(group_blob, grp):
                findings.append({
                    "title": f"Member of privileged group '{grp}'",
                    "severity": sev,
                    "description": f"Membership in '{grp}' is a well-known local "
                                   "privilege-escalation vector.",
                    "evidence": idout.strip(),
                })
        return "IDENTITY", "\n".join(lines), findings, summary

    def _collect_os_kernel(self, ctx):
        lines: List[str] = []
        uname = _run_text(ctx, ["uname", "-a"]) or _py_uname()
        lines.append(f"uname -a: {uname.strip()}")
        osrel = _read_file("/etc/os-release", limit=4000)
        if osrel:
            lines.append("--- /etc/os-release ---")
            lines.append(osrel.strip())
        kernel = ""
        try:
            kernel = platform.release()
        except Exception:
            kernel = ""
        summary = {"uname": uname.strip(), "kernel": kernel}
        # We deliberately do NOT claim a kernel exploit exists -- just record it.
        return "OS / KERNEL", "\n".join(lines), [], summary

    def _collect_sudo(self, ctx):
        findings: List[Dict[str, str]] = []
        if not ctx.runner.have("sudo"):
            return ("SUDO", "sudo binary not present in PATH.", [],
                    {"available": False})
        # -n = non-interactive: never blocks waiting for a password.
        res = ctx.runner.run(["sudo", "-n", "-l"], timeout=10)
        body = res.text.strip() or "(no output)"
        summary = {"available": True, "rc": res.returncode, "timed_out": res.timed_out}

        text = res.text
        if res.timed_out:
            body = "[sudo -l timed out]"
        elif "NOPASSWD" in text:
            findings.append({
                "title": "sudo NOPASSWD entry available",
                "severity": "high",
                "description": "The current user can run command(s) via sudo without "
                               "a password. Check GTFOBins for the allowed binaries.",
                "evidence": _clip(text, 1500),
            })
            summary["nopasswd"] = True
        elif res.ok and ("may run" in text or "(ALL" in text or "ALL :" in text):
            findings.append({
                "title": "sudo rights enumerated (password required)",
                "severity": "low",
                "description": "The user has sudo entries; a password is required. "
                               "Useful if the account password is known.",
                "evidence": _clip(text, 1500),
            })
            summary["has_rules"] = True
        return "SUDO RIGHTS (sudo -n -l)", body, findings, summary

    def _collect_suid_sgid(self, ctx):
        findings: List[Dict[str, str]] = []
        suid = _find_perm(ctx, "-4000")
        sgid = _find_perm(ctx, "-2000")

        lines: List[str] = ["--- SUID (-perm -4000) ---"]
        lines.extend(suid["paths"] or ["(none found / find unavailable)"])
        if suid["truncated"]:
            lines.append(f"... (truncated at {_MAX_LINES} entries)")
        if suid["timed_out"]:
            lines.append("[find timed out; results are partial]")
        lines.append("")
        lines.append("--- SGID (-perm -2000) ---")
        lines.extend(sgid["paths"] or ["(none found / find unavailable)"])
        if sgid["truncated"]:
            lines.append(f"... (truncated at {_MAX_LINES} entries)")

        interesting = _interesting_setuid(suid["paths"]) + _interesting_setuid(sgid["paths"])
        interesting = sorted(set(interesting))
        if interesting:
            findings.append({
                "title": f"{len(interesting)} exploitable SUID/SGID binaries (GTFOBins)",
                "severity": "medium",
                "description": "These setuid/setgid binaries have known GTFOBins "
                               "techniques to escalate privileges.",
                "evidence": ", ".join(interesting[:40]),
            })

        summary = {
            "suid_count": len(suid["paths"]),
            "sgid_count": len(sgid["paths"]),
            "interesting": interesting,
            "available": suid["available"] or sgid["available"],
        }
        return "SUID / SGID BINARIES", "\n".join(lines), findings, summary

    def _collect_capabilities(self, ctx):
        findings: List[Dict[str, str]] = []
        if not ctx.runner.have("getcap"):
            return ("FILE CAPABILITIES", "getcap not present; install libcap "
                    "(package 'libcap2-bin') to enumerate file capabilities.",
                    [], {"available": False})
        res = ctx.runner.run(["getcap", "-r", "/"], timeout=45)
        body = res.text.strip() or "(no file capabilities found)"
        if res.timed_out:
            body += "\n[getcap timed out; partial results]"
        dangerous = []
        for ln in res.stdout.splitlines():
            low = ln.lower()
            if any(cap in low for cap in _DANGEROUS_CAPS):
                dangerous.append(ln.strip())
        if dangerous:
            findings.append({
                "title": f"{len(dangerous)} binaries with dangerous capabilities",
                "severity": "high",
                "description": "File capabilities such as cap_setuid / cap_sys_admin "
                               "can be leveraged for privilege escalation.",
                "evidence": _clip("\n".join(dangerous), 1500),
            })
        summary = {"available": True, "dangerous": dangerous}
        return "FILE CAPABILITIES", body, findings, summary

    def _collect_sensitive_files(self, ctx):
        findings: List[Dict[str, str]] = []
        lines: List[str] = []
        summary: Dict[str, object] = {}

        passwd_w = _writable("/etc/passwd")
        shadow_r = _readable("/etc/shadow")
        sudoers_w = _writable("/etc/sudoers")
        lines.append(f"/etc/passwd writable: {passwd_w}")
        lines.append(f"/etc/shadow readable: {shadow_r}")
        lines.append(f"/etc/sudoers writable: {sudoers_w}")
        lines.append(_ls_la("/etc/passwd"))
        lines.append(_ls_la("/etc/shadow"))
        summary.update({"passwd_writable": passwd_w, "shadow_readable": shadow_r,
                        "sudoers_writable": sudoers_w})

        if passwd_w:
            findings.append({
                "title": "/etc/passwd is writable",
                "severity": "critical",
                "description": "A writable /etc/passwd allows adding a root user "
                               "(e.g. an entry with a known password hash and uid 0).",
                "evidence": _ls_la("/etc/passwd"),
            })
        if shadow_r:
            findings.append({
                "title": "/etc/shadow is readable",
                "severity": "critical",
                "description": "Readable /etc/shadow exposes password hashes for "
                               "offline cracking.",
                "evidence": _ls_la("/etc/shadow"),
            })
        if sudoers_w:
            findings.append({
                "title": "/etc/sudoers is writable",
                "severity": "critical",
                "description": "A writable sudoers file grants trivial root access.",
                "evidence": _ls_la("/etc/sudoers"),
            })

        # NFS root-squash misconfig is a classic escalation from the client side.
        exports = _read_file("/etc/exports", limit=4000)
        if exports:
            lines.append("--- /etc/exports ---")
            lines.append(exports.strip())
            if "no_root_squash" in exports:
                findings.append({
                    "title": "NFS export with no_root_squash",
                    "severity": "high",
                    "description": "no_root_squash lets a client mount the share and "
                                   "create setuid-root files.",
                    "evidence": _clip(exports, 1000),
                })
        return "SENSITIVE FILE PERMISSIONS", "\n".join(lines), findings, summary

    def _collect_world_writable(self, ctx):
        findings: List[Dict[str, str]] = []
        # Non-sticky world-writable directories are the notable case.
        res = _find_world_writable_dirs(ctx)
        paths = res["paths"]
        notable = [p for p in paths if p not in _EXPECTED_WORLD_WRITABLE]

        lines: List[str] = ["--- world-writable dirs (no sticky bit) ---"]
        lines.extend(paths or ["(none found / find unavailable)"])
        if res["truncated"]:
            lines.append(f"... (truncated at {_MAX_LINES} entries)")
        if res["timed_out"]:
            lines.append("[find timed out; partial results]")

        if notable:
            findings.append({
                "title": f"{len(notable)} world-writable directories without sticky bit",
                "severity": "low",
                "description": "World-writable directories missing the sticky bit can "
                               "allow file tampering / planting.",
                "evidence": _clip("\n".join(notable), 1200),
            })
        summary = {"count": len(paths), "notable": notable[:50],
                   "available": res["available"]}
        return "WORLD-WRITABLE DIRECTORIES", "\n".join(lines), findings, summary

    def _collect_cron(self, ctx):
        findings: List[Dict[str, str]] = []
        lines: List[str] = []
        writable_jobs: List[str] = []

        targets: List[str] = ["/etc/crontab"]
        for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                  "/etc/cron.weekly", "/etc/cron.monthly"):
            try:
                if os.path.isdir(d):
                    for entry in sorted(os.listdir(d)):
                        targets.append(os.path.join(d, entry))
            except OSError:
                continue

        for path in targets:
            content = _read_file(path, limit=4000)
            if content is None:
                continue
            lines.append(f"--- {path} ---")
            lines.append(content.rstrip() or "(empty)")
            if _writable(path):
                writable_jobs.append(path)

        if not lines:
            lines.append("(no readable cron files)")

        if writable_jobs:
            findings.append({
                "title": f"{len(writable_jobs)} writable cron file(s)",
                "severity": "high",
                "description": "A writable cron job runs attacker-controlled commands, "
                               "typically as root.",
                "evidence": "\n".join(writable_jobs),
            })
        summary = {"files": len([l for l in lines if l.startswith('--- ')]),
                   "writable": writable_jobs}
        return "CRON JOBS", "\n".join(lines), findings, summary

    def _collect_sockets(self, ctx):
        if ctx.runner.have("ss"):
            res = ctx.runner.run(["ss", "-tulpn"], timeout=15)
            tool = "ss -tulpn"
        elif ctx.runner.have("netstat"):
            res = ctx.runner.run(["netstat", "-tulpn"], timeout=15)
            tool = "netstat -tulpn"
        else:
            body = _read_proc_listeners()
            return "LISTENING SOCKETS", body, [], {"tool": "/proc/net"}
        body = res.text.strip() or "(no output)"
        if res.timed_out:
            body += "\n[timed out]"
        return f"LISTENING SOCKETS ({tool})", body, [], {"tool": tool}

    def _collect_environment(self, ctx):
        findings: List[Dict[str, str]] = []
        lines: List[str] = []
        interesting_keys = (
            "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "SHELL",
            "HOME", "USER", "SUDO_USER", "SUDO_COMMAND", "HISTFILE",
            "MAIL", "EDITOR", "PS1",
        )
        for k in interesting_keys:
            v = os.environ.get(k)
            if v is not None:
                lines.append(f"{k}={v}")

        if os.environ.get("LD_PRELOAD"):
            findings.append({
                "title": "LD_PRELOAD is set in the environment",
                "severity": "low",
                "description": "A preserved LD_PRELOAD across privilege boundaries "
                               "can enable code injection.",
                "evidence": f"LD_PRELOAD={os.environ.get('LD_PRELOAD')}",
            })

        # Writable directories on PATH -> binary-planting risk.
        path_dirs = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
        writable_path = [p for p in path_dirs if _writable(p)]
        rel_path = [p for p in path_dirs if p in (".", "") or not os.path.isabs(p)]
        if writable_path:
            findings.append({
                "title": f"{len(writable_path)} writable directory(ies) on PATH",
                "severity": "medium",
                "description": "A writable PATH directory allows planting a malicious "
                               "binary that a higher-privileged process may execute.",
                "evidence": os.pathsep.join(writable_path),
            })
        if rel_path:
            findings.append({
                "title": "Relative or empty entry on PATH",
                "severity": "low",
                "description": "Relative PATH entries invite current-directory binary "
                               "hijacking.",
                "evidence": os.pathsep.join(rel_path),
            })
        summary = {"writable_path": writable_path, "relative_path": rel_path}
        return "ENVIRONMENT", "\n".join(lines) or "(nothing interesting)", findings, summary

    def _collect_containers(self, ctx):
        findings: List[Dict[str, str]] = []
        lines: List[str] = []
        in_container = False
        kind = None

        if os.path.exists("/.dockerenv"):
            in_container = True
            kind = "docker"
            lines.append("/.dockerenv present -> inside a Docker container")

        cgroup = _read_file("/proc/1/cgroup", limit=4000) or ""
        for marker, label in (("docker", "docker"), ("lxc", "lxc"),
                              ("kubepods", "kubernetes"), ("containerd", "containerd")):
            if marker in cgroup:
                in_container = True
                kind = kind or label
                lines.append(f"/proc/1/cgroup references '{marker}' -> {label}")

        if not in_container:
            lines.append("No container indicators found (looks like a bare host/VM).")
        else:
            findings.append({
                "title": f"Running inside a container ({kind})",
                "severity": "info",
                "description": "Enumerate container escape paths: mounted docker.sock, "
                               "privileged flag, host mounts, capabilities.",
                "evidence": "\n".join(lines),
            })
            # A mounted docker socket is a direct host-takeover primitive.
            if os.path.exists("/var/run/docker.sock") or os.path.exists("/run/docker.sock"):
                findings.append({
                    "title": "Docker socket accessible inside container",
                    "severity": "high",
                    "description": "A reachable docker.sock lets you start a privileged "
                                   "container mounting the host filesystem -> host root.",
                    "evidence": "docker.sock present",
                })
        summary = {"in_container": in_container, "kind": kind}
        return "CONTAINER / VIRTUALISATION HINTS", "\n".join(lines), findings, summary

    # ------------------------------------------------------------------ #
    # Report rendering
    # ------------------------------------------------------------------ #
    @staticmethod
    def _render_report(hostname: str, sections: List[Tuple[str, str]]) -> str:
        import datetime

        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        out: List[str] = [
            "=" * 72,
            "redkit :: postex.linux_enum -- local privilege-escalation enumeration",
            f"host: {hostname}",
            f"generated: {stamp}",
            "=" * 72,
        ]
        for title, body in sections:
            out.append("")
            out.append(f"===== {title} =====")
            out.append(body if body else "(no data)")
        out.append("")
        out.append("=" * 72)
        out.append("End of report. Review SUID/GTFOBins, sudo NOPASSWD, capabilities,")
        out.append("writable cron/passwd/sudoers, container escape and kernel version.")
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# Module-level helpers (all pure-stdlib, all failure-tolerant)
# --------------------------------------------------------------------------- #

def _run_text(ctx, argv: List[str], timeout: float = 15) -> str:
    """Run a command via the runner if the binary exists; return combined text."""
    tool = argv[0]
    try:
        if not ctx.runner.have(tool):
            return ""
        res = ctx.runner.run(argv, timeout=timeout)
        return res.text
    except Exception:
        return ""


def _find_perm(ctx, perm: str) -> Dict[str, object]:
    """`find / -xdev -perm <perm> -type f`, bounded and truncated."""
    result: Dict[str, object] = {"paths": [], "truncated": False,
                                 "timed_out": False, "available": False}
    if not ctx.runner.have("find"):
        return result
    result["available"] = True
    try:
        res = ctx.runner.run(
            ["find", "/", "-xdev", "-perm", perm, "-type", "f"], timeout=60
        )
    except Exception:
        return result
    result["timed_out"] = bool(res.timed_out)
    paths = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    if len(paths) > _MAX_LINES:
        result["truncated"] = True
        paths = paths[:_MAX_LINES]
    result["paths"] = paths
    return result


def _find_world_writable_dirs(ctx) -> Dict[str, object]:
    """World-writable directories without the sticky bit."""
    result: Dict[str, object] = {"paths": [], "truncated": False,
                                 "timed_out": False, "available": False}
    if not ctx.runner.have("find"):
        return result
    result["available"] = True
    try:
        res = ctx.runner.run(
            ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000"],
            timeout=60,
        )
    except Exception:
        return result
    result["timed_out"] = bool(res.timed_out)
    paths = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    if len(paths) > _MAX_LINES:
        result["truncated"] = True
        paths = paths[:_MAX_LINES]
    result["paths"] = paths
    return result


def _interesting_setuid(paths: List[str]) -> List[str]:
    """Return the subset of paths whose basename is a GTFOBins escalation binary."""
    hits: List[str] = []
    for p in paths:
        base = os.path.basename(p.split()[0]) if p else ""
        if not base:
            continue
        if base in _COMMON_SETUID:
            continue
        if base in _GTFOBINS_SETUID:
            hits.append(p)
    return hits


def _read_proc_listeners() -> str:
    """Fallback listening-socket view parsed from /proc/net without any binary."""
    out: List[str] = []
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")):
        raw = _read_file(path, limit=200000)
        if not raw:
            continue
        listen_state = "0A"  # TCP LISTEN; for UDP we just list bound sockets
        for line in raw.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 4:
                continue
            local = cols[1]
            state = cols[3]
            if proto.startswith("tcp") and state != listen_state:
                continue
            addr = _decode_proc_addr(local)
            if addr:
                out.append(f"{proto:5} LISTEN {addr}")
    return "\n".join(out) if out else "(no listeners parsed from /proc/net)"


def _decode_proc_addr(hexaddr: str) -> Optional[str]:
    """Decode a /proc/net 'HEXIP:HEXPORT' token to 'ip:port' (best effort)."""
    try:
        ip_hex, port_hex = hexaddr.split(":")
        port = int(port_hex, 16)
        if len(ip_hex) == 8:  # IPv4, little-endian
            b = bytes.fromhex(ip_hex)
            ip = ".".join(str(x) for x in reversed(b))
        else:  # IPv6 or unknown -> just show the hex compactly
            ip = f"[{ip_hex}]"
        return f"{ip}:{port}"
    except Exception:
        return None


def _read_file(path: str, limit: int = 4000) -> Optional[str]:
    """Read a text file safely; returns None if it cannot be read."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except (OSError, ValueError):
        return None


def _writable(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False


def _readable(path: str) -> bool:
    try:
        return os.access(path, os.R_OK)
    except Exception:
        return False


def _ls_la(path: str) -> str:
    """A stdlib approximation of `ls -la` for a single path."""
    try:
        st = os.stat(path)
    except OSError:
        return f"(cannot stat {path})"
    import stat as _stat

    mode = _stat.filemode(st.st_mode)
    owner = _lookup_user(st.st_uid)
    group = _lookup_group(st.st_gid)
    return f"{mode} {owner}:{group} {st.st_size:>8} {path}"


def _lookup_user(uid: int) -> str:
    try:
        import pwd  # Unix-only; guarded

        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _lookup_group(gid: int) -> str:
    try:
        import grp  # Unix-only; guarded

        return grp.getgrgid(gid).gr_name
    except Exception:
        return str(gid)


def _safe_getuid() -> int:
    try:
        return os.getuid()  # type: ignore[attr-defined]
    except Exception:
        return -1


def _safe_hostname() -> str:
    try:
        return socket.gethostname() or "localhost"
    except Exception:
        return "localhost"


def _py_whoami() -> str:
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return _lookup_user(_safe_getuid())


def _py_id() -> str:
    uid = _safe_getuid()
    try:
        gid = os.getgid()  # type: ignore[attr-defined]
    except Exception:
        gid = -1
    user = _lookup_user(uid)
    group = _lookup_group(gid)
    try:
        groups = ",".join(str(g) for g in os.getgroups())  # type: ignore[attr-defined]
    except Exception:
        groups = ""
    base = f"uid={uid}({user}) gid={gid}({group})"
    return base + (f" groups={groups}" if groups else "")


def _py_uname() -> str:
    try:
        u = platform.uname()
        return f"{u.system} {u.node} {u.release} {u.version} {u.machine}"
    except Exception:
        return "unknown"


def _has_group(blob: str, group: str) -> bool:
    """Whether a group name appears as a token in an id/groups blob."""
    import re

    return re.search(rf"(^|[\s,(]){re.escape(group)}([\s,)]|$)", blob) is not None


def _clip(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + " ...[truncated]"


def _severity_counts(findings: List[Dict[str, str]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _fmt_counts(counts: Dict[str, int]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    parts = [f"{counts[s]} {s}" for s in order if counts.get(s)]
    return ", ".join(parts) if parts else "none"


def _top_severity(findings: List[Dict[str, str]]) -> Optional[str]:
    order = ["critical", "high", "medium", "low", "info"]
    present = {f.get("severity", "info") for f in findings}
    for s in order:
        if s in present:
            return s
    return None


def _echo_finding(ctx, f: Dict[str, str]) -> None:
    sev = f.get("severity", "info")
    msg = f"[{sev}] {f['title']}"
    if sev in ("critical", "high"):
        ctx.console.bad(msg)
    elif sev == "medium":
        ctx.console.warn(msg)
    else:
        ctx.console.info(msg)
