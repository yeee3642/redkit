"""Engagement reporting module.

Renders the shared :class:`~redkit.core.engagement.Engagement` state into a
human-readable Markdown report or a machine-readable JSON dump. This module is
the terminal step of most workflows: every other module persists its findings
into ``ctx.engagement`` and this one collates them.

Everything here is pure standard library and fully deterministic - the same
engagement state always produces byte-for-byte identical section ordering. No
network calls, no external tools, no AI. Runs identically on Windows and Linux.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Severity ranking: higher rank sorts first (critical at the top). Unknown
# severities are pushed below everything known but still rendered.
_SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK: Dict[str, int] = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
_UNKNOWN_RANK = len(_SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# small formatting helpers (module-level so they stay pure + testable)
# ---------------------------------------------------------------------------
def _cell(value: Any) -> str:
    """Escape a value for safe inclusion in a Markdown table cell."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("|", "\\|")
    return text.strip()


def _md_table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    """Return the lines of a GitHub-flavoured Markdown table."""
    out = ["| " + " | ".join(_cell(h) for h in headers) + " |"]
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        out.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return out


def _fence(text: str) -> str:
    """Wrap ``text`` in a fenced code block, widening the fence if needed."""
    text = "" if text is None else str(text).rstrip("\n")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def _host_sort_key(ip: str) -> Tuple[int, Tuple[int, ...], str]:
    """Sort IPv4 addresses numerically, other identifiers lexicographically."""
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return (0, tuple(int(p) for p in parts), ip)
        except ValueError:
            pass
    return (1, (), ip)


def _finding_sort_key(finding: Dict[str, Any]) -> Tuple[int, str]:
    """Order findings by descending severity, then by stable id."""
    sev = str(finding.get("severity") or "info").lower()
    rank = _SEVERITY_RANK.get(sev, _UNKNOWN_RANK)
    return (rank, str(finding.get("id") or ""))


def _fmt_ts(epoch: Any) -> str:
    """Format an epoch integer as a UTC timestamp, tolerating junk input."""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(int(epoch)))
    except (TypeError, ValueError, OSError):
        return str(epoch)


@register
class ReportMarkdown(Module):
    """Collate engagement state into a Markdown or JSON report."""

    name = "report.markdown"
    description = "generate a Markdown or JSON engagement report from collected state"
    phase = "report"
    options = [
        Option(
            "format",
            help="output format: markdown (alias md) or json",
            default="markdown",
            choices=["markdown", "md", "json"],
        ),
        Option(
            "out",
            help="output filename inside the workdir (default report.md / report.json)",
            default="",
        ),
    ]
    requires_tools: List[str] = []
    references: List[str] = [
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]

    # -- entry point -------------------------------------------------------
    def run(self, opts: Dict[str, Any], ctx: "Context") -> Result:  # noqa: F821
        data = dict(getattr(ctx.engagement, "data", {}) or {})
        fmt = str(opts.get("format") or "markdown").lower()
        as_json = fmt == "json"

        out_name = str(opts.get("out") or "").strip()
        if not out_name:
            out_name = "report.json" if as_json else "report.md"
        path = ctx.artifact_path(out_name)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return Result(ok=False, summary=f"cannot create report directory: {exc}")

        counts = self._counts(data)

        if as_json:
            body = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)
        else:
            body = self._render_markdown(data, counts)

        try:
            path.write_text(body + "\n", encoding="utf-8")
        except OSError as exc:
            return Result(ok=False, summary=f"cannot write report: {exc}")

        self._print_summary(ctx, data, counts, path, fmt)

        summary = (
            f"{'JSON' if as_json else 'Markdown'} report written to {path} "
            f"({counts['hosts']} hosts, {counts['services']} services, "
            f"{counts['findings']} findings, {counts['creds']} creds)"
        )
        return Result(
            ok=True,
            summary=summary,
            data={
                "format": "json" if as_json else "markdown",
                "path": str(path),
                "counts": counts,
            },
            artifacts=[str(path)],
        )

    # -- counting ----------------------------------------------------------
    @staticmethod
    def _counts(data: Dict[str, Any]) -> Dict[str, Any]:
        """Return JSON-serializable summary counts for the engagement."""
        hosts = data.get("hosts") or {}
        findings = data.get("findings") or []
        services = 0
        for host in hosts.values():
            services += len((host or {}).get("ports") or {})

        severity: Dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
        other = 0
        for finding in findings:
            sev = str((finding or {}).get("severity") or "info").lower()
            if sev in severity:
                severity[sev] += 1
            else:
                other += 1
        if other:
            severity["other"] = other

        return {
            "hosts": len(hosts),
            "services": services,
            "creds": len(data.get("creds") or []),
            "findings": len(findings),
            "loot": len(data.get("loot") or []),
            "notes": len(data.get("notes") or []),
            "severity": severity,
        }

    # -- markdown rendering ------------------------------------------------
    def _render_markdown(self, data: Dict[str, Any], counts: Dict[str, Any]) -> str:
        name = str(data.get("name") or "engagement")
        lines: List[str] = []
        lines.append(f"# Engagement Report: {name}")
        lines.append("")
        created = data.get("created")
        if created is not None:
            lines.append(f"- Created: {_fmt_ts(created)}")
        lines.append(f"- Generated: {_fmt_ts(int(time.time()))}")
        lines.append("")

        self._section_summary(lines, counts)
        self._section_findings(lines, data.get("findings") or [])
        self._section_hosts(lines, data.get("hosts") or {})
        self._section_creds(lines, data.get("creds") or [])
        self._section_loot(lines, data.get("loot") or [])
        self._section_notes(lines, data.get("notes") or [])

        return "\n".join(lines).rstrip("\n")

    @staticmethod
    def _section_summary(lines: List[str], counts: Dict[str, Any]) -> None:
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Hosts: {counts['hosts']}")
        lines.append(f"- Open services: {counts['services']}")
        lines.append(f"- Credentials: {counts['creds']}")
        sev = counts.get("severity", {})
        breakdown = ", ".join(
            f"{s}: {sev.get(s, 0)}"
            for s in list(_SEVERITY_ORDER) + (["other"] if "other" in sev else [])
        )
        lines.append(f"- Findings: {counts['findings']} ({breakdown})")
        lines.append(f"- Loot: {counts['loot']}")
        lines.append(f"- Notes: {counts['notes']}")
        lines.append("")

    def _section_findings(self, lines: List[str], findings: List[Dict[str, Any]]) -> None:
        lines.append("## Findings")
        lines.append("")
        if not findings:
            lines.append("_No findings recorded._")
            lines.append("")
            return

        ordered = sorted(findings, key=_finding_sort_key)
        rows = [
            [
                f.get("id"),
                str(f.get("severity") or "info").upper(),
                f.get("host"),
                f.get("title"),
            ]
            for f in ordered
        ]
        lines.extend(_md_table(["ID", "Severity", "Host", "Title"], rows))
        lines.append("")

        for f in ordered:
            fid = f.get("id") or ""
            title = f.get("title") or "(untitled)"
            sev = str(f.get("severity") or "info").upper()
            lines.append(f"### {fid} - {title} ({sev})".strip())
            lines.append("")
            if f.get("host"):
                lines.append(f"- Host: {f.get('host')}")
            lines.append(f"- Severity: {sev}")
            lines.append("")
            description = str(f.get("description") or "").strip()
            if description:
                lines.append(description)
                lines.append("")
            evidence = f.get("evidence")
            if evidence:
                lines.append("Evidence:")
                lines.append("")
                lines.append(_fence(str(evidence)))
                lines.append("")

    def _section_hosts(self, lines: List[str], hosts: Dict[str, Any]) -> None:
        lines.append("## Hosts & Services")
        lines.append("")
        if not hosts:
            lines.append("_No hosts recorded._")
            lines.append("")
            return

        for ip in sorted(hosts.keys(), key=_host_sort_key):
            host = hosts.get(ip) or {}
            hostname = host.get("hostname")
            os_name = host.get("os")
            header = f"### {ip}"
            if hostname:
                header += f" ({hostname})"
            if os_name:
                header += f" - {os_name}"
            lines.append(header)
            lines.append("")

            ports = host.get("ports") or {}
            if not ports:
                lines.append("_No open ports recorded._")
                lines.append("")
                continue

            ordered_ports = sorted(
                ports.values(),
                key=lambda s: (int((s or {}).get("port") or 0), str((s or {}).get("proto") or "")),
            )
            rows = [
                [
                    svc.get("port"),
                    svc.get("proto"),
                    svc.get("service"),
                    svc.get("product"),
                    svc.get("banner"),
                ]
                for svc in ordered_ports
            ]
            lines.extend(_md_table(["Port", "Proto", "Service", "Product", "Banner"], rows))
            lines.append("")

    def _section_creds(self, lines: List[str], creds: List[Dict[str, Any]]) -> None:
        lines.append("## Credentials")
        lines.append("")
        if not creds:
            lines.append("_No credentials recorded._")
            lines.append("")
            return

        ordered = sorted(
            creds,
            key=lambda c: (
                str((c or {}).get("host") or ""),
                str((c or {}).get("service") or ""),
                str((c or {}).get("username") or ""),
                str((c or {}).get("password") or ""),
            ),
        )
        rows = [
            [
                c.get("service"),
                c.get("host"),
                c.get("username"),
                c.get("password"),
                c.get("hash"),
                c.get("source"),
            ]
            for c in ordered
        ]
        lines.extend(
            _md_table(["Service", "Host", "Username", "Password", "Hash", "Source"], rows)
        )
        lines.append("")

    def _section_loot(self, lines: List[str], loot: List[Dict[str, Any]]) -> None:
        lines.append("## Loot")
        lines.append("")
        if not loot:
            lines.append("_No loot recorded._")
            lines.append("")
            return

        ordered = sorted(
            loot,
            key=lambda item: (
                str((item or {}).get("host") or ""),
                str((item or {}).get("kind") or ""),
                str((item or {}).get("value") or ""),
            ),
        )
        rows = [
            [item.get("host"), item.get("kind"), item.get("value"), item.get("source")]
            for item in ordered
        ]
        lines.extend(_md_table(["Host", "Kind", "Value", "Source"], rows))
        lines.append("")

    def _section_notes(self, lines: List[str], notes: List[Dict[str, Any]]) -> None:
        lines.append("## Notes")
        lines.append("")
        if not notes:
            lines.append("_No notes recorded._")
            lines.append("")
            return

        # Notes are chronological (as appended); keep insertion order but stable.
        for note in notes:
            ts = note.get("ts")
            text = str(note.get("text") or "").strip()
            prefix = f"[{_fmt_ts(ts)}] " if ts is not None else ""
            first, *rest = text.splitlines() or [""]
            lines.append(f"- {prefix}{first}")
            for extra in rest:
                lines.append(f"  {extra}")
        lines.append("")

    # -- console summary ---------------------------------------------------
    @staticmethod
    def _print_summary(
        ctx: "Context",  # noqa: F821
        data: Dict[str, Any],
        counts: Dict[str, Any],
        path: Any,
        fmt: str,
    ) -> None:
        console = ctx.console
        name = str(data.get("name") or "engagement")
        console.info(f"engagement '{name}' -> {fmt} report")
        sev = counts.get("severity", {})
        try:
            console.table(
                ["metric", "count"],
                [
                    ["hosts", counts["hosts"]],
                    ["services", counts["services"]],
                    ["creds", counts["creds"]],
                    ["findings", counts["findings"]],
                    ["loot", counts["loot"]],
                    ["notes", counts["notes"]],
                    ["critical/high", sev.get("critical", 0) + sev.get("high", 0)],
                ],
            )
        except Exception:  # console formatting must never break report writing
            pass
        console.good(f"wrote {path}")
