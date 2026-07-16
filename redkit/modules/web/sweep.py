"""web.sweep - one-shot web attack-surface triage ("scan once, know what to hit").

Runs the redkit web arsenal against a target, funnels every finding into the
engagement, then prints a RANKED attack plan: each exploitable issue ordered by
exploitability, with the exact redkit command to press the attack.

Design constraints (redkit invariants): no AI, offline-capable, pure stdlib,
deterministic. This module is a pure ORCHESTRATOR - it does not send any traffic
itself; it invokes the other web modules (which use the shared HttpClient) and
ranks what they find. Everything it runs is bounded by max_targets/max_params.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from redkit.core import registry
from redkit.core.http import WEB_COMMON_OPTIONS
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Severity ranking used for the attack plan (higher = hit this first).
_SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Options that belong to the shared web layer; forwarded to every sub-module.
_WEB_OPT_NAMES = ("cookie", "header", "proxy", "timeout", "user_agent", "insecure")


@register
class WebSweep(Module):
    """Automated web recon + vuln sweep that outputs a ranked, actionable hit list."""

    name = "web.sweep"
    description = "One-shot web triage: sweep the whole arsenal and rank what you can hit"
    phase = "web"
    options = [
        Option("url", help="Target URL (base or a specific endpoint)", required=True),
        Option("active", default=True, help="Run active injection tests (else recon/misconfig only)"),
        Option("aggressive", default=False, help="Enable slow time-based checks (sqli time, cmdi)"),
        Option("crawl", default=True, help="Spider the target to discover more injection points"),
        Option("max_targets", default=15, help="Max injection-point URLs to test"),
        Option("max_params", default=12, help="Max discovered params attached per target URL"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, Any], ctx) -> Result:
        console = ctx.console
        url = str(opts["url"]).strip()
        if "://" not in url:
            url = "http://" + url
        parsed = urllib.parse.urlsplit(url)
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r}")
        host = parsed.hostname
        origin = f"{parsed.scheme}://{parsed.netloc}"

        active = bool(opts["active"])
        aggressive = bool(opts["aggressive"])
        do_crawl = bool(opts["crawl"])
        max_targets = max(1, int(opts["max_targets"]))
        max_params = max(0, int(opts["max_params"]))

        web_opts = {k: opts[k] for k in _WEB_OPT_NAMES if k in opts}
        cookie = str(opts.get("cookie", "") or "")

        console.banner("web.sweep", f"target={origin}  active={active}  aggressive={aggressive}")
        ctx.engagement.add_host(host)

        # Collected exploitable items: {finding, module, category, how}
        hits: List[Dict[str, Any]] = []

        def run_mod(name: str, extra: Dict[str, Any], how_fn) -> Optional[Result]:
            """Invoke a sub-module, attribute any new findings, build a how-to."""
            before = len(ctx.engagement.data["findings"])
            res = _call(ctx, name, extra, web_opts)
            for f in ctx.engagement.data["findings"][before:]:
                hits.append({"finding": f, "module": name, "how": how_fn(extra, f)})
            return res

        # -- 1. recon / passive fingerprint ------------------------------- #
        console.info("[phase] recon & fingerprint")
        run_mod("web.waf", {"url": origin}, lambda e, f: f"expect WAF: consider --dry-run first / evasion")
        run_mod("web.secrets", {"url": origin, "dump": aggressive},
                lambda e, f: _cmd("web.secrets", origin, cookie, extra="-o dump=true"))

        endpoints: List[str] = []
        params: List[str] = []
        get_targets: List[str] = []
        form_targets: List[Dict[str, Any]] = []
        if do_crawl:
            console.info("[phase] crawl")
            cres = run_mod("web.crawl", {"url": url}, lambda e, f: _cmd("web.crawl", url, cookie))
            if cres and cres.data:
                endpoints = list(cres.data.get("endpoints") or [])
                params = list(cres.data.get("params") or [])
                get_targets = list(cres.data.get("get_targets") or [])
                form_targets = list(cres.data.get("form_targets") or [])

        # -- 2. endpoint-level misconfig ---------------------------------- #
        console.info("[phase] endpoint checks (cors, graphql)")
        run_mod("web.cors", {"url": origin}, lambda e, f: _cmd("web.cors", origin, cookie))
        run_mod("web.graphql", {"url": url}, lambda e, f: _cmd("web.graphql", url, cookie))

        token = _extract_jwt(cookie)
        if token:
            console.info("[phase] jwt (token found in cookie)")
            run_mod("web.jwt", {"token": token, "action": "analyze"},
                    lambda e, f: f"redkit run web.jwt -o token=<jwt> -o action=brute")

        # -- 3. active injection testing ---------------------------------- #
        if active:
            targets = _collect_targets(origin, url, parsed, get_targets, form_targets,
                                       endpoints, params, max_targets, max_params)
            console.info(f"[phase] active injection on {len(targets)} target(s)")
            for t in targets:
                run_mod("web.sqli", {**t, "technique": "all" if aggressive else "error"},
                        lambda e, f: _cmd("web.sqli", e["url"], cookie, extra="-o technique=all"))
                run_mod("web.xss", dict(t), lambda e, f: _cmd("web.xss", e["url"], cookie))
                run_mod("web.ssti", dict(t), lambda e, f: _cmd("web.ssti", e["url"], cookie))
                run_mod("web.lfi", dict(t), lambda e, f: _cmd("web.lfi", e["url"], cookie))
                run_mod("web.redirect", dict(t), lambda e, f: _cmd("web.redirect", e["url"], cookie))
                run_mod("web.ssrf", dict(t), lambda e, f: _cmd("web.ssrf", e["url"], cookie))
                if aggressive:
                    run_mod("web.cmdi", dict(t), lambda e, f: _cmd("web.cmdi", e["url"], cookie))
        else:
            console.info("active testing disabled (-o active=false); recon/misconfig only")

        # -- 4. rank & report --------------------------------------------- #
        ranked = _rank(hits)
        artifact = _write_plan(ctx, host, origin, ranked)
        _print_plan(console, ranked)

        n_crit = sum(1 for h in ranked if h["finding"]["severity"] == "critical")
        n_high = sum(1 for h in ranked if h["finding"]["severity"] == "high")
        summary = (
            f"{len(ranked)} exploitable issue(s) on {host}: "
            f"{n_crit} critical, {n_high} high"
        )
        ctx.engagement.add_note(f"web.sweep: {summary}")
        return Result(ok=True, summary=summary,
                      data={"host": host, "hits": len(ranked), "critical": n_crit, "high": n_high},
                      artifacts=[artifact] if artifact else [])


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _call(ctx, name: str, extra: Dict[str, Any], web_opts: Dict[str, Any]) -> Optional[Result]:
    """Invoke a registered module, filtering options to what it declares."""
    cls = registry.get(name)
    if cls is None:
        ctx.console.debug(f"sweep: module {name} not available, skipping")
        return None
    allowed = set(cls.option_map().keys())
    merged: Dict[str, Any] = {k: v for k, v in web_opts.items() if k in allowed}
    for k, v in extra.items():
        if k in allowed:
            merged[k] = v
    try:
        resolved = cls.resolve_options(merged)
    except ValueError as exc:
        ctx.console.debug(f"sweep: {name} option error: {exc}")
        return None
    try:
        return cls().run(resolved, ctx)
    except Exception as exc:  # a sub-module crash must not abort the sweep
        ctx.console.debug(f"sweep: {name} raised: {exc}")
        return None


def _collect_targets(origin: str, base_url: str, parsed, get_targets: List[str],
                     form_targets: List[Dict[str, Any]], endpoints: List[str],
                     params: List[str], max_targets: int, max_params: int) -> List[Dict[str, Any]]:
    """Build bounded injection targets, each {url[, method, data]}.

    Prefers the real param-bearing GET URLs and forms the crawler actually saw.
    Falls back to attaching discovered params to discovered endpoints only when
    no concrete injection point was found.
    """
    targets: List[Dict[str, Any]] = []
    seen = set()

    def add(d: Dict[str, Any]) -> None:
        key = (d.get("url"), d.get("method", "GET"), d.get("data", ""))
        if not d.get("url") or key in seen:
            return
        seen.add(key)
        targets.append(d)

    # 1. operator's exact URL (keeps its real params)
    add({"url": base_url})

    # 2. real param-bearing GET URLs the crawler visited
    for gt in get_targets:
        add({"url": gt})

    # 3. forms -> concrete GET/POST targets
    for fm in form_targets:
        action = fm.get("action")
        method = str(fm.get("method") or "get").upper()
        inputs = [str(i) for i in (fm.get("inputs") or []) if i]
        if not action:
            continue
        if method == "POST":
            add({"url": action, "method": "POST", "data": "&".join(f"{i}=1" for i in inputs)})
        else:
            q = "&".join(f"{i}=1" for i in inputs)
            u = action + (("&" if urllib.parse.urlsplit(action).query else "?") + q if q else "")
            add({"url": u})

    # 4. fallback: nothing concrete found -> attach discovered params to endpoints
    if len(targets) <= 1 and params:
        plist = [p for p in params if p][:max_params]
        query = "&".join(f"{p}=1" for p in plist)
        paths = list(dict.fromkeys([parsed.path or "/"] + [e for e in endpoints if e]))
        for path in paths:
            u = origin + (path if path.startswith("/") else "/" + path)
            if query:
                u = u + ("&" if urllib.parse.urlsplit(u).query else "?") + query
            add({"url": u})

    return targets[:max_targets]


def _extract_jwt(cookie: str) -> Optional[str]:
    """Pull a JWT-looking value out of a cookie string, if present."""
    import re

    m = re.search(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", cookie or "")
    return m.group(0) if m else None


def _cmd(module: str, url: str, cookie: str, extra: str = "") -> str:
    """Build a copy-paste redkit command to press an attack."""
    parts = [f"redkit run {module}", f"-o url='{url}'"]
    if cookie:
        parts.append(f"-o cookie='{cookie}'")
    if extra:
        parts.append(extra)
    return " ".join(parts)


def _rank(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Dedupe and sort findings by exploitability (severity, then title)."""
    seen = set()
    unique = []
    for h in hits:
        f = h["finding"]
        key = (f.get("title"), f.get("host"), f.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(h)
    unique.sort(key=lambda h: (-_SEV_WEIGHT.get(h["finding"].get("severity", "info"), 0),
                               h["finding"].get("id", "")))
    return unique


def _print_plan(console, ranked: List[Dict[str, Any]]) -> None:
    console.raw("")
    console.banner("ATTACK PLAN - what you can hit", f"{len(ranked)} ranked issue(s)")
    if not ranked:
        console.info("no exploitable issues surfaced (target may be hardened, or try -o aggressive=true)")
        return
    rows = []
    for i, h in enumerate(ranked, 1):
        f = h["finding"]
        where = f.get("evidence") or f.get("host") or ""
        rows.append([i, f.get("severity", "").upper(), f.get("title", ""), _short(where, 42)])
    console.table(["#", "SEV", "VULN", "WHERE"], rows)
    console.raw("")
    console.raw("How to press each (top items):")
    for i, h in enumerate(ranked[:12], 1):
        console.raw(f"  {i}. [{h['finding'].get('severity','').upper()}] {h['finding'].get('title','')}")
        console.raw(f"       {h['how']}")


def _write_plan(ctx, host: str, origin: str, ranked: List[Dict[str, Any]]) -> Optional[str]:
    lines = [f"# Web attack plan: {host}", "", f"- Target: {origin}",
             f"- Exploitable issues: {len(ranked)}", ""]
    order = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for h in ranked:
        order.setdefault(h["finding"].get("severity", "info"), []).append(h)
    for sev in ("critical", "high", "medium", "low", "info"):
        items = order.get(sev) or []
        if not items:
            continue
        lines.append(f"## {sev.upper()} ({len(items)})")
        lines.append("")
        for h in items:
            f = h["finding"]
            lines.append(f"### {f.get('id','')} {f.get('title','')}")
            if f.get("host"):
                lines.append(f"- host: {f['host']}")
            if f.get("evidence"):
                lines.append(f"- where: `{f['evidence']}`")
            if f.get("description"):
                lines.append(f"- {f['description']}")
            lines.append(f"- **press it:** `{h['how']}`")
            lines.append("")
    try:
        path = ctx.artifact_path("attack_plan.md")
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)
    except OSError:
        return None


def _short(text: str, n: int) -> str:
    text = str(text)
    return text if len(text) <= n else text[: n - 3] + "..."
