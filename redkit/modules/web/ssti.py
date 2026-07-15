"""Server-Side Template Injection (SSTI) detection + engine fingerprint.

Injects a set of polyglot arithmetic markers -- one syntax family per popular
template engine -- into each candidate parameter and looks for the *evaluated*
product in the response while the *literal* payload text stays absent. Every
probe is paired with a control request that sends the bare arithmetic literal
(no template delimiters) so a coincidental reflection of digits can never be
mistaken for real server-side evaluation.

Once a syntax family is confirmed vulnerable, a small, bounded set of
engine-specific follow-up probes narrows the guess down (Jinja2 vs Twig,
FreeMarker vs Velocity, Ruby ERB vs a plain EL evaluator, Smarty comment
stripping, ...).

Design constraints (redkit invariants):
    * NO AI/LLM usage - every decision here is a deterministic string/regex rule.
    * Pure standard library (``urllib``, ``re``, ``uuid``, ``os``).
    * Imports and runs on both Windows and Linux (no OS-specific calls).
    * Offline: no downloads, no external services.
    * Bounded and safe: capped parameter count, capped request budget, GET by
      default, POST only when the operator explicitly selects it via
      ``method``/``data``. No destructive requests are ever sent.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# budgets (redkit invariant: bounded and safe)
# --------------------------------------------------------------------------- #
MAX_PARAMS = 15                # never test more than this many parameters
MAX_REQUESTS = 300             # hard cap on total HTTP requests for the whole run
MAX_FINGERPRINT_PER_PARAM = 8  # extra engine-id probes per confirmed-vulnerable param

# --------------------------------------------------------------------------- #
# polyglot arithmetic markers, one syntax family per popular template engine.
# Each template takes two ints (a, b); the second operand is randomized per
# parameter (see ``_rand_factor``) so the expected product is unique per probe
# (avoids coincidental matches against static page content, and lets an
# operator safely re-run).
# --------------------------------------------------------------------------- #
BASE_POLYGLOTS: List[Tuple[str, str, str]] = [
    ("double_brace", "{{%d*%d}}", "double-brace {{ }} (Jinja2 / Twig / Nunjucks)"),
    ("dollar_brace", "${%d*%d}", "dollar-brace ${ } (FreeMarker / Velocity / JSP-EL)"),
    ("hash_brace", "#{%d*%d}", "hash-brace #{ } (Ruby ERB/Slim / JSF-EL)"),
    ("erb_tag", "<%%= %d*%d %%>", "scriptlet <%= %> (ERB / JSP)"),
    ("single_brace", "{%d*%d}", "single-brace { } (Smarty)"),
    ("dollar_double_brace", "${{%d*%d}}", "dollar-double-brace ${{ }} (Jinja2 format-string)"),
    ("hash_brace_spaced", "#{ %d*%d }", "spaced hash-brace #{ } (Ruby Slim)"),
    ("razor_at", "@(%d*%d)", "Razor @( ) (ASP.NET)"),
]

_JINJA_FAMILIES = {"double_brace", "dollar_double_brace"}
_RUBY_FAMILIES = {"hash_brace", "hash_brace_spaced"}


def _rand_factor() -> int:
    """A 3-digit-ish random operand, fresh per probe (os.urandom based)."""
    return 700 + (os.urandom(1)[0] % 256)  # 700..955 -> product range ~4900-6685


def _contains_number(text: str, number: str) -> bool:
    """True if ``number`` appears in ``text`` as a standalone digit run.

    A plain substring check (``number in text``) would false-positive when the
    expected product's digits happen to occur *inside* a larger, unrelated
    number already on the page (an order id, timestamp, price, session token,
    ...). Anchoring on non-digit boundaries keeps the critical-severity SSTI
    verdict tied to an actual evaluated match.
    """
    return re.search(rf"(?<!\d){re.escape(number)}(?!\d)", text) is not None


def _replace_or_add(pairs: List[Tuple[str, str]], key: str, value: str) -> List[Tuple[str, str]]:
    """Return a copy of ``pairs`` with ``key``'s value replaced (or appended)."""
    out: List[Tuple[str, str]] = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            out.append((k, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((key, value))
    return out


@register
class Ssti(Module):
    """Detect Server-Side Template Injection and fingerprint the engine."""

    name = "web.ssti"
    description = "Server-Side Template Injection (SSTI) detection + engine fingerprint"
    phase = "web"
    options = [
        Option("url", help="target URL, e.g. https://host/page?name=x", required=True),
        Option("param", default="", help="comma list of parameter names to test (default: all discovered)"),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method to use for injections"),
        Option("data", default="", help="POST body, urlencoded 'a=1&b=2' (only used when method=POST)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/vulnerabilities/Server-Side_Template_Injection",
        "https://portswigger.net/research/server-side-template-injection",
        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console
        client = client_from_opts(opts)

        raw_url = str(opts.get("url", "") or "").strip()
        parsed = urlsplit(raw_url if "://" in raw_url else f"http://{raw_url}")
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts.get('url')!r}")
        host = parsed.hostname
        method = str(opts.get("method", "GET") or "GET").upper()
        data_raw = str(opts.get("data", "") or "")

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        body_pairs = parse_qsl(data_raw, keep_blank_values=True) if (method == "POST" and data_raw) else []

        ctx.engagement.add_host(host)

        sources = self._select_sources(opts, query_pairs, body_pairs, method)
        if not sources:
            summary = f"no parameters found to test on {raw_url}"
            console.warn(summary)
            return Result(ok=True, summary=summary, data={"findings": [], "params_tested": []})

        if len(sources) > MAX_PARAMS:
            console.warn(f"{len(sources)} parameters found; capping to {MAX_PARAMS} (budget)")
            sources = sources[:MAX_PARAMS]

        console.info(f"web.ssti: probing {len(sources)} parameter(s) on {raw_url} via {method}")

        budget = _Budget(MAX_REQUESTS)
        findings: List[Dict[str, object]] = []
        params_tested: List[str] = []

        for location, key, _orig_value in sources:
            if budget.exhausted:
                console.warn("request budget reached; stopping further probes")
                break
            params_tested.append(key)
            sender = self._make_sender(client, parsed, method, query_pairs, body_pairs, location, key, budget)
            hit = self._probe_param(sender, key, location, console, budget)
            if hit:
                findings.append(hit)
                self._record_finding(ctx, host, raw_url, hit)

        summary = (
            f"{raw_url}: {len(findings)} SSTI finding(s) across {len(params_tested)} parameter(s) tested"
            if findings
            else f"{raw_url}: no SSTI found across {len(params_tested)} parameter(s) tested"
        )
        if findings:
            console.bad(summary)
        else:
            console.good(summary)

        data = {
            "url": raw_url,
            "method": method,
            "params_tested": params_tested,
            "requests_sent": budget.used,
            "findings": findings,
        }
        return Result(ok=True, summary=summary, data=data)

    # --------------------------------------------------------- parameters -- #
    @staticmethod
    def _select_sources(
        opts: Dict[str, object],
        query_pairs: List[Tuple[str, str]],
        body_pairs: List[Tuple[str, str]],
        method: str,
    ) -> List[Tuple[str, str, str]]:
        """Return ``[(location, key, original_value)]`` candidates to test."""
        sources: List[Tuple[str, str, str]] = [("query", k, v) for k, v in query_pairs]
        sources += [("body", k, v) for k, v in body_pairs]

        requested = [p.strip() for p in str(opts.get("param", "") or "").split(",") if p.strip()]
        if not requested:
            return sources

        filtered = [s for s in sources if s[1] in requested]
        present = {s[1] for s in filtered}
        default_loc = "body" if (method == "POST" and body_pairs) else "query"
        for name in requested:
            if name not in present:
                filtered.append((default_loc, name, ""))
                present.add(name)
        return filtered

    # ------------------------------------------------------------ sender -- #
    def _make_sender(self, client, parsed, method, query_pairs, body_pairs, location, key, budget):
        """Build a ``value -> Response`` closure that injects at (location, key)
        while leaving every other parameter at its original value."""

        def send(value: str) -> Response:
            budget.spend()
            q = _replace_or_add(query_pairs, key, value) if location == "query" else query_pairs
            b = _replace_or_add(body_pairs, key, value) if location == "body" else body_pairs
            query_str = urlencode(q) if q else ""
            target_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query_str, ""))
            if method == "POST":
                return client.post(target_url, data=dict(b) if b else None)
            return client.get(target_url)

        return send

    # ------------------------------------------------------------- probe -- #
    def _probe_param(self, send, key, location, console, budget) -> Optional[Dict[str, object]]:
        """Run the polyglot battery against one parameter. Returns a finding
        dict on the first confirmed SSTI, or ``None``."""
        a = 7
        b = _rand_factor()
        expected = str(a * b)
        control_literal = f"{a}*{b}"

        control_resp = send(control_literal)
        if control_resp.status == 0:
            console.warn(f"param '{key}': control request unreachable ({control_resp.error}); skipping")
            return None
        control_text = control_resp.text

        hit_families: List[Dict[str, object]] = []
        for family_id, template, family_label in BASE_POLYGLOTS:
            if budget.exhausted:
                break
            payload = template % (a, b)
            resp = send(payload)
            if resp.status == 0:
                continue
            text = resp.text
            if _contains_number(text, expected) and payload not in text and not _contains_number(control_text, expected):
                hit_families.append(
                    {
                        "family_id": family_id,
                        "family": family_label,
                        "payload": payload,
                        "status": resp.status,
                        "length": resp.length,
                    }
                )

        if not hit_families:
            return None

        family_ids = {h["family_id"] for h in hit_families}
        engines = self._fingerprint_engine(send, family_ids, a, b, budget)

        primary = hit_families[0]
        console.bad(
            f"SSTI: param '{key}' ({location}) -> {primary['family']} "
            f"payload={primary['payload']!r} engine={', '.join(engines) or 'unconfirmed'}"
        )
        return {
            "param": key,
            "location": location,
            "families": hit_families,
            "engines": engines,
            "example_payload": primary["payload"],
        }

    # ------------------------------------------------------- fingerprint -- #
    def _fingerprint_engine(self, send, family_ids, a: int, b: int, budget) -> List[str]:
        """Bounded, deterministic follow-up probes to narrow the engine guess."""
        engines: List[str] = []
        used = 0

        def spend() -> bool:
            nonlocal used
            if budget.exhausted or used >= MAX_FINGERPRINT_PER_PARAM:
                return False
            used += 1
            return True

        # -- Jinja2 vs Twig/Nunjucks: string * int semantics differ ----------
        if family_ids & _JINJA_FAMILIES and spend():
            payload = "{{7*'7'}}"
            resp = send(payload)
            if resp.status != 0:
                text = resp.text
                if "7777777" in text:
                    engines.append("Jinja2 (Python)")
                elif re.search(r"(?<!\d)49(?!\d)", text) and payload not in text:
                    engines.append("Twig/Nunjucks (non-Python string*int coercion)")

        # -- Smarty: {* ... *} comments get stripped from output -------------
        if "single_brace" in family_ids and spend():
            left, mid, right = uuid4().hex[:6], uuid4().hex[:6], uuid4().hex[:6]
            payload = f"{left}{{*{mid}*}}{right}"
            resp = send(payload)
            if resp.status != 0:
                text = resp.text
                if f"{left}{right}" in text and mid not in text and payload not in text:
                    engines.append("Smarty (comment-stripping confirmed)")

        # -- Ruby (ERB/Slim) supports string repetition; plain EL does not --
        if family_ids & _RUBY_FAMILIES and spend():
            payload = '#{"7"*7}'
            resp = send(payload)
            if resp.status != 0 and "7777777" in resp.text:
                engines.append("Ruby (ERB/Slim, string-repeat confirmed)")
            else:
                engines.append("Ruby ERB/Slim or JSF/Java EL (unconfirmed)")

        # -- ERB (Ruby scriptlet) vs JSP scriptlet ---------------------------
        if "erb_tag" in family_ids and spend():
            payload = "<%= '7'*7 %>"
            resp = send(payload)
            if resp.status != 0 and "7777777" in resp.text:
                engines.append("ERB (Ruby scriptlet, string-repeat confirmed)")
            else:
                engines.append("ERB/JSP scriptlet (unconfirmed)")

        # -- FreeMarker vs Velocity: distinct directive syntax ---------------
        if "dollar_brace" in family_ids:
            if spend():
                var = "rk" + uuid4().hex[:6]
                payload = f"<#assign {var}={a}*{b}>${{{var}}}"
                resp = send(payload)
                if resp.status != 0:
                    text = resp.text
                    if _contains_number(text, str(a * b)) and "<#assign" not in text:
                        engines.append("FreeMarker")
            if spend():
                var = "rk" + uuid4().hex[:6]
                payload = f"#set(${var}={a}*{b})${{{var}}}"
                resp = send(payload)
                if resp.status != 0:
                    text = resp.text
                    if _contains_number(text, str(a * b)) and "#set(" not in text:
                        engines.append("Velocity")
            if not any(e.startswith(("FreeMarker", "Velocity")) for e in engines):
                engines.append("FreeMarker/Velocity/JSP-EL (unconfirmed, ${} syntax)")

        # -- Razor: fairly distinctive syntax, low collision risk ------------
        if "razor_at" in family_ids:
            engines.append("Razor (ASP.NET)")

        return engines

    # ------------------------------------------------------------ report -- #
    @staticmethod
    def _record_finding(ctx, host: str, url: str, hit: Dict[str, object]) -> None:
        families = ", ".join(f["family"] for f in hit["families"])  # type: ignore[index]
        engines = ", ".join(hit["engines"]) or "unconfirmed"  # type: ignore[arg-type]
        ctx.engagement.add_finding(
            f"Server-Side Template Injection in parameter '{hit['param']}'",
            severity="critical",
            host=host,
            description=(
                f"Parameter '{hit['param']}' ({hit['location']}) on {url} evaluates injected "
                f"template expressions. Matched syntax: {families}. Likely engine: {engines}."
            ),
            evidence=f"payload={hit['example_payload']!r}",
        )


class _Budget:
    """Simple mutable request-count budget shared across closures."""

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def spend(self) -> None:
        self.used += 1

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit
