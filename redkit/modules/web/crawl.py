"""Same-origin web spider with JS-endpoint mining and secret detection.

Performs a breadth-first crawl of a target site, staying strictly within the
starting URL's scheme+host. For every page it parses anchor hrefs, form
action/method/input-names, and query-string parameters. Optionally it also
fetches same-origin ``.js`` files referenced by the pages and mines both HTML
and JS bodies for API-ish endpoints and likely leaked secrets (AWS/Google/
Slack keys, bearer tokens, JWTs, generic api_key=/secret=/password=
assignments, PEM private keys).

Design constraints (redkit invariants):
    * NO AI/LLM usage - every decision here is a deterministic regex/HTML
      parsing rule against the raw response bytes.
    * Pure standard library (``urllib``, ``html.parser``, ``re``). All HTTP
      goes through the shared ``redkit.core.http`` client so proxying,
      cookies, auth headers, and TLS handling stay consistent with every
      other web module.
    * Imports and runs on both Windows and Linux (no OS-specific calls).
    * Offline-first: nothing is ever downloaded except the target itself.
    * Safe and bounded: GET-only, hard ceilings on pages/depth/JS files,
      capped per-resource body size read for regex scanning, a capped
      thread pool only for the (already-discovered) JS fetch phase, and the
      crawl never follows a link or redirect off the starting scheme+host.
      Only redacted previews of any detected secret are ever persisted -
      the raw secret value is never written to disk or the engagement.
"""
from __future__ import annotations

import html.parser
import json
import re
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

from redkit.core.http import WEB_COMMON_OPTIONS, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# bounds - hard invariants, not operator-configurable beyond these ceilings
# --------------------------------------------------------------------------- #
MAX_PAGES_HARD_CAP = 2000        # absolute ceiling regardless of operator input
MAX_DEPTH_HARD_CAP = 10
MAX_JS_FILES = 60                # ceiling on distinct .js files fetched per run
MAX_JS_THREADS = 20              # thread pool cap for the JS-fetch phase
MAX_RESOURCE_BYTES = 10_000_000  # skip parsing/scanning oversized responses
MAX_BODY_SCAN = 2_000_000        # chars of text regex-scanned per resource
MAX_LOOT_PARAMS = 1000           # ceiling on param names persisted as loot
MAX_LOOT_ENDPOINTS = 1000        # ceiling on endpoints persisted as loot
MAX_SECRET_FINDINGS = 200        # ceiling on distinct secret findings recorded

REDIRECT_CODES = (301, 302, 303, 307, 308)
HTML_LIKE_TYPES = ("text/html", "application/xhtml+xml")
_SKIP_HREF_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "sms:")
_ASSET_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".css", ".map",
)

# --------------------------------------------------------------------------- #
# JS endpoint-mining patterns (relative/absolute paths, fetch/axios/XHR calls)
# --------------------------------------------------------------------------- #
_ENDPOINT_CALL_PATTERNS = [
    re.compile(r"""fetch\(\s*[`'"]([^`'"]+)[`'"]"""),
    re.compile(r"""axios(?:\.\w+)?\(\s*\{[^}]*?url\s*:\s*[`'"]([^`'"]+)[`'"]""", re.S),
    re.compile(r"""axios\.(?:get|post|put|delete|patch|head)\(\s*[`'"]([^`'"]+)[`'"]"""),
    re.compile(r"""\.open\(\s*[`'"](?:GET|POST|PUT|DELETE|PATCH|HEAD)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]""", re.I),
    re.compile(r"""\$\.(?:get|post|ajax|getJSON)\(\s*[`'"]([^`'"]+)[`'"]"""),
]
_PATH_LITERAL_RE = re.compile(r"""[`'"](/[A-Za-z0-9][A-Za-z0-9_\-./%]{1,200})[`'"]""")
_ABS_URL_RE = re.compile(r"""[`'"](https?://[A-Za-z0-9._\-]+(?:/[A-Za-z0-9_\-./%?=&,+~]*)?)[`'"]""")

# --------------------------------------------------------------------------- #
# secret patterns - kind name -> compiled regex (captures the value in group 1
# where possible, otherwise group 0 is used as-is)
# --------------------------------------------------------------------------- #
SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_.=]{15,})")),
    ("generic_api_key", re.compile(
        r'(?i)\b(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_./+]{8,})["\']?'
    )),
    ("generic_secret", re.compile(
        r'(?i)\bsecret(?:[_-]?key)?["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_./+]{8,})["\']?'
    )),
    ("generic_password", re.compile(
        r'(?i)\bpassword["\']?\s*[:=]\s*["\']?([^\s"\'<>(){};,]{6,})["\']?'
    )),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]
_GENERIC_KINDS = {"generic_api_key", "generic_secret", "generic_password"}
_SECRET_VALUE_BLOCKLIST = {
    "true", "false", "null", "undefined", "password", "username", "placeholder",
    "xxxxxxxx", "changeme", "string", "enter", "yourpassword", "123456", "email",
}


# --------------------------------------------------------------------------- #
# lightweight HTML parsing: anchors, forms, <script> tags/inline bodies
# --------------------------------------------------------------------------- #
class _PageParser(html.parser.HTMLParser):
    """Collects hrefs, forms (action/method/input-names), and script data."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, object]] = []
        self.scripts: List[str] = []
        self.inline_scripts: List[str] = []
        self._cur_form: Optional[Dict[str, object]] = None
        self._in_script = False
        self._script_buf: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: D401
        tag = tag.lower()
        adict = {k.lower(): v for k, v in attrs if k}
        if tag in ("a", "area"):
            href = adict.get("href")
            if href:
                self.links.append(href)
        elif tag == "form":
            self._cur_form = {
                "action": adict.get("action") or "",
                "method": (adict.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "select", "textarea", "button") and self._cur_form is not None:
            name = adict.get("name")
            if name:
                self._cur_form["inputs"].append(name)  # type: ignore[union-attr]
        elif tag == "script":
            src = adict.get("src")
            if src:
                self.scripts.append(src)
                self._in_script = False
            else:
                self._in_script = True
                self._script_buf = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None
        elif tag == "script" and self._in_script:
            if self._script_buf:
                self.inline_scripts.append("".join(self._script_buf))
            self._in_script = False
            self._script_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)


# --------------------------------------------------------------------------- #
# small pure helpers
# --------------------------------------------------------------------------- #
def _strip_fragment(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _resolve(base_url: str, href: Optional[str]) -> Optional[str]:
    """Join a possibly-relative href against ``base_url``; None if unusable."""
    if not href:
        return None
    href = href.strip()
    if not href or href.startswith("#") or href.lower().startswith(_SKIP_HREF_SCHEMES):
        return None
    try:
        return urllib.parse.urljoin(base_url, href)
    except ValueError:
        return None


def _extract_query_params(url: str) -> List[str]:
    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return []
    if not query:
        return []
    try:
        return list(urllib.parse.parse_qs(query, keep_blank_values=True).keys())
    except ValueError:
        return []


def _looks_like_html(snippet: str) -> bool:
    low = snippet.lower()
    return "<html" in low or "<!doctype html" in low or "<body" in low or "<head" in low


def _is_same_origin(url: str, scheme: str, host: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == scheme and (parts.hostname or "").lower() == host


def _extract_js_endpoints(text: str, origin_scheme: str, origin_host: str) -> Set[str]:
    """Regex-mine relative/absolute endpoint paths out of JS source text."""
    found: Set[str] = set()
    budget = 3000  # bound regex work against pathological/minified input
    for pattern in _ENDPOINT_CALL_PATTERNS:
        for m in pattern.finditer(text):
            val = (m.group(1) or "").strip()
            if val:
                found.add(val)
            budget -= 1
            if budget <= 0:
                return found
    for m in _PATH_LITERAL_RE.finditer(text):
        val = m.group(1).strip()
        if val.lower().endswith(_ASSET_EXTS):
            continue
        found.add(val)
        budget -= 1
        if budget <= 0:
            return found
    for m in _ABS_URL_RE.finditer(text):
        val = m.group(1).strip()
        if _is_same_origin(val, origin_scheme, origin_host):
            path = urllib.parse.urlsplit(val).path or "/"
            found.add(path)
        budget -= 1
        if budget <= 0:
            return found
    return found


def _redact(value: str) -> str:
    """Return a short, non-reversible preview - never persist the raw secret."""
    value = value.strip()
    if len(value) <= 8:
        return "***"
    return f"{value[:6]}...{value[-4:]}"


def _extract_secrets(text: str) -> List[Tuple[str, str]]:
    """Regex-scan text for likely secrets. Returns (kind, raw_value) pairs."""
    found: List[Tuple[str, str]] = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = (m.group(1) if m.groups() else m.group(0)).strip().strip("'\"")
            if not value:
                continue
            if kind in _GENERIC_KINDS and (len(value) < 6 or value.lower() in _SECRET_VALUE_BLOCKLIST):
                continue
            found.append((kind, value))
            if len(found) >= 500:  # bound work against pathological input
                return found
    return found


def _normalize_start_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    return raw


@register
class WebCrawl(Module):
    """Same-origin spider: pages, forms, params, JS endpoints, leaked secrets."""

    name = "web.crawl"
    description = "Same-origin web spider with JS-endpoint mining and secret detection"
    phase = "web"
    options = [
        Option("url", help="starting URL, e.g. https://target.example/", required=True),
        Option("max_pages", default=200, help=f"max pages to fetch (hard-capped at {MAX_PAGES_HARD_CAP})"),
        Option("depth", default=2, help=f"max BFS link depth from the start URL (hard-capped at {MAX_DEPTH_HARD_CAP})"),
        Option("fetch_js", default=True, help="download same-origin .js files and mine them for endpoints/secrets"),
        Option("extract_secrets", default=True, help="regex-scan HTML/JS bodies for likely leaked secrets"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, object], ctx) -> Result:  # noqa: C901 - linear pipeline
        console = ctx.console
        start_url = _normalize_start_url(str(opts["url"]))
        parsed = urllib.parse.urlsplit(start_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r} (expected http(s)://host)")

        origin_scheme = parsed.scheme
        origin_host = parsed.hostname.lower()
        host_only = origin_host
        start_url = _strip_fragment(start_url)

        max_pages = max(1, min(int(opts["max_pages"]), MAX_PAGES_HARD_CAP))
        depth_limit = max(0, min(int(opts["depth"]), MAX_DEPTH_HARD_CAP))
        fetch_js = bool(opts["fetch_js"])
        do_secrets = bool(opts["extract_secrets"])

        # Redirects are surfaced (not auto-followed) so a same-origin check can
        # be applied uniformly to every hop - the crawl must never silently
        # wander off the authorized origin via a 3xx.
        client = client_from_opts(opts, allow_redirects=False)
        ctx.engagement.add_host(host_only)

        console.info(
            f"crawling {start_url}  (max_pages={max_pages}, depth={depth_limit}, "
            f"fetch_js={fetch_js}, extract_secrets={do_secrets})"
        )

        visited: Set[str] = set()
        queued: Set[str] = {start_url}
        queue: deque = deque([(start_url, 0)])

        pages: Dict[str, Dict[str, object]] = {}
        all_params: Set[str] = set()
        all_endpoints: Set[str] = set()
        js_urls: Set[str] = set()
        secrets_seen: Set[Tuple[str, str]] = set()
        secret_records: List[Dict[str, str]] = []
        forms_total = 0
        errors = 0

        def record_secret(kind: str, value: str, source: str) -> None:
            key = (kind, value)
            if key in secrets_seen or len(secret_records) >= MAX_SECRET_FINDINGS:
                return
            secrets_seen.add(key)
            secret_records.append({"kind": kind, "preview": _redact(value), "source": source})

        # -- BFS crawl loop ---------------------------------------------- #
        while queue and len(visited) < max_pages:
            url, cur_depth = queue.popleft()
            norm = _strip_fragment(url)
            if norm in visited:
                continue
            visited.add(norm)

            resp = client.get(url)
            if resp.error or resp.status == 0:
                console.debug(f"unreachable: {url} ({resp.error})")
                errors += 1
                pages[norm] = {"status": 0, "depth": cur_depth, "error": resp.error}
                continue

            page_entry: Dict[str, object] = {"status": resp.status, "depth": cur_depth, "links": [], "forms": []}

            # -- 3xx: treat Location as just another same-origin link, never
            #    auto-followed off the origin ------------------------------ #
            if resp.status in REDIRECT_CODES:
                location = resp.header("location")
                target = _resolve(url, location) if location else None
                if target:
                    page_entry["redirect_to"] = _strip_fragment(target)
                    if _is_same_origin(target, origin_scheme, origin_host):
                        target_norm = _strip_fragment(target)
                        if (
                            target_norm not in queued
                            and target_norm not in visited
                            and cur_depth + 1 <= depth_limit
                        ):
                            queued.add(target_norm)
                            queue.append((target_norm, cur_depth + 1))
                pages[norm] = page_entry
                continue

            if resp.length > MAX_RESOURCE_BYTES:
                console.debug(f"skipping oversized response ({resp.length}B): {url}")
                page_entry["skipped_oversized"] = True
                pages[norm] = page_entry
                continue

            for p in _extract_query_params(url):
                all_params.add(p)

            content_type = resp.header("content-type", "")
            page_entry["content_type"] = content_type
            body_text = resp.text[:MAX_BODY_SCAN]
            ctype_base = content_type.split(";")[0].strip().lower()
            is_html = ctype_base in HTML_LIKE_TYPES or (not ctype_base and _looks_like_html(body_text[:512]))

            if is_html:
                try:
                    page_parser = _PageParser()
                    page_parser.feed(body_text)
                except Exception:  # noqa: BLE001 - malformed markup must never abort the crawl
                    page_parser = _PageParser()

                # anchors -> BFS frontier (same-origin only) + query params
                for href in page_parser.links:
                    resolved = _resolve(url, href)
                    if not resolved or not _is_same_origin(resolved, origin_scheme, origin_host):
                        continue
                    for p in _extract_query_params(resolved):
                        all_params.add(p)
                    resolved_norm = _strip_fragment(resolved)
                    page_entry["links"].append(resolved_norm)  # type: ignore[union-attr]
                    if (
                        resolved_norm not in queued
                        and resolved_norm not in visited
                        and cur_depth + 1 <= depth_limit
                    ):
                        queued.add(resolved_norm)
                        queue.append((resolved_norm, cur_depth + 1))

                # forms -> action/method/input-names + params + endpoint
                for form in page_parser.forms:
                    forms_total += 1
                    action_resolved = _resolve(url, str(form["action"])) or url
                    for name in form["inputs"]:  # type: ignore[union-attr]
                        all_params.add(str(name))
                    for p in _extract_query_params(action_resolved):
                        all_params.add(p)
                    if _is_same_origin(action_resolved, origin_scheme, origin_host):
                        all_endpoints.add(urllib.parse.urlsplit(action_resolved).path or "/")
                    page_entry["forms"].append({  # type: ignore[union-attr]
                        "action": _strip_fragment(action_resolved),
                        "method": form["method"],
                        "inputs": form["inputs"],
                    })

                # scripts referenced -> queue same-origin .js for later fetch
                if fetch_js:
                    for src in page_parser.scripts:
                        resolved = _resolve(url, src)
                        if resolved and _is_same_origin(resolved, origin_scheme, origin_host):
                            js_urls.add(_strip_fragment(resolved))

                # inline <script> bodies -> mine immediately
                for script_body in page_parser.inline_scripts:
                    all_endpoints.update(_extract_js_endpoints(script_body, origin_scheme, origin_host))
                    if do_secrets:
                        for kind, value in _extract_secrets(script_body):
                            record_secret(kind, value, url)

                if do_secrets:
                    for kind, value in _extract_secrets(body_text):
                        record_secret(kind, value, url)

            pages[norm] = page_entry

        if len(visited) >= max_pages and queue:
            console.warn(f"max_pages ({max_pages}) reached; {len(queue)} discovered URL(s) left unvisited")

        # -- JS fetch phase (bounded, capped thread pool, same-origin only) -- #
        js_fetched = 0
        if fetch_js and js_urls:
            js_list = sorted(js_urls)[:MAX_JS_FILES]
            if len(js_urls) > MAX_JS_FILES:
                console.warn(f"capping JS fetch at {MAX_JS_FILES} of {len(js_urls)} discovered script(s)")
            console.info(f"fetching {len(js_list)} same-origin script(s)")
            workers = min(MAX_JS_THREADS, max(1, len(js_list)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {pool.submit(client.get, js_url): js_url for js_url in js_list}
                for fut in as_completed(future_map):
                    js_url = future_map[fut]
                    try:
                        jresp = fut.result()
                    except Exception:  # noqa: BLE001 - a fetch must never abort the run
                        continue
                    if jresp.error or jresp.status == 0 or not jresp.ok:
                        continue
                    if jresp.length > MAX_RESOURCE_BYTES:
                        continue
                    js_fetched += 1
                    js_text = jresp.text[:MAX_BODY_SCAN]
                    all_endpoints.update(_extract_js_endpoints(js_text, origin_scheme, origin_host))
                    if do_secrets:
                        for kind, value in _extract_secrets(js_text):
                            record_secret(kind, value, js_url)

        if len(secret_records) >= MAX_SECRET_FINDINGS:
            console.warn(f"secret findings capped at {MAX_SECRET_FINDINGS}")

        # -- persist params/endpoints as loot, secrets as findings ----------- #
        params_to_store = sorted(all_params)
        if len(params_to_store) > MAX_LOOT_PARAMS:
            console.warn(f"capping persisted params at {MAX_LOOT_PARAMS} of {len(params_to_store)} found")
            params_to_store = params_to_store[:MAX_LOOT_PARAMS]
        endpoints_to_store = sorted(all_endpoints)
        if len(endpoints_to_store) > MAX_LOOT_ENDPOINTS:
            console.warn(f"capping persisted endpoints at {MAX_LOOT_ENDPOINTS} of {len(endpoints_to_store)} found")
            endpoints_to_store = endpoints_to_store[:MAX_LOOT_ENDPOINTS]

        for p in params_to_store:
            ctx.engagement.add_loot(host_only, "param", p, source="web.crawl")
        for e in endpoints_to_store:
            ctx.engagement.add_loot(host_only, "endpoint", e, source="web.crawl")
        for rec in secret_records:
            ctx.engagement.add_finding(
                f"Possible secret exposed in web content ({rec['kind']})",
                severity="high",
                host=host_only,
                description=(
                    f"A pattern matching '{rec['kind']}' was found in content served at "
                    f"{rec['source']}. Preview (redacted): {rec['preview']}"
                ),
                evidence=rec["source"],
            )

        # Real injection points: param-bearing GET URLs actually seen, and the
        # forms (action/method/inputs) discovered. These let a downstream sweep
        # attack the exact endpoints rather than guessing param/path pairings.
        get_targets = sorted(u for u in visited if urllib.parse.urlsplit(u).query)
        form_targets: List[Dict[str, object]] = []
        _seen_forms = set()
        for pg in pages.values():
            for fm in (pg.get("forms") or []):  # type: ignore[union-attr]
                key = (fm.get("action"), fm.get("method"))
                if key in _seen_forms:
                    continue
                _seen_forms.add(key)
                form_targets.append(fm)

        data = {
            "start_url": start_url,
            "host": host_only,
            "pages_crawled": len(visited),
            "pages_errored": errors,
            "forms_found": forms_total,
            "params_found": len(all_params),
            "endpoints_found": len(all_endpoints),
            "js_files_fetched": js_fetched,
            "secrets_found": len(secret_records),
            "params": params_to_store[:500],
            "endpoints": endpoints_to_store[:500],
            "secrets": secret_records[:200],
            "get_targets": get_targets[:500],
            "form_targets": form_targets[:200],
        }

        artifacts = self._write_artifacts(ctx, host_only, pages, data)

        console.good(
            f"crawl complete: {len(visited)} page(s), {forms_total} form(s), "
            f"{len(all_params)} param(s), {len(all_endpoints)} endpoint(s), "
            f"{len(secret_records)} secret(s)"
        )
        summary = (
            f"{start_url}: {len(visited)} pages, {forms_total} forms, "
            f"{len(all_params)} params, {len(all_endpoints)} endpoints, "
            f"{len(secret_records)} secrets"
        )
        ctx.engagement.add_note(f"web.crawl: {summary}")
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # -------------------------------------------------------- internals -- #
    @staticmethod
    def _write_artifacts(ctx, host: str, pages: Dict[str, Dict[str, object]], data: Dict[str, object]) -> List[str]:
        artifacts: List[str] = []
        safe_host = (host or "target").replace(":", "_")
        try:
            path = ctx.artifact_path(f"crawl_map_{safe_host}.json")
            path.write_text(
                json.dumps({"summary": data, "pages": pages}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            artifacts.append(str(path))
        except OSError:
            pass
        return artifacts
