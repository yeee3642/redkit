"""WAF / CDN fingerprinting probe.

Sends a benign baseline ``GET`` and a second, lightly malicious ``GET`` that
carries an obvious attack canary (an XSS tag plus a SQLi boolean payload) in
a throwaway query parameter, then diffs the two responses to work out what
security/CDN layer sits in front of the target -- so the operator knows what
is likely to block them before they start real testing.

Signals compared between the baseline and the malicious-probe response:
    * response headers (``Server``, ``Via``, ``X-CDN``, ``X-Cache``,
      ``CF-RAY``, ``CF-Cache-Status``, ``X-Sucuri-*``, ``X-Akamai-*``,
      ``X-Iinfo``, ``X-Amz-Cf-Id``, ``X-Powered-By-Plesk``, ``X-WAF-*`` ...)
    * ``Set-Cookie`` names (``__cfduid``, ``__cf_bm``, ``incap_ses_``,
      ``visid_incap_``, ``AWSALB``, ``barra_counter_session``, ``ns_af``,
      ``citrix_ns_id`` ...)
    * a status-code change on the malicious request alone (403/406/429/501/999)
    * body signatures for known WAF/CDN block pages (Cloudflare "Attention
      Required", Akamai "Reference #", Imperva/Incapsula, Sucuri CloudProxy,
      AWS WAF, F5 BIG-IP, Citrix NetScaler AppFirewall, ModSecurity,
      Wordfence, Barracuda, DenyALL, Fortinet FortiWeb)

Matches are made against a small built-in signature table (name -> header /
cookie-name / body regexes). Every verdict is a deterministic regex/string
match -- there is no ML/AI classifier or scoring model involved.

Design constraints (redkit invariants):
    * NO AI/LLM usage.
    * Pure standard library (``re``, ``urllib``). No third-party imports.
    * Imports and runs on both Windows and Linux; no OS-specific calls.
    * Offline: nothing downloaded, the signature table is bundled in this
      file.
    * Bounded: exactly two requests are sent per run (baseline + malicious
      probe) through the shared, timeout-bound :class:`HttpClient`.
    * Safe by default: both requests are ``GET``; the "malicious" request is
      a single read-only probe carrying an inert canary string, never a
      state-changing request.
    * Never crashes on transport errors -- unreachable targets are reported,
      not raised.

For AUTHORIZED security testing only.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List

from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# tuning constants (all conservative / bounded -- exactly 2 requests per run)
# --------------------------------------------------------------------------- #
BODY_SAMPLE = 200_000  # chars of response body inspected per response

CANARY_PARAM = "redkitwaf"
CANARY_BENIGN = "1"
# Obvious, inert attack canary: an XSS tag plus a classic SQLi boolean
# payload. Never executed anywhere -- it is just a string sent as a query
# value to see whether a WAF/filter reacts to it.
CANARY_PAYLOAD = "<script>alert(1)</script>' OR 1=1-- -"

# Status codes commonly returned by WAFs/CDNs/edge proxies for a blocked or
# challenged request.
BLOCK_STATUS_CODES = {403, 406, 429, 501, 999}

# --------------------------------------------------------------------------- #
# Built-in WAF / CDN signature table.
#
#   headers          : [(header_name_lower, value_regex_or_None), ...]
#                       -- None means "header present" is itself the signal.
#   header_prefixes  : [prefix_lower, ...] -- any response header whose
#                       *name* starts with one of these is a signal (e.g.
#                       x-akamai-*).
#   cookies          : [name_regex, ...] -- matched against the raw
#                       Set-Cookie header value (cookie *names*).
#   body             : [phrase_regex, ...] -- matched against response body
#                       text (case-insensitive).
# --------------------------------------------------------------------------- #
SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Cloudflare",
        "headers": [("server", r"cloudflare"), ("cf-ray", None), ("cf-cache-status", None)],
        "cookies": [r"__cfduid", r"__cf_bm", r"cf_clearance"],
        "body": [
            r"attention required[^<]{0,40}cloudflare",
            r"cloudflare ray id",
            r"checking your browser[\s\S]{0,80}cloudflare",
        ],
    },
    {
        "name": "Akamai",
        "headers": [("server", r"akamaighost")],
        "header_prefixes": ["x-akamai-"],
        "body": [r"reference #\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+", r"akamai"],
    },
    {
        "name": "Imperva / Incapsula",
        "headers": [("x-iinfo", None), ("x-cdn", r"incapsula")],
        "cookies": [r"incap_ses_", r"visid_incap_"],
        "body": [r"_incapsula_resource", r"incapsula incident id", r"imperva"],
    },
    {
        "name": "Sucuri CloudProxy",
        "headers": [("x-sucuri-id", None), ("x-sucuri-cache", None), ("server", r"sucuri")],
        "body": [r"sucuri (website firewall|cloudproxy)", r"access denied[\s\S]{0,80}sucuri", r"sucuri/cloudproxy"],
    },
    {
        "name": "AWS WAF / CloudFront",
        "headers": [("x-amz-cf-id", None), ("x-amzn-errortype", r"waf")],
        "cookies": [r"awsalb", r"awsalbcors"],
        "body": [r"request blocked", r"the request could not be satisfied", r"\baws waf\b"],
    },
    {
        "name": "F5 BIG-IP ASM",
        "headers": [("server", r"big-?ip")],
        "cookies": [r"^ts[0-9a-f]{6,}", r"bigipserver"],
        "body": [r"the requested url was rejected", r"please consult with your administrator"],
    },
    {
        "name": "Citrix NetScaler AppFirewall",
        "headers": [("server", r"netscaler")],
        "cookies": [r"ns_af", r"citrix_ns_id"],
        "body": [r"citrix application firewall", r"netscaler"],
    },
    {
        "name": "ModSecurity",
        "headers": [("server", r"mod_security|modsecurity")],
        "body": [r"mod_security", r"modsecurity", r"this error was generated by mod_security"],
    },
    {
        "name": "Wordfence",
        "body": [r"wordfence", r"generated by wordfence"],
    },
    {
        "name": "Barracuda WAF",
        "headers": [("server", r"barracuda")],
        "cookies": [r"barra_counter_session"],
        "body": [r"barracuda"],
    },
    {
        "name": "DenyALL",
        "headers": [("server", r"denyall")],
        # NOTE: intentionally *not* matching the bare phrase "deny all" in the
        # body -- that is common, unrelated English (ACL docs, permission
        # dialogs) and would be a false-positive-prone signature. Only the
        # one-word vendor/product name is treated as a signal.
        "body": [r"denyall"],
    },
    {
        "name": "Fortinet FortiWeb",
        "headers": [("server", r"fortiweb|fortinet")],
        "body": [r"fortiweb", r"fortinet"],
    },
]

# Generic, vendor-agnostic CDN/proxy/WAF hints -- reported as "unidentified"
# only when present but no named vendor signature above already matched.
GENERIC_HEADER_HINTS = ["via", "x-cdn", "x-cache", "x-powered-by-plesk"]
GENERIC_WAF_PREFIX = "x-waf-"


def _set_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value`` (added if absent)."""
    parts = urllib.parse.urlsplit(url)
    pairs = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    new_query = urllib.parse.urlencode(pairs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _match_signature(sig: Dict[str, Any], label: str, resp: Response) -> List[str]:
    """Return evidence strings for one signature against one labeled response."""
    evidence: List[str] = []
    hdrs = resp.headers or {}

    for hname, vregex in sig.get("headers", []):
        val = hdrs.get(hname)
        if val is None:
            continue
        if vregex is None or re.search(vregex, val, re.I):
            evidence.append(f"{label} header {hname}: {val}")

    for prefix in sig.get("header_prefixes", []):
        for k, v in hdrs.items():
            if k.startswith(prefix):
                evidence.append(f"{label} header {k}: {v}")

    cookies_res = sig.get("cookies")
    if cookies_res:
        set_cookie = hdrs.get("set-cookie", "")
        if set_cookie:
            for cre in cookies_res:
                if re.search(cre, set_cookie, re.I):
                    evidence.append(f"{label} Set-Cookie matches /{cre}/: {set_cookie[:120]}")

    body_res = sig.get("body")
    if body_res and resp.body:
        text = resp.text[:BODY_SAMPLE]
        for bre in body_res:
            m = re.search(bre, text, re.I)
            if m:
                evidence.append(f"{label} body matches /{bre}/: {m.group(0)[:80]!r}")

    return evidence


def _resp_summary(resp: Response) -> Dict[str, Any]:
    return {
        "status": resp.status,
        "reason": resp.reason,
        "length": resp.length,
        "error": resp.error,
        "headers": dict(resp.headers or {}),
    }


def _unreachable(resp: Response) -> bool:
    """True only for genuine transport-level failures (never for 4xx/5xx)."""
    return bool(resp.error) and resp.status == 0


@register
class Waf(Module):
    """Fingerprint the WAF/CDN in front of a URL via a baseline vs. malicious-probe diff."""

    name = "web.waf"
    description = "WAF/CDN fingerprint (baseline vs malicious-probe header/cookie/status/body diffing)"
    phase = "web"
    options = [
        Option("url", help="target URL, e.g. https://host/path?param=value", required=True),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/Web_Application_Firewall",
        "https://github.com/EnableSecurity/wafw00f",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/09-Testing_WAF_Bypass_or_WAF_Detection",
    ]

    def run(self, opts: Dict[str, Any], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts.get("url") or "").strip()
        if "://" not in raw_url:
            raw_url = "http://" + raw_url
        parsed = urllib.parse.urlsplit(raw_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts.get('url')!r} (expected http(s)://host[...])")

        host = parsed.hostname
        ctx.engagement.add_host(host)

        client = client_from_opts(opts)

        baseline_url = _set_query_param(raw_url, CANARY_PARAM, CANARY_BENIGN)
        malicious_url = _set_query_param(raw_url, CANARY_PARAM, CANARY_PAYLOAD)

        console.banner("WAF / CDN fingerprint", raw_url)
        console.info(f"baseline GET {baseline_url}")
        baseline_resp = client.get(baseline_url)
        console.info(f"malicious-probe GET {malicious_url}")
        malicious_resp = client.get(malicious_url)

        if _unreachable(baseline_resp) and _unreachable(malicious_resp):
            err = baseline_resp.error or malicious_resp.error
            summary = f"{raw_url} unreachable: {err}"
            console.warn(summary)
            ctx.engagement.add_note(f"web.waf: {summary}")
            return Result(ok=False, summary=summary, data={"url": raw_url, "host": host, "error": err})

        responses = []
        if not _unreachable(baseline_resp):
            responses.append(("baseline", baseline_resp))
        if not _unreachable(malicious_resp):
            responses.append(("malicious", malicious_resp))

        # -- signature matching ------------------------------------------------
        detections: Dict[str, List[str]] = {}
        for sig in SIGNATURES:
            evidence: List[str] = []
            for label, resp in responses:
                evidence.extend(_match_signature(sig, label, resp))
            if evidence:
                detections[sig["name"]] = evidence

        generic_hits: List[str] = []
        for label, resp in responses:
            hdrs = resp.headers or {}
            for hname in GENERIC_HEADER_HINTS:
                if hname in hdrs:
                    generic_hits.append(f"{label} header {hname}: {hdrs[hname]}")
            for k, v in hdrs.items():
                if k.startswith(GENERIC_WAF_PREFIX):
                    generic_hits.append(f"{label} header {k}: {v}")

        # -- status-code / transport behaviour change on the malicious probe ---
        blocked = False
        status_note = ""
        if baseline_resp.status and malicious_resp.status:
            if malicious_resp.status != baseline_resp.status and malicious_resp.status in BLOCK_STATUS_CODES:
                blocked = True
                status_note = (
                    f"malicious probe returned HTTP {malicious_resp.status} vs baseline HTTP "
                    f"{baseline_resp.status} -- looks like the request was blocked/challenged"
                )
        elif malicious_resp.error and not baseline_resp.error:
            blocked = True
            status_note = (
                f"malicious probe was rejected at the transport level ({malicious_resp.error}) "
                f"while the baseline succeeded"
            )

        # -- report findings -----------------------------------------------------
        for wname, evidence in detections.items():
            shown = evidence[:6]
            desc = f"{raw_url}: fingerprint signals matched for {wname}: " + "; ".join(shown)
            if len(evidence) > len(shown):
                desc += f" (+{len(evidence) - len(shown)} more)"
            ctx.engagement.add_finding(
                f"WAF/CDN detected: {wname}",
                severity="info",
                host=host,
                description=desc,
                evidence="; ".join(evidence[:10]),
            )
            console.good(f"detected: {wname} ({len(evidence)} signal(s))")

        if not detections and generic_hits:
            desc = (
                f"{raw_url}: generic CDN/proxy/WAF header(s) present but no specific vendor signature "
                f"matched: " + "; ".join(generic_hits[:6])
            )
            ctx.engagement.add_finding(
                "WAF/CDN detected: unidentified (generic proxy/CDN headers present)",
                severity="info",
                host=host,
                description=desc,
                evidence="; ".join(generic_hits[:10]),
            )
            console.info(f"unidentified CDN/proxy headers present: {len(generic_hits)} signal(s)")

        if blocked:
            console.warn(status_note)
            ctx.engagement.add_note(
                f"web.waf: {status_note}. A WAF/filter appears to be intercepting the malicious probe -- "
                f"active testing (sqli/xss/etc.) against {host} may need evasion (encoding, chunking, "
                f"alternate parameter placement, throttling) to get past it."
            )
        elif detections:
            ctx.engagement.add_note(
                f"web.waf: {raw_url} -- detected {', '.join(sorted(detections.keys()))}; the malicious "
                f"probe was not visibly blocked (status {malicious_resp.status or 'n/a'})."
            )

        if not detections and not generic_hits and not blocked:
            console.info("no WAF/CDN signature matched -- no fingerprint (or an unlisted product)")

        names = sorted(detections.keys())
        summary = f"{raw_url}: {len(names)} WAF/CDN signature(s) matched"
        if names:
            summary += f" ({', '.join(names)})"
        if blocked:
            summary += "; malicious probe appears blocked"

        data: Dict[str, Any] = {
            "url": raw_url,
            "host": host,
            "baseline": _resp_summary(baseline_resp),
            "malicious": _resp_summary(malicious_resp),
            "waf": names,
            "blocked": blocked,
            "evidence": detections,
            "generic_hints": generic_hits,
        }
        return Result(ok=True, summary=summary, data=data)
