"""CORS (Cross-Origin Resource Sharing) misconfiguration tester.

Sends a small, bounded set of crafted ``Origin`` headers at the target URL and
inspects how the server's ``Access-Control-Allow-Origin`` (ACAO) and
``Access-Control-Allow-Credentials`` (ACAC) response headers react. This
uncovers the handful of classic CORS misconfiguration patterns:

    * arbitrary-origin reflection (any ``Origin`` is echoed back)
    * the ``null`` origin being trusted (sandboxed iframes / file:// pages)
    * a bare wildcard (``ACAO: *``)
    * "suffix" bypass  -- naive checks like ``origin.startswith(allowed)``
      are fooled by an attacker-controlled origin that *starts with* the
      real hostname, e.g. ``https://target.example.com.evil.example``
    * "prefix" bypass  -- naive checks like ``origin.endswith(allowed)``
      are fooled by concatenating onto the real domain without a separating
      dot, e.g. ``https://eviltarget.example.com``
    * an overly-broad sibling-subdomain trust policy
    * scheme confusion (http accepted where only https should be)

Design constraints (redkit invariants):
    * NO AI/LLM usage - every verdict here is a deterministic string/header
      comparison.
    * Pure standard library. All HTTP goes through the shared
      :mod:`redkit.core.http` client (proxy/cookie/header/TLS/timeout aware).
    * Bounded: a fixed, small number of crafted Origin probes per run - no
      wordlists, no unbounded loops.
    * Safe by default: the configured ``method`` defaults to ``GET``; no
      state-changing request is sent unless the operator explicitly picks a
      different method.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.http import WEB_COMMON_OPTIONS, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# Hard cap on crafted-Origin probes per run (defence in depth; the built-in
# origin list below is fixed and well under this already).
MAX_ORIGINS = 10

EVIL_DOMAIN = "evil.example"
SIBLING_LABEL = "redkit-sibling"


def _craft_origins(parsed: urllib.parse.SplitResult) -> List[Tuple[str, str]]:
    """Build the fixed list of ``(origin_type, origin_value)`` probes.

    ``parsed`` is the already-validated target URL split into components.
    Every entry is a distinct, deterministic Origin-header value designed to
    expose one classic CORS misconfiguration pattern.
    """
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = parsed.netloc.split("@")[-1]  # strip any userinfo defensively

    origins: List[Tuple[str, str]] = [
        ("evil_unrelated", f"https://{EVIL_DOMAIN}"),
        ("null", "null"),
    ]

    # Suffix bypass: attacker-controlled domain that *starts with* the real
    # hostname, tripping up naive `origin.startswith(allowed)` checks.
    suffix_host = f"{host}.{EVIL_DOMAIN}"
    origins.append(("suffix_bypass", f"{scheme}://{suffix_host}"))

    # Prefix bypass: real domain glued onto an attacker label with no
    # separating dot, tripping up naive `origin.endswith(allowed)` checks.
    prefix_host = f"evil{host}"
    origins.append(("prefix_bypass", f"{scheme}://{prefix_host}"))

    # Sibling subdomain: same registrable-ish domain, different (unrelated)
    # subdomain label, testing overly-broad "*.domain" trust policies.
    labels = [lbl for lbl in host.split(".") if lbl]
    if len(labels) >= 3:
        sibling_host = ".".join([SIBLING_LABEL] + labels[1:])
    elif len(labels) == 2:
        sibling_host = f"{SIBLING_LABEL}.{host}"
    elif host:
        sibling_host = f"{SIBLING_LABEL}-{host}"
    else:
        sibling_host = f"{SIBLING_LABEL}.{EVIL_DOMAIN}"
    origins.append(("sibling_subdomain", f"{scheme}://{sibling_host}"))

    # Scheme confusion: the exact same host[:port], opposite scheme.
    alt_scheme = "http" if scheme == "https" else "https"
    origins.append(("scheme_swap", f"{alt_scheme}://{netloc}"))

    return origins[:MAX_ORIGINS]


def _classify(origin_type: str, origin_value: str, acao: str, acac: bool) -> Tuple[str, Optional[str]]:
    """Classify one probe's response headers.

    Returns ``(verdict, severity)``. ``severity`` is ``None`` when the
    response does not indicate a misconfiguration worth reporting (no
    finding is recorded in that case).
    """
    acao_norm = (acao or "").strip()
    if not acao_norm:
        return "not-reflected", None

    reflects = acao_norm == origin_value

    if acao_norm.lower() == "null":
        # The server explicitly trusts the sandboxed/opaque "null" origin
        # (reachable from sandboxed iframes, file:// pages, some redirects).
        return "null-origin-accepted", "high"

    if acao_norm == "*":
        # Wildcard ACAO. Per the Fetch spec browsers refuse to pair this
        # with credentialed requests, so it stays "medium" regardless of
        # any Access-Control-Allow-Credentials value the server also sent.
        return "wildcard-acao", "medium"

    if origin_type in ("suffix_bypass", "prefix_bypass") and reflects:
        # The domain-matching check itself is bypassable by an
        # attacker-registrable domain - a real vulnerability on its own.
        return f"{origin_type.replace('_', '-')}-accepted", "high"

    if reflects and acac:
        return "reflected-origin-with-credentials", "high"

    if reflects:
        return "reflected-origin", "medium"

    return "acao-mismatch", None


@register
class CorsMisconfig(Module):
    """Probe a URL with crafted Origin headers to find CORS misconfigurations."""

    name = "web.cors"
    description = "CORS misconfiguration tester (reflected/null/wildcard/suffix-prefix/sibling bypass)"
    phase = "web"
    options = [
        Option("url", help="target URL, e.g. https://host/api/endpoint", required=True),
        Option("method", default="GET", help="HTTP method used for each probe (favour GET; avoid state-changing methods unless intended)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://portswigger.net/web-security/cors",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    ]

    def run(self, opts: Dict[str, Any], ctx) -> Result:
        console = ctx.console
        url = str(opts.get("url") or "").strip()
        method = str(opts.get("method") or "GET").strip().upper() or "GET"

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {url!r} (expected http(s)://host[...])")

        host = parsed.hostname
        origins = _craft_origins(parsed)

        console.banner("CORS misconfiguration test", url)
        console.info(f"probing {len(origins)} crafted Origin header(s) with {method} {url} (capped at {MAX_ORIGINS})")

        client = client_from_opts(opts)

        results: List[Dict[str, Any]] = []
        findings = 0
        for origin_type, origin_value in origins:
            resp = client.request(method, url, headers={"Origin": origin_value})

            if resp.error or resp.status == 0:
                console.warn(f"[{origin_type}] {origin_value} -> unreachable ({resp.error or 'no response'})")
                results.append(
                    {
                        "origin_type": origin_type,
                        "origin": origin_value,
                        "status": resp.status,
                        "acao": None,
                        "acac": None,
                        "verdict": "unreachable",
                    }
                )
                continue

            acao_raw = resp.header("access-control-allow-origin", "")
            acac_raw = resp.header("access-control-allow-credentials", "")
            acac = acac_raw.strip().lower() == "true"
            verdict, severity = _classify(origin_type, origin_value, acao_raw, acac)

            results.append(
                {
                    "origin_type": origin_type,
                    "origin": origin_value,
                    "status": resp.status,
                    "acao": acao_raw or None,
                    "acac": acac,
                    "verdict": verdict,
                }
            )

            if severity:
                findings += 1
                title = f"CORS misconfiguration ({origin_type}): {verdict}"
                description = (
                    f"{method} {url} with request header 'Origin: {origin_value}' returned "
                    f"Access-Control-Allow-Origin: {acao_raw or '(absent)'}, "
                    f"Access-Control-Allow-Credentials: {acac_raw or '(absent)'} (HTTP {resp.status})."
                )
                ctx.engagement.add_finding(
                    title,
                    severity=severity,
                    host=host,
                    description=description,
                    evidence=f"Origin: {origin_value} -> Access-Control-Allow-Origin: {acao_raw}",
                )
                console.bad(f"[{origin_type}] {verdict}  (reflected origin: {origin_value})")
            else:
                console.info(f"[{origin_type}] {origin_value} -> ACAO={acao_raw or '(absent)'} verdict={verdict}")

        summary = f"{url}: {len(origins)} Origin probe(s), {findings} CORS misconfiguration finding(s)"
        if findings:
            ctx.engagement.add_note(f"web.cors: {summary}")
        return Result(
            ok=True,
            summary=summary,
            data={"url": url, "method": method, "results": results},
        )
