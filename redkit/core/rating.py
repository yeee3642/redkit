"""Offline risk rating (CVSS 3.1) + PoC generation for findings.

Deterministic, no network, no AI. Turns a raw finding into something you can
put in a report and submit: a CVSS vector + score + severity, a CWE, a
remediation, a "submittable" flag, and a runnable proof-of-concept (curl + raw
HTTP request) reconstructed from the finding's context.
"""
from __future__ import annotations

import math
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# CVSS 3.1 base-score calculator
# --------------------------------------------------------------------------- #
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed

_SEVERITY_BANDS = [
    (0.0, 0.0, "none"),
    (0.1, 3.9, "low"),
    (4.0, 6.9, "medium"),
    (7.0, 8.9, "high"),
    (9.0, 10.0, "critical"),
]


def _roundup(x: float) -> float:
    # CVSS 3.1 roundup: smallest number, to 1 decimal, that is >= x.
    return math.ceil(round(x, 5) * 10) / 10.0


def cvss_base(vector: str) -> Tuple[float, str]:
    """Compute (base_score, severity) from a CVSS 3.1 vector string.

    Accepts a full ``CVSS:3.1/AV:N/...`` string or just the metric part.
    Falls back gracefully to (0.0, "none") on a malformed vector.
    """
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip().upper()] = v.strip().upper()
    try:
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        scope_changed = metrics.get("S", "U") == "C"
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return 0.0, "none"

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    return score, severity_for(score)


def severity_for(score: float) -> str:
    for lo, hi, label in _SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    return "none"


# --------------------------------------------------------------------------- #
# vulnerability catalog: category -> rating template
# --------------------------------------------------------------------------- #
class VulnClass:
    def __init__(self, name, cwe, cvss, remediation, submittable, confidence="confirmed"):
        self.name = name
        self.cwe = cwe
        self.cvss = cvss
        self.remediation = remediation
        self.submittable = submittable
        self.confidence = confidence


_P = "CVSS:3.1/"
CATALOG: Dict[str, VulnClass] = {
    "sqli": VulnClass("SQL Injection", "CWE-89", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H",
                      "Use parameterised queries / prepared statements; never concatenate untrusted input into SQL. Apply least-privilege DB accounts.", True),
    "cmdi": VulnClass("OS Command Injection", "CWE-78", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H",
                      "Avoid shelling out with user input; use safe APIs and strict allow-lists. Never pass untrusted data to a shell.", True),
    "ssti": VulnClass("Server-Side Template Injection", "CWE-1336", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H",
                      "Do not render user input as a template. Use a logic-less/sandboxed engine and pass data as bound variables.", True),
    "lfi": VulnClass("Local File Inclusion / Path Traversal", "CWE-22", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
                     "Resolve and canonicalise paths against an allow-list; reject traversal sequences and absolute paths; avoid passing user input to file APIs.", True),
    "ssrf": VulnClass("Server-Side Request Forgery", "CWE-918", _P + "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                      "Validate/allow-list outbound targets, block internal ranges and cloud metadata (169.254.169.254), disable unused URL schemes.", True),
    "xss": VulnClass("Reflected Cross-Site Scripting", "CWE-79", _P + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                     "Context-aware output encoding; a strict CSP; treat all user input as untrusted in every sink.", True),
    "open-redirect": VulnClass("Open Redirect", "CWE-601", _P + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
                               "Redirect only to an allow-list of internal paths/hosts; never trust a user-supplied absolute URL.", True),
    "git-exposure": VulnClass("Exposed .git Repository", "CWE-538", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
                              "Block access to VCS metadata (.git/.svn/.hg) at the web server; never deploy the repo working tree to webroot.", True),
    "env-exposure": VulnClass("Exposed Environment/Secret File", "CWE-538", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
                              "Move secrets out of webroot; deny dotfiles/backup files at the server; rotate any leaked credentials immediately.", True),
    "secret-exposure": VulnClass("Sensitive File Exposure", "CWE-200", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
                                 "Remove backup/config files from webroot and deny access to sensitive paths; rotate any leaked secrets.", True),
    "secret-leak": VulnClass("Secret Leaked in Web Content", "CWE-540", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
                             "Remove hard-coded secrets from client-side code; rotate the exposed key; load secrets server-side only.", True),
    "cors": VulnClass("CORS Misconfiguration", "CWE-942", _P + "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
                      "Reflect only an allow-list of trusted origins; never combine a wildcard/echoed Origin with Access-Control-Allow-Credentials: true.", True),
    "jwt-alg-none": VulnClass("JWT alg=none Accepted", "CWE-347", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:N",
                              "Reject the 'none' algorithm; pin the expected algorithm server-side and verify signatures.", True),
    "jwt-weak-secret": VulnClass("JWT Weak HMAC Secret", "CWE-347", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:N",
                                 "Use a long, random HMAC secret (or asymmetric keys); rotate the compromised secret.", True),
    "default-cred": VulnClass("Default Credentials", "CWE-1392", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H",
                              "Change all default credentials; enforce a strong-password policy.", True),
    "graphql-introspection": VulnClass("GraphQL Introspection Enabled", "CWE-200", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:L/I:N/A:N",
                                       "Disable introspection in production; enforce authorization on all resolvers.", False, "firm"),
    "hidden-param": VulnClass("Hidden Parameter", "CWE-200", _P + "AV:N/AC:L/PR:N/UI:N/S:N/C:L/I:N/A:N",
                              "Review the undocumented parameter for unintended functionality/authorization gaps.", False, "tentative"),
    "missing-header": VulnClass("Missing Security Header", "CWE-693", _P + "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                                "Add the missing header (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).", False, "firm"),
    "waf": VulnClass("WAF/CDN Present (informational)", "CWE-200", _P + "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                     "Informational: active testing may require evasion.", False, "firm"),
    "info": VulnClass("Informational Finding", "CWE-200", _P + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                      "Review for information disclosure.", False, "tentative"),
}

# title-substring -> category (checked in order; first match wins)
_CLASSIFY_RULES: List[Tuple[str, str]] = [
    ("sql injection", "sqli"),
    ("command injection", "cmdi"),
    ("template injection", "ssti"),
    ("ssti", "ssti"),
    ("local file inclusion", "lfi"),
    ("path traversal", "lfi"),
    ("file inclusion", "lfi"),
    (".git", "git-exposure"),
    ("git repository", "git-exposure"),
    (".env", "env-exposure"),
    ("environment", "env-exposure"),
    ("secret in web content", "secret-leak"),
    ("secret exposed", "secret-leak"),
    ("sensitive file", "secret-exposure"),
    ("exposed", "secret-exposure"),
    ("server-side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("cross-site scripting", "xss"),
    ("xss", "xss"),
    ("open redirect", "open-redirect"),
    ("cors", "cors"),
    ("jwt", "jwt-alg-none"),  # refined below by keyword
    ("default credential", "default-cred"),
    ("graphql introspection", "graphql-introspection"),
    ("graphql", "graphql-introspection"),
    ("hidden parameter", "hidden-param"),
    ("security header", "missing-header"),
    ("header", "missing-header"),
    ("waf", "waf"),
    ("zone transfer", "info"),
]


def classify(title: str) -> str:
    """Map a finding title to a catalog category slug."""
    t = (title or "").lower()
    if "jwt" in t:
        if "secret" in t or "cracked" in t or "brute" in t:
            return "jwt-weak-secret"
        if "none" in t:
            return "jwt-alg-none"
        return "jwt-alg-none"
    for needle, cat in _CLASSIFY_RULES:
        if needle in t:
            return cat
    return "info"


def rate(category: str) -> Dict[str, object]:
    """Return a rating dict for a category (cvss vector/score/severity, cwe, ...)."""
    vc = CATALOG.get(category, CATALOG["info"])
    score, severity = cvss_base(vc.cvss)
    return {
        "category": category,
        "name": vc.name,
        "cwe": vc.cwe,
        "cvss_vector": vc.cvss,
        "cvss_score": score,
        "cvss_severity": severity,
        "remediation": vc.remediation,
        "submittable": vc.submittable,
        "confidence": vc.confidence,
    }


# --------------------------------------------------------------------------- #
# PoC reconstruction
# --------------------------------------------------------------------------- #
# canonical payloads per category when the exact one is not embedded in evidence
_CANON_PAYLOAD = {
    "sqli": "' OR '1'='1'-- -",
    "cmdi": ";id",
    "ssti": "{{7*7}}",
    "lfi": "../../../../etc/passwd",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "xss": "<script>alert(document.domain)</script>",
    "open-redirect": "//evil.example",
}


def _inject_param(url: str, param: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    found = False
    new_qs = []
    for k, v in qs:
        if k == param:
            new_qs.append((k, payload))
            found = True
        else:
            new_qs.append((k, v))
    if not found:
        new_qs.append((param, payload))
    query = urllib.parse.urlencode(new_qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def extract_param(evidence: str, description: str) -> Optional[str]:
    text = f"{evidence or ''} {description or ''}"
    m = re.search(r"param(?:eter)?[=\s'\"]+([A-Za-z0-9_.\[\]-]+)", text)
    return m.group(1) if m else None


def extract_payload(evidence: str) -> Optional[str]:
    # capture up to a following " key=" token (evidence often chains
    # "payload=X signals=[...]") or end of line
    m = re.search(r"payload[=:]\s*'?(.+?)'?(?:\s+[a-z_]+=|\s*[|\n]|\s*$)", evidence or "", re.I)
    return m.group(1).strip() if m else None


def build_poc(category: str, url: str, evidence: str = "", description: str = "",
              cookie: str = "", proxy: str = "", method: str = "GET",
              data: str = "") -> Dict[str, str]:
    """Reconstruct a runnable PoC (curl + raw request) for a finding.

    Best-effort: uses the exact param/payload when present in the evidence,
    otherwise a canonical payload for the class aimed at the finding's URL.
    """
    param = extract_param(evidence, description)
    payload = extract_payload(evidence) or _CANON_PAYLOAD.get(category)

    target = url
    note = ""
    if category in ("sqli", "cmdi", "ssti", "lfi", "ssrf", "xss", "open-redirect") and param and payload:
        target = _inject_param(url, param, payload)
        note = f"inject into parameter '{param}'"
    elif category in _CANON_PAYLOAD and payload and "?" in url:
        # unknown param: hit the first query param
        first = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)
        if first:
            target = _inject_param(url, first[0][0], payload)
            note = f"inject into parameter '{first[0][0]}'"

    if category in ("git-exposure", "env-exposure", "secret-exposure", "secret-leak"):
        m = re.search(r"https?://[^\s'\"|]+", evidence or "")
        file_url = m.group(0) if m else url
        curl = f"curl -sk {_q(file_url)}" + _extra(cookie, proxy)
        return {"curl": curl, "request": _raw("GET", file_url, {}, cookie),
                "note": "fetch the exposed file directly"}

    if category == "cors":
        curl = f"curl -sk -i -H 'Origin: https://evil.example' {_q(url)}" + _extra(cookie, proxy)
        note = "check Access-Control-Allow-Origin reflects the attacker Origin with credentials"
        return {"curl": curl, "request": _raw("GET", url, {"Origin": "https://evil.example"}, cookie), "note": note}

    if category == "graphql-introspection":
        body = '{"query":"{__schema{types{name}}}"}'
        curl = (f"curl -sk -X POST -H 'Content-Type: application/json' "
                f"--data '{body}' {_q(url)}" + _extra(cookie, proxy))
        return {"curl": curl, "request": _raw("POST", url, {"Content-Type": "application/json"}, cookie, body),
                "note": "introspection returns the full schema"}

    if method.upper() == "POST" or data:
        curl = f"curl -sk -X POST --data {_q(data or '')} {_q(target)}" + _extra(cookie, proxy)
        return {"curl": curl, "request": _raw("POST", target, {}, cookie, data), "note": note}

    curl = f"curl -sk {_q(target)}" + _extra(cookie, proxy)
    return {"curl": curl, "request": _raw("GET", target, {}, cookie), "note": note}


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


def _extra(cookie: str, proxy: str) -> str:
    out = ""
    if cookie:
        out += f" -H {_q('Cookie: ' + cookie)}"
    if proxy:
        out += f" -x {_q(proxy)}"
    return out


def _raw(method: str, url: str, headers: Dict[str, str], cookie: str = "", body: str = "") -> str:
    parts = urllib.parse.urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append(body)
    else:
        lines.append("")
    return "\n".join(lines)


def enrich_finding(finding: Dict[str, object], cookie: str = "", proxy: str = "",
                   target_url: str = "", method: str = "GET", data: str = "") -> Dict[str, object]:
    """Attach rating + PoC to a finding dict in place, returning it.

    Respects a stored 'category'/'confidence' if the producing module set one.
    """
    category = str(finding.get("category") or classify(str(finding.get("title", ""))))
    r = rate(category)
    url = target_url or _url_from_evidence(finding) or ""
    poc = build_poc(category, url, str(finding.get("evidence") or ""),
                    str(finding.get("description") or ""), cookie, proxy, method, data) if url else {}

    confidence = str(finding.get("confidence") or r["confidence"])
    # an explicitly low-confidence heuristic is never auto-submittable
    if "low-confidence" in str(finding.get("title", "")).lower():
        confidence = "tentative"

    finding["category"] = category
    finding["cwe"] = finding.get("cwe") or r["cwe"]
    finding["cvss_vector"] = finding.get("cvss_vector") or r["cvss_vector"]
    finding["cvss_score"] = finding.get("cvss_score") or r["cvss_score"]
    finding["cvss_severity"] = r["cvss_severity"]
    finding["remediation"] = finding.get("remediation") or r["remediation"]
    finding["confidence"] = confidence
    finding["submittable"] = bool(r["submittable"]) and confidence in ("confirmed", "firm")
    if poc:
        finding["poc"] = poc
    return finding


def _url_from_evidence(finding: Dict[str, object]) -> Optional[str]:
    for field in ("evidence", "description"):
        m = re.search(r"https?://[^\s'\"|]+", str(finding.get(field) or ""))
        if m:
            return m.group(0)
    return None
