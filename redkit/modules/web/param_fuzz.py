"""Hidden HTTP parameter discovery (arjun-style differential fuzzing).

Probes a target URL with buckets of candidate GET/POST parameter names -
each set to a unique per-run canary value - and compares the response
against a baseline to detect parameters the application silently accepts
(status change, meaningful body-length/word-count shift, or canary
reflection). A bucket that shifts the response is recursively binary-split
until the exact accepted parameter(s) are isolated, keeping the total
request count small even against large wordlists.

Design constraints (redkit invariants):
    * NO AI/LLM usage - every decision here is a deterministic rule based on
      response deltas against a measured baseline.
    * Pure standard library. All HTTP goes through the shared
      ``redkit.core.http`` client so proxying, cookies, auth headers, and
      TLS handling stay consistent with every other web module.
    * Imports and runs on both Windows and Linux (no OS-specific calls).
    * Offline-first: candidate parameter names come from the bundled
      wordlist (or an operator-supplied path); nothing is ever downloaded.
    * Safe and bounded: favours GET by default, caps the thread pool,
      and enforces a hard ceiling on the total number of HTTP requests
      issued during a single run regardless of wordlist size or options.
"""
from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlparse

from redkit.core import config
from redkit.core.http import WEB_COMMON_OPTIONS, HttpClient, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# bounds - hard invariants, not operator-configurable
# --------------------------------------------------------------------------- #
MAX_THREADS = 20                # hard cap on concurrent workers
MAX_CANDIDATES = 1000           # hard cap on candidate parameter names considered
MAX_BUCKET = 100                # hard cap on how many params ride in one request
MAX_REQUESTS = 600              # hard cap on total HTTP requests issued per run
MIN_TOLERANCE_BYTES = 25        # floor for the "noise" byte-length tolerance
LENGTH_TOLERANCE_RATIO = 0.03   # +/- 3% of baseline length is treated as noise
WORD_TOLERANCE = 4              # +/- word-count noise allowance
EXHAUSTIVE_LEAF = 4             # bucket size at which we stop halving and just
                                 # test every remaining candidate individually


@dataclass
class Baseline:
    """Reference response characteristics used to detect a shift."""

    status: int
    length: int
    words: int
    canary_reflects: bool
    tolerance_bytes: int


class _Budget:
    """Thread-safe counter enforcing the overall per-run request cap."""

    def __init__(self, cap: int):
        self.cap = cap
        self.used = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        """Reserve one request slot; ``False`` if the budget is exhausted."""
        with self._lock:
            if self.used >= self.cap:
                return False
            self.used += 1
            return True

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.cap - self.used)


def _word_count(text: str) -> int:
    return len(text.split())


def _canary() -> str:
    """A short, unique, unlikely-to-collide token for this probe."""
    return "rk" + uuid.uuid4().hex[:16]


def _load_words(path: Path) -> List[str]:
    """Read a newline-delimited wordlist, skipping blanks/comments, deduped."""
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


def _resolve_wordlist(name: str, ctx) -> List[str]:
    """Resolve a bundled wordlist name or an operator-supplied path.

    Returns ``[]`` (and warns via the console) rather than raising when
    nothing usable is found, so the module degrades gracefully.
    """
    name = (name or "").strip() or "params-common.txt"
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
                    return words
        except OSError:
            continue
    ctx.console.warn(
        f"wordlist '{name}' not found (looked in cwd and bundled data); nothing to fuzz"
    )
    return []


def _send(client: HttpClient, url: str, method: str, params: Dict[str, str]) -> Response:
    if method == "POST":
        return client.post(url, data=params)
    return client.get(url, params=params)


def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    return raw


@register
class ParamFuzz(Module):
    """Discover hidden/unlinked HTTP GET or POST parameters."""

    name = "web.param_fuzz"
    description = "Discover hidden HTTP parameters via differential response fuzzing (arjun-style)"
    phase = "web"
    options = [
        Option("url", help="target URL", required=True),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method to fuzz"),
        Option(
            "wordlist",
            default="params-common.txt",
            help="bundled wordlist name or path to a list of candidate parameter names",
        ),
        Option("bucket", default=25, help=f"candidate params probed per request (capped at {MAX_BUCKET})"),
        Option("threads", default=10, help=f"concurrent worker threads (capped at {MAX_THREADS})"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://github.com/s0md3v/Arjun",
        "https://owasp.org/www-project-web-security-testing-guide/latest/"
        "4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, object], ctx) -> Result:  # noqa: C901 - linear pipeline
        console = ctx.console
        url = _normalize_url(str(opts["url"]))
        method = str(opts.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        parsed = urlparse(url)
        host = parsed.hostname or str(opts["url"])

        empty_data = {"params": [], "candidates_tested": 0, "requests_used": 0}
        if not parsed.scheme or not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r}", data=empty_data)

        bucket_size = max(1, min(int(opts["bucket"]), MAX_BUCKET))
        threads = max(1, min(int(opts["threads"]), MAX_THREADS))

        words = _resolve_wordlist(str(opts["wordlist"]), ctx)
        if not words:
            return Result(ok=False, summary="no candidate parameter names available (empty/missing wordlist)", data=empty_data)
        truncated = len(words) > MAX_CANDIDATES
        words = words[:MAX_CANDIDATES]

        client = client_from_opts(opts)
        budget = _Budget(MAX_REQUESTS)

        console.info(
            f"param_fuzz {method} {url}  ({len(words)} candidates"
            f"{' (truncated)' if truncated else ''}, bucket={bucket_size}, "
            f"threads={threads}, request cap={MAX_REQUESTS})"
        )

        # -- baseline --------------------------------------------------------- #
        budget.take()
        base_resp = _send(client, url, method, {})
        if base_resp.error:
            console.bad(f"target unreachable: {base_resp.error}")
            return Result(ok=False, summary=f"{url} unreachable: {base_resp.error}", data=empty_data)

        canary_name = _canary()
        canary_val = _canary()
        budget.take()
        canary_resp = _send(client, url, method, {canary_name: canary_val})
        canary_reflects = (not canary_resp.error) and canary_val in canary_resp.text

        tolerance = max(MIN_TOLERANCE_BYTES, int(base_resp.length * LENGTH_TOLERANCE_RATIO))
        baseline = Baseline(
            status=base_resp.status,
            length=base_resp.length,
            words=_word_count(base_resp.text),
            canary_reflects=canary_reflects,
            tolerance_bytes=tolerance,
        )
        console.debug(
            f"baseline status={baseline.status} length={baseline.length} words={baseline.words} "
            f"canary_reflects={baseline.canary_reflects} tolerance={tolerance}B"
        )
        if baseline.canary_reflects:
            console.debug("baseline reflects arbitrary unknown parameter values; canary-reflection signal disabled")

        # -- assign each candidate its own unique canary ---------------------- #
        canaries: Dict[str, str] = {name: _canary() for name in words}

        def shift_reason(resp: Response, tested_canaries: Sequence[str]) -> Optional[str]:
            """Return a human-readable reason the response differs, or None."""
            if resp.error:
                return None  # transport failure/timeout: no signal, not a crash
            if resp.status != baseline.status:
                return f"status {baseline.status}->{resp.status}"
            delta = resp.length - baseline.length
            if abs(delta) > baseline.tolerance_bytes:
                return f"length delta {delta:+d}B"
            if not baseline.canary_reflects:
                for cval in tested_canaries:
                    if cval and cval in resp.text:
                        return "canary value reflected in response"
            word_delta = _word_count(resp.text) - baseline.words
            if abs(word_delta) > WORD_TOLERANCE:
                return f"word-count delta {word_delta:+d}"
            return None

        def probe(names: Sequence[str]) -> Optional[str]:
            """Send one request carrying `names` (each with its own canary)."""
            if not names or not budget.take():
                return None
            params = {n: canaries[n] for n in names}
            resp = _send(client, url, method, params)
            return shift_reason(resp, list(params.values()))

        confirmed: Dict[str, str] = {}
        confirmed_lock = threading.Lock()

        def isolate(names: Sequence[str]) -> None:
            """Recursively binary-split a shifted set until exact param(s) found.

            Once a group shrinks to ``EXHAUSTIVE_LEAF`` or fewer candidates it
            is cheaper (and more resilient to param-interaction effects) to
            just confirm each one individually than to keep halving.
            """
            if not names or budget.remaining <= 0:
                return
            if len(names) <= EXHAUSTIVE_LEAF:
                for n in names:
                    if budget.remaining <= 0:
                        return
                    reason = probe([n])
                    if reason:
                        with confirmed_lock:
                            confirmed[n] = reason
                return
            mid = len(names) // 2
            for half in (names[:mid], names[mid:]):
                if not half or budget.remaining <= 0:
                    continue
                reason = probe(half)
                if reason:
                    isolate(half)

        # -- first pass: scan buckets in parallel ----------------------------- #
        buckets = [words[i : i + bucket_size] for i in range(0, len(words), bucket_size)]
        shifted_buckets: List[List[str]] = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            future_map = {}
            for b in buckets:
                if budget.remaining <= 0:
                    break
                future_map[pool.submit(probe, b)] = b
            for fut in as_completed(future_map):
                b = future_map[fut]
                try:
                    reason = fut.result()
                except Exception:  # noqa: BLE001 - a probe must never abort the run
                    reason = None
                if reason:
                    shifted_buckets.append(b)

        if budget.remaining <= 0:
            console.warn(f"request budget ({MAX_REQUESTS}) exhausted during bucket scan; results may be partial")

        # -- second pass: binary-split each shifted bucket -------------------- #
        if shifted_buckets and budget.remaining > 0:
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = [pool.submit(isolate, b) for b in shifted_buckets]
                for fut in as_completed(futures):
                    fut.result()  # propagate unexpected exceptions to the log, not silently lost

        # -- record findings --------------------------------------------------- #
        for pname, reason in sorted(confirmed.items()):
            ctx.engagement.add_loot(host, "hidden-param", pname, source=url)
            ctx.engagement.add_finding(
                "Hidden parameter discovered",
                severity="low",
                host=host,
                description=(
                    f"Parameter '{pname}' altered the {method} response from {url} ({reason})."
                ),
                evidence=url,
            )
        if confirmed:
            console.good(f"{len(confirmed)} hidden parameter(s) discovered")
            console.table(
                ["parameter", "reason"],
                [[n, confirmed[n]] for n in sorted(confirmed)],
            )
        else:
            console.info("no hidden parameters detected")

        data = {
            "url": url,
            "method": method,
            "candidates_tested": len(words),
            "requests_used": budget.used,
            "request_cap": MAX_REQUESTS,
            "baseline": {
                "status": baseline.status,
                "length": baseline.length,
                "words": baseline.words,
                "canary_reflects": baseline.canary_reflects,
            },
            "params": sorted(confirmed.keys()),
            "details": [{"name": n, "reason": confirmed[n]} for n in sorted(confirmed)],
        }

        artifacts: List[str] = []
        try:
            out_path = ctx.artifact_path(f"param_fuzz_{(host or 'target').replace(':', '_')}.json")
            out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(out_path))
        except OSError:
            pass

        summary = (
            f"{url}: {len(confirmed)} hidden parameter(s) found out of {len(words)} candidates "
            f"tested ({budget.used} requests)"
        )
        ctx.engagement.add_note(f"param_fuzz: {summary}")
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)
