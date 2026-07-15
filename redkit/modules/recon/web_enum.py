"""HTTP(S) enumeration module.

Fingerprints a web target, audits its response security headers, harvests
paths from ``robots.txt`` / ``sitemap.xml``, and performs a threaded directory
brute-force using a bundled wordlist.

Design constraints (redkit invariants):
    * NO AI/LLM usage - every decision here is a deterministic rule.
    * Pure standard library by default (``urllib``). ``requests`` is used as an
      optional fast-path only when importable; the module works without it.
    * Imports and runs on both Windows and Linux (no OS-specific calls).
    * Offline-first: the wordlist is read from the bundled data directory.
    * Safe defaults: bounded timeouts, a capped thread pool, unverified TLS is
      tolerated (self-signed lab targets) but redirects are never followed into
      a different host.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register
from redkit.core import config

# Optional fast-path. MUST degrade gracefully when absent.
try:  # pragma: no cover - availability depends on the host
    import requests as _requests  # type: ignore

    try:
        # Silence noisy warnings for intentionally-unverified TLS.
        from urllib3.exceptions import InsecureRequestWarning  # type: ignore

        _requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - best effort only
        pass
except Exception:  # noqa: BLE001 - ImportError or a broken install
    _requests = None  # type: ignore


# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
USER_AGENT = "redkit-web-enum/1.0 (+authorized-testing)"
_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "Connection": "close",
}
MAX_BODY = 131072          # cap body reads to protect memory / bandwidth
MAX_THREADS = 100          # hard cap enforced by redkit invariants
REDIRECT_CODES = (301, 302, 303, 307, 308)

# Response security headers we expect a hardened server to send.
SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "low"),
    "strict-transport-security": ("Strict-Transport-Security (HSTS)", "low"),
    "x-frame-options": ("X-Frame-Options", "low"),
    "x-content-type-options": ("X-Content-Type-Options", "info"),
}

# Paths that warrant an elevated finding if they respond at all.
SENSITIVE_PATHS = {
    ".git", ".git/config", ".git/head", ".env", ".env.local",
    "config.php", "wp-config.php", "web.config", ".htpasswd", ".htaccess",
    "backup", "backup.zip", "backup.sql", "dump.sql", "db.sql",
    "phpinfo.php", "server-status", "server-info", "id_rsa", ".ssh",
    "docker-compose.yml", ".aws/credentials", "credentials", ".svn",
}

# Deterministic header/body -> technology signatures.
_HEADER_TECH = [
    ("server", re.compile(r"nginx", re.I), "nginx"),
    ("server", re.compile(r"apache", re.I), "Apache"),
    ("server", re.compile(r"microsoft-iis", re.I), "IIS"),
    ("server", re.compile(r"litespeed", re.I), "LiteSpeed"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("server", re.compile(r"gunicorn", re.I), "Gunicorn"),
    ("server", re.compile(r"werkzeug", re.I), "Werkzeug/Flask"),
    ("x-powered-by", re.compile(r"php", re.I), "PHP"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("x-powered-by", re.compile(r"express", re.I), "Express"),
    ("x-powered-by", re.compile(r"next\.js", re.I), "Next.js"),
    ("x-aspnet-version", re.compile(r".+"), "ASP.NET"),
    ("x-drupal-cache", re.compile(r".+"), "Drupal"),
    ("x-generator", re.compile(r"drupal", re.I), "Drupal"),
]

_COOKIE_TECH = [
    (re.compile(r"phpsessid", re.I), "PHP"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
    (re.compile(r"ci_session", re.I), "CodeIgniter"),
    (re.compile(r"jsessionid", re.I), "Java"),
    (re.compile(r"asp\.net_sessionid|aspxauth", re.I), "ASP.NET"),
    (re.compile(r"connect\.sid", re.I), "Express"),
    (re.compile(r"csrftoken|django", re.I), "Django"),
    (re.compile(r"wordpress_|wp-settings", re.I), "WordPress"),
]

_BODY_TECH = [
    (re.compile(r"/wp-(content|includes)/|wp-json", re.I), "WordPress"),
    (re.compile(r"Drupal\.settings|/sites/default/files", re.I), "Drupal"),
    (re.compile(r"/media/jui/|joomla", re.I), "Joomla"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=|ng-app", re.I), "Angular"),
    (re.compile(r"data-reactroot|react(?:-dom)?\.production", re.I), "React"),
    (re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{8}", re.I), "Vue.js"),
    (re.compile(r"jquery[.-]", re.I), "jQuery"),
    (re.compile(r"bootstrap(?:\.min)?\.(?:js|css)", re.I), "Bootstrap"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"laravel", re.I), "Laravel"),
]

_META_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I
)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


# --------------------------------------------------------------------------- #
# low-level HTTP response holder
# --------------------------------------------------------------------------- #
@dataclass
class _Resp:
    """Normalized HTTP response, shared across the urllib / requests paths."""

    status: Optional[int]
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""            # concatenation of every Set-Cookie value
    body: bytes = b""
    url: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error is None


class _Client:
    """Tiny HTTP client that does NOT auto-follow redirects.

    Uses ``requests`` when available (faster connection reuse), otherwise a
    stdlib ``urllib`` opener configured with an unverified TLS context and a
    redirect handler that surfaces 3xx responses instead of chasing them.
    """

    def __init__(self, timeout: float):
        self.timeout = float(timeout)
        self._session = None
        self._opener = None
        if _requests is not None:
            self._session = _requests.Session()
            self._session.headers.update(_HEADERS)
        else:
            ctx = ssl._create_unverified_context()
            self._opener = urllib.request.build_opener(
                _NoRedirect(),
                urllib.request.HTTPSHandler(context=ctx),
            )

    # -- single request, no redirect following ---------------------------- #
    def raw_get(self, url: str) -> _Resp:
        if self._session is not None:
            return self._raw_get_requests(url)
        return self._raw_get_urllib(url)

    def _raw_get_requests(self, url: str) -> _Resp:
        try:
            resp = self._session.get(  # type: ignore[union-attr]
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
                stream=True,
            )
            try:
                body = resp.raw.read(MAX_BODY, decode_content=True) or b""
            except Exception:  # noqa: BLE001 - body is best effort
                body = resp.content[:MAX_BODY]
            finally:
                resp.close()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookie = resp.headers.get("set-cookie", "") or ""
            return _Resp(resp.status_code, headers, cookie, body, url, None)
        except Exception as exc:  # noqa: BLE001 - network failures are expected
            return _Resp(None, {}, "", b"", url, _short_err(exc))

    def _raw_get_urllib(self, url: str) -> _Resp:
        req = urllib.request.Request(url, headers=dict(_HEADERS), method="GET")
        try:
            resp = self._opener.open(req, timeout=self.timeout)  # type: ignore[union-attr]
            return self._from_urllib(resp, url)
        except urllib.error.HTTPError as exc:  # 3xx (no-follow) and 4xx/5xx
            return self._from_urllib(exc, url)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            return _Resp(None, {}, "", b"", url, _short_err(exc))
        except Exception as exc:  # noqa: BLE001 - never let a probe crash the run
            return _Resp(None, {}, "", b"", url, _short_err(exc))

    @staticmethod
    def _from_urllib(resp, url: str) -> _Resp:
        try:
            body = resp.read(MAX_BODY)
        except Exception:  # noqa: BLE001
            body = b""
        headers = {}
        cookie = ""
        hdrs = getattr(resp, "headers", None)
        if hdrs is not None:
            for key, value in hdrs.items():
                headers[key.lower()] = value
            try:
                cookie = "; ".join(hdrs.get_all("set-cookie") or [])
            except Exception:  # noqa: BLE001
                cookie = headers.get("set-cookie", "")
        status = getattr(resp, "status", None) or getattr(resp, "code", None)
        return _Resp(status, headers, cookie, body, url, None)

    # -- request with same-host redirect following ------------------------ #
    def get_follow(self, url: str, base_host: str, max_hops: int = 4) -> _Resp:
        """Fetch ``url`` following redirects only while they stay on ``base_host``.

        A cross-host redirect is returned as-is (the 3xx response) rather than
        followed, so we never wander off the authorized target.
        """
        seen = set()
        current = url
        resp = self.raw_get(current)
        for _ in range(max_hops):
            if not resp.ok or resp.status not in REDIRECT_CODES:
                return resp
            location = resp.headers.get("location")
            if not location:
                return resp
            nxt = urllib.parse.urljoin(current, location)
            host = urllib.parse.urlsplit(nxt).netloc.lower()
            if host != base_host or nxt in seen:
                return resp  # off-host or loop -> stop, keep the redirect resp
            seen.add(nxt)
            current = nxt
            resp = self.raw_get(current)
        return resp


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow, surfacing 3xx as HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _short_err(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    return text[:200]


# --------------------------------------------------------------------------- #
# fingerprinting helpers (pure, deterministic)
# --------------------------------------------------------------------------- #
def _fingerprint(resp: _Resp) -> List[str]:
    """Derive a technology list from headers, cookies, and body signatures."""
    found: List[str] = []

    def add(tech: str) -> None:
        if tech and tech not in found:
            found.append(tech)

    for header, pattern, tech in _HEADER_TECH:
        value = resp.headers.get(header)
        if value and pattern.search(value):
            add(tech)

    if resp.cookies:
        for pattern, tech in _COOKIE_TECH:
            if pattern.search(resp.cookies):
                add(tech)

    text = resp.body.decode("utf-8", "replace") if resp.body else ""
    if text:
        for pattern, tech in _BODY_TECH:
            if pattern.search(text):
                add(tech)
        meta = _META_GENERATOR.search(text)
        if meta:
            add(f"generator:{meta.group(1).strip()[:60]}")

    return found


def _audit_security_headers(resp: _Resp, is_https: bool) -> List[Tuple[str, str, str]]:
    """Return (header_key, pretty_name, severity) for each missing header."""
    missing: List[Tuple[str, str, str]] = []
    for key, (pretty, severity) in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and not is_https:
            continue  # HSTS is meaningless over plain HTTP
        if key not in resp.headers:
            missing.append((key, pretty, severity))
    return missing


def _extract_robots(text: str) -> List[str]:
    """Pull Disallow/Allow paths and Sitemap URLs out of a robots.txt body."""
    paths: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith(("disallow:", "allow:")):
            value = line.split(":", 1)[1].strip()
            if value and value != "/":
                paths.append(value)
        elif low.startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value:
                paths.append(value)
    # de-dupe preserving order
    seen: set = set()
    return [p for p in paths if not (p in seen or seen.add(p))]


def _extract_sitemap(text: str, base_host: str) -> List[str]:
    """Extract <loc> paths from sitemap.xml, keeping only same-host entries."""
    out: List[str] = []
    seen: set = set()
    for match in _LOC_RE.findall(text):
        parts = urllib.parse.urlsplit(match)
        if parts.netloc and parts.netloc.lower() != base_host:
            continue  # ignore cross-host sitemap entries
        path = parts.path or match
        if path and path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _load_words(path) -> List[str]:
    """Read a wordlist, skipping blanks and comments. Tolerant of encodings."""
    words: List[str] = []
    seen: set = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip()
                if not word or word.startswith("#"):
                    continue
                word = word.lstrip("/")
                if word and word not in seen:
                    seen.add(word)
                    words.append(word)
    except OSError:
        return []
    return words


def _split_csv(value: str) -> List[str]:
    return [part.strip() for part in str(value).split(",") if part.strip()]


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class WebEnum(Module):
    """Enumerate a web server: fingerprint, header audit, and content brute."""

    name = "recon.web_enum"
    description = "HTTP(S) fingerprint, security-header audit, and directory brute-force"
    phase = "recon"
    requires_tools: List[str] = []  # pure stdlib; requests is only a soft speed-up
    options = [
        Option("url", help="base URL, e.g. http://host or https://host:8443", required=True),
        Option("wordlist", default="dirs-common.txt", help="bundled wordlist name or absolute path"),
        Option("threads", default=20, help="concurrent brute workers (capped at 100)"),
        Option("timeout", default=5, help="per-request timeout in seconds"),
        Option("ext", default="", help="comma list of extensions to append, e.g. php,txt"),
        Option(
            "codes",
            default="200,204,301,302,307,401,403",
            help="comma list of status codes treated as interesting hits",
        ),
    ]
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, object], ctx) -> Result:  # noqa: C901 - linear pipeline
        console = ctx.console

        base, base_host, host_only, port, is_https = _parse_url(str(opts["url"]))
        if not base_host:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r} (expected http(s)://host)")

        timeout = max(1, int(opts["timeout"]))
        threads = max(1, min(int(opts["threads"]), MAX_THREADS))
        interesting = self._parse_codes(str(opts["codes"]))
        exts = [e.lstrip(".") for e in _split_csv(str(opts["ext"]))]

        client = _Client(timeout=timeout)
        backend = "requests" if _requests is not None else "urllib"
        console.info(f"web enum {base}  (via {backend}, {threads} threads, {timeout}s timeout)")

        data: Dict[str, object] = {
            "url": base,
            "host": host_only,
            "port": port,
            "https": is_https,
            "backend": backend,
            "reachable": False,
            "status": None,
            "server": None,
            "powered_by": None,
            "technologies": [],
            "missing_security_headers": [],
            "robots_paths": [],
            "sitemap_paths": [],
            "discovered": [],
        }

        # persist the host + web service early so later modules see it
        ctx.engagement.add_host(host_only)

        # -- step 1: base fetch + fingerprint + header audit -------------- #
        base_resp = client.get_follow(base, base_host)
        if not base_resp.ok:
            console.warn(f"base URL not reachable: {base_resp.error}")
            ctx.engagement.add_note(f"web_enum: {base} unreachable ({base_resp.error})")
            return Result(
                ok=False,
                summary=f"{base} unreachable: {base_resp.error}",
                data=data,
            )

        data["reachable"] = True
        data["status"] = base_resp.status
        server = base_resp.headers.get("server")
        powered = base_resp.headers.get("x-powered-by")
        data["server"] = server
        data["powered_by"] = powered
        techs = _fingerprint(base_resp)
        data["technologies"] = techs

        ctx.engagement.add_service(
            host_only,
            port,
            proto="tcp",
            service="https" if is_https else "http",
            product=server or None,
            banner=(f"HTTP {base_resp.status} {server or ''}").strip(),
        )
        console.good(f"HTTP {base_resp.status}  server={server or '?'}  tech={', '.join(techs) or 'n/a'}")
        if server or powered or techs:
            fp_desc = f"Server: {server or 'n/a'}; X-Powered-By: {powered or 'n/a'}; tech: {', '.join(techs) or 'n/a'}"
            ctx.engagement.add_finding(
                "Web server fingerprint",
                severity="info",
                host=host_only,
                description=fp_desc,
                evidence=base,
            )

        missing = _audit_security_headers(base_resp, is_https)
        data["missing_security_headers"] = [pretty for _, pretty, _ in missing]
        for _key, pretty, severity in missing:
            ctx.engagement.add_finding(
                f"Missing security header: {pretty}",
                severity=severity,
                host=host_only,
                description=f"Response from {base} does not set the {pretty} header.",
                evidence=base,
            )
        if missing:
            console.warn(f"missing security headers: {', '.join(p for _, p, _ in missing)}")

        # -- step 2: robots.txt + sitemap.xml ----------------------------- #
        robots_paths = self._harvest_robots(client, base, base_host, host_only, ctx)
        sitemap_paths = self._harvest_sitemap(client, base, base_host, host_only, ctx)
        data["robots_paths"] = robots_paths
        data["sitemap_paths"] = sitemap_paths

        # -- step 3: threaded directory brute ----------------------------- #
        discovered = self._brute(
            client, base, base_host, host_only, interesting, exts, threads,
            str(opts["wordlist"]), ctx,
        )
        data["discovered"] = discovered

        # -- artifacts ---------------------------------------------------- #
        artifacts = self._write_artifacts(ctx, data)

        summary = (
            f"{base} -> HTTP {base_resp.status}; "
            f"{len(techs)} tech, {len(missing)} missing headers, "
            f"{len(robots_paths) + len(sitemap_paths)} referenced paths, "
            f"{len(discovered)} discovered path(s)"
        )
        ctx.engagement.add_note(f"web_enum: {summary}")
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # -------------------------------------------------------- internals -- #
    @staticmethod
    def _parse_codes(raw: str) -> set:
        codes: set = set()
        for part in _split_csv(raw):
            try:
                codes.add(int(part))
            except ValueError:
                continue
        return codes or {200, 204, 301, 302, 307, 401, 403}

    def _harvest_robots(self, client, base, base_host, host_only, ctx) -> List[str]:
        url = base + "/robots.txt"
        resp = client.get_follow(url, base_host)
        if not resp.ok or resp.status != 200 or not resp.body:
            return []
        text = resp.body.decode("utf-8", "replace")
        # A body that is actually HTML (soft-404) is not a real robots.txt.
        if "<html" in text[:200].lower():
            return []
        paths = _extract_robots(text)
        if paths:
            ctx.console.info(f"robots.txt: {len(paths)} referenced path(s)")
            ctx.engagement.add_finding(
                "robots.txt exposes paths",
                severity="info",
                host=host_only,
                description="robots.txt lists paths: " + ", ".join(paths[:25]),
                evidence=url,
            )
            for path in paths:
                ctx.engagement.add_loot(host_only, "web-path", path, source="robots.txt")
        return paths

    def _harvest_sitemap(self, client, base, base_host, host_only, ctx) -> List[str]:
        url = base + "/sitemap.xml"
        resp = client.get_follow(url, base_host)
        if not resp.ok or resp.status != 200 or not resp.body:
            return []
        text = resp.body.decode("utf-8", "replace")
        paths = _extract_sitemap(text, base_host)
        if paths:
            ctx.console.info(f"sitemap.xml: {len(paths)} URL(s)")
            for path in paths[:200]:
                ctx.engagement.add_loot(host_only, "web-path", path, source="sitemap.xml")
        return paths

    def _brute(self, client, base, base_host, host_only, interesting, exts, threads, wordlist_name, ctx) -> List[Dict[str, object]]:
        words = self._resolve_wordlist(wordlist_name, ctx)
        if not words:
            return []
        candidates = self._build_candidates(words, exts)
        if not candidates:
            ctx.console.warn("wordlist produced no candidates")
            return []

        ctx.console.info(
            f"brute-forcing {len(candidates)} path(s) against {base} "
            f"(interesting: {','.join(str(c) for c in sorted(interesting))})"
        )

        discovered: List[Dict[str, object]] = []
        workers = min(threads, MAX_THREADS, len(candidates))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(self._probe_path, client, base, base_host, cand): cand
                for cand in candidates
            }
            for future in as_completed(future_map):
                try:
                    hit = future.result()
                except Exception:  # noqa: BLE001 - a probe must never abort the run
                    hit = None
                if hit and hit["status"] in interesting:
                    discovered.append(hit)

        discovered.sort(key=lambda h: (h["status"], h["path"]))
        for hit in discovered:
            self._record_hit(hit, host_only, base, ctx)
        ctx.console.good(f"{len(discovered)} interesting path(s) discovered")
        return discovered

    def _resolve_wordlist(self, wordlist_name: str, ctx) -> List[str]:
        """Resolve the wordlist to a list of words, offline-first.

        Accepts either a bundled wordlist name (resolved via ``config``) or an
        absolute/relative path the operator supplied. Returns ``[]`` and warns
        (rather than raising) when nothing usable is found.
        """
        from pathlib import Path

        name = (wordlist_name or "").strip() or "dirs-common.txt"
        candidates = []
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
            f"wordlist '{name}' not found (looked in cwd and bundled data); "
            f"skipping directory brute-force"
        )
        return []

    @staticmethod
    def _probe_path(client, base, base_host, candidate: str) -> Optional[Dict[str, object]]:
        url = f"{base}/{candidate}"
        resp = client.raw_get(url)  # raw: do not follow, so 3xx codes are visible
        if not resp.ok:
            return None
        location = resp.headers.get("location") if resp.status in REDIRECT_CODES else None
        return {
            "path": "/" + candidate,
            "status": int(resp.status),
            "url": url,
            "length": len(resp.body),
            "location": location,
        }

    @staticmethod
    def _build_candidates(words: List[str], exts: List[str]) -> List[str]:
        out: List[str] = []
        seen: set = set()
        for word in words:
            for cand in [word] + [f"{word}.{ext}" for ext in exts]:
                if cand not in seen:
                    seen.add(cand)
                    out.append(cand)
        return out

    def _record_hit(self, hit: Dict[str, object], host_only, base, ctx) -> None:
        path = str(hit["path"])
        status = int(hit["status"])
        leaf = path.strip("/").lower()
        sensitive = leaf in SENSITIVE_PATHS or any(
            leaf == s or leaf.endswith("/" + s) for s in SENSITIVE_PATHS
        )
        if sensitive and status in (200, 401, 403):
            severity = "high" if status == 200 else "medium"
            title = f"Sensitive path exposed: {path} (HTTP {status})"
        elif status in (401, 403):
            severity = "low"
            title = f"Protected path found: {path} (HTTP {status})"
        else:
            severity = "info"
            title = f"Path found: {path} (HTTP {status})"
        ctx.engagement.add_finding(
            title,
            severity=severity,
            host=host_only,
            description=f"Directory brute-force hit at {hit['url']} (status {status}).",
            evidence=str(hit["url"]),
        )
        ctx.engagement.add_loot(host_only, "web-path", path, source="dir-brute")

    def _write_artifacts(self, ctx, data: Dict[str, object]) -> List[str]:
        import json

        artifacts: List[str] = []
        host = str(data.get("host") or "target").replace(":", "_")
        try:
            json_path = ctx.artifact_path(f"web_enum_{host}.json")
            json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(json_path))
        except OSError:
            pass
        try:
            lines = [str(hit["url"]) for hit in data.get("discovered", [])]  # type: ignore[index]
            if lines:
                paths_path = ctx.artifact_path(f"web_enum_{host}_paths.txt")
                paths_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                artifacts.append(str(paths_path))
        except OSError:
            pass
        return artifacts


def _parse_url(raw: str) -> Tuple[str, str, str, int, bool]:
    """Normalize a URL.

    Returns ``(base, netloc, host_only, port, is_https)`` where ``base`` has no
    trailing slash and no path. ``netloc`` retains any explicit port for
    same-host redirect comparison; ``host_only`` is the bare hostname used as
    the engagement key.
    """
    raw = (raw or "").strip()
    if not raw:
        return "", "", "", 0, False
    if "://" not in raw:
        raw = "http://" + raw
    parts = urllib.parse.urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return "", "", "", 0, False
    is_https = scheme == "https"
    host_only = parts.hostname
    port = parts.port or (443 if is_https else 80)
    netloc = parts.netloc.lower()
    base = f"{scheme}://{netloc}"
    return base, netloc, host_only, int(port), is_https
