"""Shared HTTP client for web modules.

Pure standard library (``urllib``) so it stays portable and offline-friendly.
Every web module builds its requests through :class:`HttpClient` so they all get
the same behaviour for free: routing through an intercepting proxy (Burp/ZAP),
authenticated testing via cookies/headers, TLS-verification bypass, redirect
control, and a persistent cookie jar for session-aware crawling.

No AI. No third-party requirement. Deterministic.
"""
from __future__ import annotations

import gzip
import http.cookiejar
import io
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from .module import Option

DEFAULT_UA = "redkit/0.1 (+authorized-testing)"
Params = Optional[Union[Dict[str, str], List[Tuple[str, str]]]]


@dataclass
class Response:
    """A simple, fully-read HTTP response."""

    url: str
    status: int
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)   # lower-cased keys
    body: bytes = b""
    elapsed: float = 0.0
    error: Optional[str] = None                              # transport-level error, if any

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def length(self) -> int:
        return len(self.body)

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 400


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirect following (return the 3xx as-is)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,N802
        return None


class HttpClient:
    """Minimal configurable HTTP client shared by all web modules."""

    def __init__(
        self,
        proxy: str = "",
        timeout: float = 10.0,
        verify: bool = True,
        user_agent: str = DEFAULT_UA,
        headers: Optional[Dict[str, str]] = None,
        cookie: str = "",
        allow_redirects: bool = True,
        max_redirects: int = 5,
    ):
        self.timeout = timeout
        self.verify = verify
        self.user_agent = user_agent
        self.base_headers = dict(headers or {})
        self.cookie = cookie
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self.jar = http.cookiejar.CookieJar()

        self._ssl_ctx = None
        if not verify:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

        self._proxies = {}
        if proxy:
            self._proxies = {"http": proxy, "https": proxy}

    # -- opener ------------------------------------------------------------
    def _build_opener(self, allow_redirects: bool) -> urllib.request.OpenerDirector:
        handlers: List[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(self.jar),
        ]
        if self._ssl_ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self._ssl_ctx))
        if self._proxies:
            handlers.append(urllib.request.ProxyHandler(self._proxies))
        if not allow_redirects:
            handlers.append(_NoRedirect())
        return urllib.request.build_opener(*handlers)

    # -- request -----------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        params: Params = None,
        data: Optional[Union[bytes, str, Dict[str, str]]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: Optional[bool] = None,
    ) -> Response:
        method = method.upper()
        if params:
            query = urllib.parse.urlencode(list(params.items()) if isinstance(params, dict) else params)
            sep = "&" if urllib.parse.urlparse(url).query else "?"
            url = f"{url}{sep}{query}"

        body: Optional[bytes] = None
        req_headers = {"User-Agent": self.user_agent}
        req_headers.update(self.base_headers)
        if self.cookie:
            req_headers["Cookie"] = self.cookie
        if headers:
            req_headers.update(headers)

        if data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode()
                req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, str):
                body = data.encode()
            else:
                body = data

        redirects = self.allow_redirects if allow_redirects is None else allow_redirects
        opener = self._build_opener(redirects)
        req = urllib.request.Request(url=url, data=body, method=method, headers=req_headers)

        start = time.time()
        try:
            resp = opener.open(req, timeout=self.timeout)
            return self._to_response(url, resp, time.time() - start)
        except urllib.error.HTTPError as exc:  # 4xx/5xx are valid responses
            return self._to_response(url, exc, time.time() - start)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ConnectionError, OSError) as exc:
            return Response(url=url, status=0, error=str(getattr(exc, "reason", exc)), elapsed=time.time() - start)
        except Exception as exc:  # never let a request kill a whole scan
            return Response(url=url, status=0, error=str(exc), elapsed=time.time() - start)

    def _to_response(self, url: str, resp, elapsed: float) -> Response:
        raw = resp.read()
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        raw = _decompress(raw, hdrs.get("content-encoding", ""))
        return Response(
            url=getattr(resp, "url", url),
            status=getattr(resp, "status", None) or getattr(resp, "code", 0),
            reason=getattr(resp, "reason", "") or "",
            headers=hdrs,
            body=raw,
            elapsed=elapsed,
        )

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Response:
        return self.request("POST", url, **kw)


def _decompress(raw: bytes, encoding: str) -> bytes:
    try:
        if encoding == "gzip":
            return gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        if encoding == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        return raw
    return raw


# ---------------------------------------------------------------------------
# Shared options + builder so every web module exposes the same knobs.
# ---------------------------------------------------------------------------
WEB_COMMON_OPTIONS: List[Option] = [
    Option("cookie", default="", help="Cookie header for authenticated testing, e.g. 'PHPSESSID=abc; auth=1'"),
    Option("header", default="", help="Extra header 'Name: value'; separate several with '||'"),
    Option("proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080 to route through Burp/ZAP"),
    Option("timeout", default=10, help="Per-request timeout in seconds"),
    Option("user_agent", default=DEFAULT_UA, help="User-Agent header"),
    Option("insecure", default=True, help="Ignore TLS certificate errors"),
]


def parse_headers(raw: str) -> Dict[str, str]:
    """Parse a '||'-separated 'Name: value' string into a header dict."""
    out: Dict[str, str] = {}
    for chunk in (raw or "").split("||"):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        name, value = chunk.split(":", 1)
        out[name.strip()] = value.strip()
    return out


def client_from_opts(opts: Dict[str, object], allow_redirects: bool = True) -> HttpClient:
    """Build an :class:`HttpClient` from the standard WEB_COMMON_OPTIONS values."""
    return HttpClient(
        proxy=str(opts.get("proxy", "") or ""),
        timeout=float(opts.get("timeout", 10) or 10),
        verify=not bool(opts.get("insecure", True)),
        user_agent=str(opts.get("user_agent", DEFAULT_UA) or DEFAULT_UA),
        headers=parse_headers(str(opts.get("header", "") or "")),
        cookie=str(opts.get("cookie", "") or ""),
        allow_redirects=allow_redirects,
    )
