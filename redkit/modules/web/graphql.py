"""GraphQL reconnaissance module.

Locates a live GraphQL endpoint (either the exact URL supplied by the operator
or, when given a bare base URL, by probing a small set of common paths), then
optionally runs the standard ``__schema`` introspection query to enumerate the
API surface (types, queries, mutations, subscriptions). Also flags GET-based
query execution, a classic GraphQL CSRF surface (queries triggered via a
simple cross-site GET are not protected by the usual same-origin restrictions
that apply to custom-content-type POST bodies).

Design constraints (redkit invariants):
    * NO AI/LLM usage - every decision here is a deterministic rule based on
      well-known GraphQL response shapes (``data``/``errors`` keys, standard
      introspection field names).
    * Pure standard library (``json``, ``urllib.parse``) plus the shared
      :mod:`redkit.core.http` client - no hand-rolled networking.
    * Imports and runs on both Windows and Linux (no OS-specific calls).
    * Offline: no wordlists needed here, but no network calls beyond the
      operator-specified target.
    * Bounded and safe: at most one specific + four common-path candidates are
      probed, all requests are GET/POST reads (no mutations are ever executed),
      and every request goes through the shared, timeout-bound HttpClient.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register
from redkit.core.http import WEB_COMMON_OPTIONS, client_from_opts

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
# Common GraphQL endpoint paths tried when the operator hands us a base URL
# rather than a specific endpoint. Kept short and well known to stay within
# the "bounded request count" invariant.
COMMON_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

# Cheap probe query used purely to fingerprint "is this thing GraphQL at all".
PROBE_QUERY = "{ __typename }"

# Standard introspection query. Deliberately requests only what we need to
# enumerate types / root-operation fields (name, kind) rather than the full
# verbose introspection payload (args, descriptions, interfaces, ...), to keep
# the request/response small while still identifying the whole schema surface.
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
      }
    }
  }
}
""".strip()

# Keywords that, when present in a JSON error payload, indicate the responder
# understood a GraphQL-shaped request even though it returned an error (e.g.
# "must provide query string", "syntax error", auth-required, etc.).
_ERROR_KEYWORDS = (
    "graphql",
    "query string",
    "must provide a query",
    "must provide query",
    "cannot query field",
    "syntax error",
    "mutation",
    "operation",
    "persisted query",
)

# Cap how many enumerated names we embed directly in Result.data; the full
# schema is always written to the artifact file regardless.
MAX_LISTED = 200


@register
class GraphQLRecon(Module):
    """Discover and fingerprint a GraphQL endpoint; enumerate via introspection."""

    name = "web.graphql"
    description = "GraphQL endpoint discovery, introspection, and GET-CSRF surface check"
    phase = "web"
    options = [
        Option(
            "url",
            help="GraphQL endpoint URL, or a base URL (e.g. https://host) to probe common paths",
            required=True,
        ),
        Option(
            "method",
            default="POST",
            choices=["POST", "GET"],
            help="HTTP method used to submit queries",
        ),
        Option("introspect", default=True, help="Attempt __schema introspection"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        "https://graphql.org/learn/introspection/",
        "https://owasp.org/www-project-api-security/",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, Any], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts.get("url") or "").strip()
        if not raw_url:
            return Result(ok=False, summary="url is required")
        if "://" not in raw_url:
            raw_url = "http://" + raw_url
        parsed = urllib.parse.urlsplit(raw_url)
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts.get('url')!r} (expected http(s)://host[/path])")

        host = parsed.hostname
        method = str(opts.get("method") or "POST").upper()
        if method not in ("POST", "GET"):
            method = "POST"
        introspect = bool(opts.get("introspect", True))

        client = client_from_opts(opts)
        ctx.engagement.add_host(host)

        candidates = _candidate_urls(raw_url)
        console.info(f"web.graphql: probing {len(candidates)} candidate endpoint(s) on {host}")

        data: Dict[str, Any] = {
            "target": raw_url,
            "host": host,
            "probed_endpoints": candidates,
            "endpoint": None,
            "method": method,
            "reachable": False,
            "introspection_enabled": False,
            "get_queries_accepted": False,
            "types_count": 0,
            "queries_count": 0,
            "mutations_count": 0,
            "subscriptions_count": 0,
            "queries": [],
            "mutations": [],
            "subscriptions": [],
            "query_type": None,
            "mutation_type": None,
            "subscription_type": None,
            "errors": [],
        }

        endpoint, probe_notes = self._find_endpoint(client, candidates, method)
        data["errors"] = probe_notes

        if not endpoint:
            console.warn("web.graphql: no live GraphQL endpoint identified among probed candidates")
            summary = f"no GraphQL endpoint found among {len(candidates)} probed path(s)"
            ctx.engagement.add_note(f"web.graphql: {summary}")
            return Result(ok=True, summary=summary, data=data)

        data["endpoint"] = endpoint
        data["reachable"] = True
        console.good(f"web.graphql: endpoint identified at {endpoint} (via {method})")

        # -- GET-based query acceptance (CSRF surface) -------------------- #
        get_accepted = self._check_get_csrf(client, endpoint, method)
        data["get_queries_accepted"] = get_accepted
        if get_accepted:
            console.warn("web.graphql: endpoint accepts GraphQL queries via GET (CSRF surface)")
            ctx.engagement.add_finding(
                "GraphQL endpoint accepts GET-based queries (CSRF surface)",
                severity="medium",
                host=host,
                description=(
                    "The GraphQL endpoint executes queries submitted as simple GET "
                    "requests with a 'query' parameter. Simple GET requests are not "
                    "subject to the CORS/CSRF protections that apply to non-simple "
                    "content types (e.g. application/json POST bodies), so an attacker "
                    "can trigger authenticated queries cross-site via a crafted link, "
                    "<img>/<script> tag, or auto-submitting form and potentially "
                    "exfiltrate data through side channels."
                ),
                evidence=f"{endpoint}?query={urllib.parse.quote(PROBE_QUERY)}",
            )

        # -- introspection --------------------------------------------------- #
        artifacts: List[str] = []
        if introspect:
            schema_body = self._introspect(client, endpoint, method)
            if schema_body is not None:
                summary_bits = _parse_schema(schema_body)
                data["introspection_enabled"] = True
                data["types_count"] = summary_bits["types_count"]
                data["queries_count"] = len(summary_bits["queries"])
                data["mutations_count"] = len(summary_bits["mutations"])
                data["subscriptions_count"] = len(summary_bits["subscriptions"])
                data["queries"] = summary_bits["queries"][:MAX_LISTED]
                data["mutations"] = summary_bits["mutations"][:MAX_LISTED]
                data["subscriptions"] = summary_bits["subscriptions"][:MAX_LISTED]
                data["query_type"] = summary_bits["query_type"]
                data["mutation_type"] = summary_bits["mutation_type"]
                data["subscription_type"] = summary_bits["subscription_type"]

                console.good(
                    f"web.graphql: introspection ENABLED - {data['types_count']} types, "
                    f"{data['queries_count']} queries, {data['mutations_count']} mutations, "
                    f"{data['subscriptions_count']} subscriptions"
                )

                artifact_path = self._write_schema_artifact(ctx, host, schema_body)
                if artifact_path:
                    artifacts.append(artifact_path)

                ctx.engagement.add_finding(
                    "GraphQL introspection enabled",
                    severity="medium",
                    host=host,
                    description=(
                        f"The GraphQL schema is fully queryable via introspection at "
                        f"{endpoint}, exposing {data['types_count']} types, "
                        f"{data['queries_count']} queries, {data['mutations_count']} "
                        f"mutations, and {data['subscriptions_count']} subscriptions. "
                        "This maps the full API attack surface, including internal or "
                        "undocumented operations, and should be disabled in production."
                    ),
                    evidence=endpoint,
                )
                for q in summary_bits["queries"][:100]:
                    ctx.engagement.add_loot(host, "graphql-query", q, source=endpoint)
                for m in summary_bits["mutations"][:100]:
                    ctx.engagement.add_loot(host, "graphql-mutation", m, source=endpoint)
                for s in summary_bits["subscriptions"][:100]:
                    ctx.engagement.add_loot(host, "graphql-subscription", s, source=endpoint)
            else:
                console.info("web.graphql: introspection appears disabled or was blocked")

        summary = (
            f"{endpoint} -> introspection="
            f"{'enabled' if data['introspection_enabled'] else 'disabled'}, "
            f"GET-queries={'accepted' if data['get_queries_accepted'] else 'rejected'}"
        )
        if data["introspection_enabled"]:
            summary += (
                f", {data['types_count']} types / {data['queries_count']} queries / "
                f"{data['mutations_count']} mutations / {data['subscriptions_count']} subscriptions"
            )
        ctx.engagement.add_note(f"web.graphql: {summary}")
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # -------------------------------------------------------- internals -- #
    @staticmethod
    def _find_endpoint(client, candidates: List[str], method: str) -> Tuple[Optional[str], List[str]]:
        """Probe each candidate with a cheap query; return the first live one."""
        notes: List[str] = []
        for cand in candidates:
            resp = _send_query(client, cand, method, PROBE_QUERY)
            if resp.status == 0 or resp.error:
                notes.append(f"{cand}: unreachable ({resp.error or 'transport error'})")
                continue
            body = _parse_json_body(resp)
            if _looks_like_graphql(body):
                return cand, notes
            notes.append(f"{cand}: HTTP {resp.status} (not recognized as a GraphQL response)")
        return None, notes

    @staticmethod
    def _check_get_csrf(client, endpoint: str, primary_method: str) -> bool:
        """Return True if the endpoint executes queries submitted via GET."""
        if primary_method == "GET":
            # We already reached this endpoint via a GET query during discovery.
            return True
        resp = _send_query(client, endpoint, "GET", PROBE_QUERY)
        if resp.status == 0 or resp.error:
            return False
        return _looks_like_graphql(_parse_json_body(resp))

    @staticmethod
    def _introspect(client, endpoint: str, method: str) -> Optional[Dict[str, Any]]:
        """Send the introspection query; return the raw response body dict or None."""
        resp = _send_query(client, endpoint, method, INTROSPECTION_QUERY)
        if resp.status == 0 or resp.error:
            return None
        body = _parse_json_body(resp)
        if not body:
            return None
        schema = (body.get("data") or {}).get("__schema") if isinstance(body.get("data"), dict) else None
        if not isinstance(schema, dict) or not schema.get("types"):
            return None
        return body

    @staticmethod
    def _write_schema_artifact(ctx, host: str, body: Dict[str, Any]) -> Optional[str]:
        try:
            path = ctx.artifact_path(f"graphql_schema_{host}.json")
            path.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
            return str(path)
        except OSError:
            return None


# --------------------------------------------------------------------------- #
# free functions (pure, testable in isolation)
# --------------------------------------------------------------------------- #
def _candidate_urls(raw_url: str) -> List[str]:
    """Build the bounded list of endpoint URLs to try.

    If the operator already supplied a specific path, it is tried first; the
    small set of well-known GraphQL paths under the same scheme+host is always
    appended (deduplicated) as a fallback, keeping the total request budget
    small (at most ``1 + len(COMMON_PATHS)``).
    """
    parsed = urllib.parse.urlsplit(raw_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    candidates: List[str] = []

    path = parsed.path or ""
    if path not in ("", "/"):
        candidates.append(f"{root}{path}")

    for p in COMMON_PATHS:
        cand = root + p
        if cand not in candidates:
            candidates.append(cand)
    return candidates


def _send_query(client, url: str, method: str, query: str, variables: Optional[dict] = None):
    """Submit a GraphQL query via POST (JSON body) or GET (query string)."""
    if method == "GET":
        params: Dict[str, str] = {"query": query}
        if variables:
            params["variables"] = json.dumps(variables)
        return client.get(url, params=params, headers={"Accept": "application/json"})

    payload: Dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    body = json.dumps(payload).encode("utf-8")
    return client.post(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )


def _parse_json_body(resp) -> Optional[Dict[str, Any]]:
    """Best-effort JSON decode of a Response body; tolerate non-JSON bodies."""
    if resp is None or resp.status == 0 or resp.error or not resp.body:
        return None
    try:
        body = json.loads(resp.text)
    except (ValueError, UnicodeDecodeError):
        return None
    return body if isinstance(body, dict) else None


def _looks_like_graphql(body: Optional[Dict[str, Any]]) -> bool:
    """Decide whether a parsed JSON body indicates a live GraphQL handler.

    Recognizes either a successful ``{"data": {"__typename": "..."}}`` shape
    from the cheap probe query, or a JSON ``errors`` array whose message text
    references GraphQL-specific semantics (query/mutation/schema handling),
    which many implementations return even when a request is otherwise
    rejected (bad method, missing auth, persisted-queries-only, etc.).
    """
    if not body:
        return False
    data = body.get("data")
    if isinstance(data, dict) and isinstance(data.get("__typename"), str) and data.get("__typename"):
        return True
    errors = body.get("errors")
    if isinstance(errors, list) and errors:
        try:
            blob = json.dumps(errors).lower()
        except (TypeError, ValueError):
            blob = str(errors).lower()
        if any(keyword in blob for keyword in _ERROR_KEYWORDS):
            return True
    return False


def _parse_schema(body: Dict[str, Any]) -> Dict[str, Any]:
    """Extract type/query/mutation/subscription names from an introspection body."""
    schema = ((body.get("data") or {}).get("__schema")) or {}
    types = schema.get("types") or []
    type_index: Dict[str, Dict[str, Any]] = {
        t.get("name"): t for t in types if isinstance(t, dict) and t.get("name")
    }

    def _fields_of(type_name: Optional[str]) -> List[str]:
        if not type_name:
            return []
        t = type_index.get(type_name) or {}
        fields = t.get("fields") or []
        names = {f.get("name") for f in fields if isinstance(f, dict) and f.get("name")}
        return sorted(names)

    query_type = (schema.get("queryType") or {}).get("name")
    mutation_type = (schema.get("mutationType") or {}).get("name")
    subscription_type = (schema.get("subscriptionType") or {}).get("name")

    # Exclude GraphQL's own reflection meta-types (__Type, __Schema, ...) from
    # the reported count so it reflects the application's actual schema size.
    named_types = [
        t.get("name")
        for t in types
        if isinstance(t, dict) and t.get("name") and not str(t.get("name")).startswith("__")
    ]

    return {
        "types_count": len(named_types),
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
        "queries": _fields_of(query_type),
        "mutations": _fields_of(mutation_type),
        "subscriptions": _fields_of(subscription_type),
    }
