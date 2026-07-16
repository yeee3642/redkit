"""Exposed VCS / config / backup file detector.

Many deployments accidentally ship version-control metadata (``.git``,
``.svn``, ``.hg``), environment files, backup copies of config/source files,
or admin debug endpoints (``phpinfo.php``, ``server-status``) alongside the
live application. This module probes a bounded, fixed list of well-known
sensitive paths plus a handful of backup-suffix variants of the target page's
own filename, and only reports a path as exposed when its response matches a
deterministic content signature for that file type -- never on a bare HTTP
200, which would false-positive against single-page-app catch-all routing.

Design constraints (redkit invariants):
    * NO AI/LLM usage -- every exposure decision is a fixed, rule-based
      signature check (magic bytes / regex / structural parse) plus a
      comparison against a random-path baseline response.
    * Pure standard library. All HTTP goes through the shared
      :mod:`redkit.core.http` client (proxy, cookie, TLS, timeout support
      included for free).
    * Imports and runs on both Windows and Linux; no OS-specific calls.
    * Offline: the probe list is fixed at import time, no external fetch.
    * Bounded: the candidate list is a short fixed set (~30 paths), the
      thread pool is capped at 20 workers, and ``dump`` only performs a
      best-effort read of already-probed ``.git`` metadata -- never a
      recursive git-object walk.
    * No destructive default: everything is a GET; ``dump`` only writes an
      artifact file inside the engagement workdir, it never writes to the
      target.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

from redkit.core.http import WEB_COMMON_OPTIONS, HttpClient, Response, client_from_opts
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

MAX_THREADS = 20   # hard invariant: capped thread pool
MAX_PATHS = 100     # defensive cap; the fixed candidate list is far smaller

# Fixed, bounded probe list -- no wordlist, no growth.
SENSITIVE_PATHS: List[str] = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.DS_Store",
    "/.htaccess",
    "/.htpasswd",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/web.config",
    "/composer.json",
    "/package.json",
    "/.npmrc",
    "/docker-compose.yml",
    "/.aws/credentials",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/.travis.yml",
    "/phpinfo.php",
    "/server-status",
]

BACKUP_SUFFIXES: List[str] = [".bak", "~", ".old", ".save", ".swp"]

# Findings whose content is itself a usable credential / secret.
CRITICAL_KINDS = {"dotenv", "git-config", "aws-credentials", "sql-dump", "wp-config-secret", "htpasswd"}

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+$", re.M)
_HTML_TAG_RE = re.compile(r"<html|<!doctype html|<body[\s>]", re.I)

_DS_STORE_MAGIC = b"\x00\x00\x00\x01Bud1"
_SQLITE_MAGIC = b"SQLite format 3\x00"
_ZIP_MAGIC = b"PK\x03\x04"
_GIT_INDEX_MAGIC = b"DIRC"


# --------------------------------------------------------------------------- #
# content-signature checkers -- pure, deterministic, no network/AI involved
# --------------------------------------------------------------------------- #
def _is_html(text: str) -> bool:
    return bool(_HTML_TAG_RE.search(text[:2000]))


def _sig_git_head(resp: Response) -> bool:
    t = resp.text.strip()
    return t.startswith("ref:") or bool(_GIT_SHA_RE.match(t))


def _sig_git_config(resp: Response) -> bool:
    return "[core]" in resp.text


def _sig_git_index(resp: Response) -> bool:
    return resp.body.startswith(_GIT_INDEX_MAGIC)


def _sig_gitignore(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return False
    markers = ("node_modules", ".env", "vendor/", "dist/", "__pycache__", ".idea", ".vscode")
    return any(ln in markers or ln.startswith(("*.", "/")) for ln in lines)


def _sig_svn_entries(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    lines = text.splitlines()
    if not lines:
        return False
    return lines[0].strip().isdigit() and ("dir" in text or "file" in text)


def _sig_svn_wcdb(resp: Response) -> bool:
    return resp.body.startswith(_SQLITE_MAGIC)


def _sig_hg_dir(resp: Response) -> bool:
    text = resp.text
    return any(tok in text for tok in ("00changelog.i", "dirstate", "store/data"))


def _sig_env(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    return bool(_ENV_LINE_RE.search(text))


def _sig_ds_store(resp: Response) -> bool:
    return resp.body.startswith(_DS_STORE_MAGIC)


def _sig_htaccess(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    markers = ("RewriteEngine", "RewriteRule", "Options ", "Deny from", "Allow from", "AuthType", "<Files", "<Directory", "ErrorDocument")
    return any(m in text for m in markers)


def _sig_htpasswd(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    return bool(re.search(r"^[^:\s]+:\$(apr1|2y|2b|1)\$", text, re.M)) or bool(
        re.search(r"^[^:\s]+:[a-zA-Z0-9./]{13}$", text, re.M)
    )


def _sig_php_source(resp: Response) -> bool:
    return "<?php" in resp.text


def _sig_wp_config(resp: Response) -> bool:
    return "DB_PASSWORD" in resp.text or "<?php" in resp.text


def _sig_web_config(resp: Response) -> bool:
    text = resp.text
    return "<configuration" in text


def _sig_composer_json(resp: Response) -> bool:
    text = resp.text.strip()
    if not text.startswith("{"):
        return False
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and ("require" in obj or ("name" in obj and "autoload" in obj))


def _sig_package_json(resp: Response) -> bool:
    text = resp.text.strip()
    if not text.startswith("{"):
        return False
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and any(k in obj for k in ("dependencies", "devDependencies", "scripts", "name"))


def _sig_npmrc(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    return any(tok in text for tok in ("registry=", "_auth=", "_authToken=", "//registry.npmjs.org"))


def _sig_docker_compose(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    return bool(re.search(r"^\s*version:\s*[\"']?\d", text, re.M)) or bool(re.search(r"^\s*services:\s*$", text, re.M))


def _sig_aws_credentials(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    return "aws_access_key_id" in text.lower() and "[" in text


def _sig_zip_archive(resp: Response) -> bool:
    return resp.body.startswith(_ZIP_MAGIC)


def _sig_sql_dump(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    upper = text.upper()
    return any(tok in upper for tok in ("CREATE TABLE", "INSERT INTO", "-- MYSQL DUMP", "PGDUMP", "DUMP COMPLETED"))


def _sig_travis_yml(resp: Response) -> bool:
    text = resp.text
    if _is_html(text):
        return False
    return bool(re.search(r"^\s*language:\s*\S+", text, re.M))


def _sig_phpinfo(resp: Response) -> bool:
    text = resp.text
    return "phpinfo()" in text or "PHP Version" in text


def _sig_server_status(resp: Response) -> bool:
    text = resp.text
    return "Apache Server Status" in text or "Scoreboard Key" in text


def _sig_generic_backup(resp: Response) -> bool:
    """Fallback signature for '<page><suffix>' backup candidates.

    There is no single fingerprint for an arbitrary page's backup, so this
    looks for source-code / non-HTML markers that indicate the raw file was
    served unprocessed rather than a rendered page or SPA catch-all.
    """
    text = resp.text
    if "<?php" in text or "<%" in text:
        return True
    ctype = resp.header("content-type", "").lower()
    if ctype and "html" not in ctype and text.strip():
        return True
    return False


# path -> (signature kind, checker)
SIGNATURE_CHECKS: Dict[str, Tuple[str, Callable[[Response], bool]]] = {
    "/.git/HEAD": ("git-head", _sig_git_head),
    "/.git/config": ("git-config", _sig_git_config),
    "/.git/index": ("git-index", _sig_git_index),
    "/.gitignore": ("gitignore", _sig_gitignore),
    "/.svn/entries": ("svn-entries", _sig_svn_entries),
    "/.svn/wc.db": ("svn-wcdb-sqlite", _sig_svn_wcdb),
    "/.hg/": ("hg-repo", _sig_hg_dir),
    "/.env": ("dotenv", _sig_env),
    "/.env.local": ("dotenv", _sig_env),
    "/.env.production": ("dotenv", _sig_env),
    "/.DS_Store": ("ds-store", _sig_ds_store),
    "/.htaccess": ("htaccess", _sig_htaccess),
    "/.htpasswd": ("htpasswd", _sig_htpasswd),
    "/config.php.bak": ("php-source", _sig_php_source),
    "/wp-config.php.bak": ("wp-config-secret", _sig_wp_config),
    "/web.config": ("web-config-xml", _sig_web_config),
    "/composer.json": ("composer-json", _sig_composer_json),
    "/package.json": ("package-json", _sig_package_json),
    "/.npmrc": ("npmrc", _sig_npmrc),
    "/docker-compose.yml": ("docker-compose", _sig_docker_compose),
    "/.aws/credentials": ("aws-credentials", _sig_aws_credentials),
    "/backup.zip": ("zip-archive", _sig_zip_archive),
    "/backup.sql": ("sql-dump", _sig_sql_dump),
    "/db.sql": ("sql-dump", _sig_sql_dump),
    "/.travis.yml": ("travis-ci-config", _sig_travis_yml),
    "/phpinfo.php": ("phpinfo", _sig_phpinfo),
    "/server-status": ("apache-server-status", _sig_server_status),
}

GIT_METADATA_PATHS = ("/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore")


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class ExposedSecrets(Module):
    """Detect exposed VCS / config / backup files and optionally dump .git."""

    name = "web.secrets"
    description = "Detect exposed VCS/config/backup files (.git, .env, .htpasswd, backups...) via content-signature checks"
    phase = "web"
    options = [
        Option("url", help="target base URL", required=True),
        Option("dump", default=False, help="if /.git/ is exposed, best-effort fetch HEAD/config/index and save an artifact"),
        Option("threads", default=10, help="concurrent probe workers (capped at 20)"),
    ] + WEB_COMMON_OPTIONS
    references = [
        "https://owasp.org/www-community/vulnerabilities/Source_Code_Disclosure",
        "https://github.com/internetwache/GitTools",
        "https://portswigger.net/kb/issues/00600300_git-repository-detected",
    ]

    # ---------------------------------------------------------------- run -- #
    def run(self, opts: Dict[str, object], ctx) -> Result:
        console = ctx.console

        raw_url = str(opts["url"]).strip()
        if not raw_url:
            return Result(ok=False, summary="url is required")
        url = raw_url if "://" in raw_url else f"http://{raw_url}"
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            return Result(ok=False, summary=f"invalid url: {opts['url']!r} (expected http(s)://host)")
        target_host = parsed.hostname
        base_root = f"{parsed.scheme}://{parsed.netloc}"

        dump = bool(opts.get("dump"))
        threads = max(1, min(int(opts.get("threads", 10) or 10), MAX_THREADS))

        data: Dict[str, object] = {
            "url": url,
            "host": target_host,
            "candidates_tried": 0,
            "baseline": None,
            "exposed": [],
        }

        candidates = self._build_candidates(parsed)[:MAX_PATHS]
        client = client_from_opts(opts)

        baseline_path = f"/redkit-{uuid.uuid4().hex[:16]}-nope"
        baseline_resp = client.get(base_root + baseline_path)
        if baseline_resp.status == 0:
            console.bad(f"target unreachable: {baseline_resp.error}")
            ctx.engagement.add_note(f"secrets: {url} unreachable ({baseline_resp.error})")
            return Result(ok=False, summary=f"{url} unreachable: {baseline_resp.error}", data=data)

        baseline = {"status": baseline_resp.status, "length": baseline_resp.length, "body": baseline_resp.body}
        data["baseline"] = {"status": baseline["status"], "length": baseline["length"]}

        console.info(f"secrets probe {url}  ({len(candidates)} candidate path(s), {threads} threads)")
        data["candidates_tried"] = len(candidates)

        fetched: Dict[str, Response] = {}
        workers = max(1, min(threads, len(candidates)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(client.get, base_root + path): path for path, _ in candidates}
            for future in as_completed(future_map):
                path = future_map[future]
                try:
                    resp = future.result()
                except Exception:  # noqa: BLE001 - one probe must never abort the run
                    continue
                if resp is None or resp.status == 0:
                    continue
                fetched[path] = resp

        kind_by_path = {path: kind for path, kind in candidates}
        exposed: List[Dict[str, object]] = []
        for path, resp in fetched.items():
            kind = kind_by_path.get(path, "unknown")
            confirmed = self._confirm(path, resp, baseline)
            if not confirmed:
                continue
            severity = "critical" if kind in CRITICAL_KINDS else "high"
            exposed.append({"path": path, "signature": kind, "severity": severity})
            self._record(path, kind, severity, resp, target_host, base_root, ctx)

        exposed.sort(key=lambda e: str(e["path"]))
        data["exposed"] = exposed

        artifacts: List[str] = []
        if dump:
            git_hit = any(e["path"] in ("/.git/HEAD", "/.git/config", "/.git/index") for e in exposed)
            if git_hit:
                console.warn(".git metadata appears exposed; dumping best-effort artifact")
                ctx.engagement.add_note(f"secrets: .git exposed at {base_root}, dumping metadata")
                artifacts = self._dump_git(ctx, fetched, target_host)
            else:
                console.info("dump requested but no .git exposure confirmed; skipping")

        summary = f"{url}: {len(exposed)} exposed file(s) found out of {len(candidates)} probed"
        ctx.engagement.add_note(f"secrets: {summary}")
        if exposed:
            console.good(summary)
        else:
            console.info(summary)
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)

    # -------------------------------------------------------- internals -- #
    @staticmethod
    def _build_candidates(parsed: urllib.parse.ParseResult) -> List[Tuple[str, str]]:
        """Fixed sensitive-path list plus backup-suffix variants of the page filename."""
        candidates: List[Tuple[str, str]] = [(p, SIGNATURE_CHECKS[p][0]) for p in SENSITIVE_PATHS]

        orig_path = parsed.path or "/"
        filename = orig_path.rsplit("/", 1)[-1]
        if filename and "." in filename:
            seen = {p for p, _ in candidates}
            for suffix in BACKUP_SUFFIXES:
                backup_path = orig_path + suffix
                if backup_path not in seen:
                    seen.add(backup_path)
                    candidates.append((backup_path, "backup-source-leak"))
        return candidates

    @staticmethod
    def _confirm(path: str, resp: Response, baseline: Dict[str, object]) -> bool:
        if not (200 <= resp.status < 300):
            return False
        # Guard against SPA/catch-all routing: identical status+body as the
        # random-path baseline means this "hit" carries no real signal.
        if resp.status == baseline["status"] and resp.body == baseline["body"]:
            return False
        checker = SIGNATURE_CHECKS.get(path)
        if checker is not None:
            return checker[1](resp)
        return _sig_generic_backup(resp)

    @staticmethod
    def _record(path: str, kind: str, severity: str, resp: Response, host: str, base_root: str, ctx) -> None:
        url = base_root + path
        snippet = resp.text[:200].replace("\n", " ").strip()
        title = f"Exposed sensitive file: {path}"
        description = f"GET {url} returned HTTP {resp.status} matching '{kind}' content signature."
        ctx.engagement.add_finding(
            title,
            severity=severity,
            host=host,
            description=description,
            evidence=f"{url} :: {snippet}",
        )
        ctx.engagement.add_loot(host, "exposed-file", path, source="web.secrets")

    @staticmethod
    def _dump_git(ctx, fetched: Dict[str, Response], host: str) -> List[str]:
        artifacts: List[str] = []
        safe_host = (host or "target").replace(":", "_")
        summary: Dict[str, object] = {"host": host, "reachable": []}
        for path in GIT_METADATA_PATHS:
            resp = fetched.get(path)
            if resp is None or not (200 <= resp.status < 300):
                continue
            summary["reachable"].append({"path": path, "status": resp.status, "length": resp.length})
            safe_name = path.strip("/").replace("/", "_")
            try:
                out_path = ctx.artifact_path(f"secrets_{safe_host}_{safe_name}.raw")
                out_path.write_bytes(resp.body)
                artifacts.append(str(out_path))
            except OSError:
                continue
        try:
            summary_path = ctx.artifact_path(f"secrets_{safe_host}_git_dump.json")
            summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
            artifacts.append(str(summary_path))
        except OSError:
            pass
        return artifacts
