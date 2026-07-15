"""redkit command-line interface.

Subcommands:
  list                 list all modules grouped by phase
  search <term>        search modules by name/description
  info <module>        show a module's options and references
  run <module> [-o k=v ...]   run a module
  report [-f fmt]      generate an engagement report
  shell                interactive menu
  version              print version

Global options select the engagement workspace and toggle verbosity/dry-run.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional

from redkit import __version__, modules
from redkit.core import config, registry
from redkit.core.console import Console
from redkit.core.context import Context
from redkit.core.engagement import Engagement
from redkit.core.runner import Runner


# ---------------------------------------------------------------------------
# context construction
# ---------------------------------------------------------------------------
def build_context(args: argparse.Namespace) -> Context:
    console = Console(verbose=getattr(args, "verbose", False))
    eng_dir = config.engagement_dir(args.engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    engagement = Engagement.load_or_create(eng_dir / "engagement.json")
    workdir = eng_dir / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    runner = Runner(
        console=console,
        evidence_log=eng_dir / "evidence.log",
        dry_run=getattr(args, "dry_run", False),
    )
    return Context(
        engagement=engagement,
        console=console,
        runner=runner,
        workdir=workdir,
        data_dir=config.DATA_DIR,
    )


def parse_kv(pairs: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"bad option '{pair}', expected key=value")
        key, value = pair.split("=", 1)
        out[key.strip()] = value
    return out


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    console = Console()
    grouped = registry.by_phase()
    if not grouped:
        console.warn("no modules registered")
        return 1
    for phase in registry.PHASES:
        mods = grouped.get(phase)
        if not mods:
            continue
        console.raw("")
        console.banner(phase.upper())
        console.table(
            ["module", "description"],
            [[m.name, m.description] for m in mods],
        )
    console.raw("")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    console = Console()
    hits = registry.search(args.term)
    if not hits:
        console.warn(f"no modules match '{args.term}'")
        return 1
    console.table(["module", "phase", "description"], [[m.name, m.phase, m.description] for m in hits])
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    console = Console()
    cls = registry.get(args.module)
    if not cls:
        console.bad(f"no such module: {args.module}")
        return 1
    console.banner(cls.name, cls.description)
    console.raw(f"phase   : {cls.phase}")
    if cls.requires_tools:
        console.raw(f"tools   : {', '.join(cls.requires_tools)} (optional external)")
    console.raw("")
    if cls.options:
        console.table(
            ["option", "required", "default", "help"],
            [[o.name, "yes" if o.required else "", o.default, o.help] for o in cls.options],
        )
    else:
        console.raw("(no options)")
    if getattr(cls, "references", None):
        console.raw("")
        console.raw("references:")
        for ref in cls.references:
            console.raw(f"  - {ref}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    cls = registry.get(args.module)
    if not cls:
        ctx.console.bad(f"no such module: {args.module}")
        return 1
    try:
        opts = cls.resolve_options(parse_kv(args.option))
    except ValueError as exc:
        ctx.console.bad(str(exc))
        ctx.console.info(f"run 'redkit info {cls.name}' to see options")
        return 2

    ctx.console.banner(f"run {cls.name}", cls.description)
    for tool in getattr(cls, "requires_tools", []):
        if not ctx.runner.have(tool):
            ctx.console.warn(f"optional tool '{tool}' not found — module may use a fallback or skip steps")

    try:
        result = cls().run(opts, ctx)
    except KeyboardInterrupt:
        ctx.console.warn("interrupted")
        ctx.engagement.save()
        return 130
    except Exception as exc:  # a module crash should not lose engagement state
        ctx.console.bad(f"module error: {exc}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        ctx.engagement.save()
        return 1

    ctx.engagement.save()
    if result is None:
        ctx.console.warn("module returned no result")
        return 0
    if result.ok:
        ctx.console.good(result.summary or "done")
    else:
        ctx.console.bad(result.summary or "failed")
    for art in result.artifacts:
        ctx.console.info(f"artifact: {art}")
    return 0 if result.ok else 1


def cmd_report(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    cls = registry.get("report.markdown")
    if not cls:
        ctx.console.bad("report module not available")
        return 1
    opts = cls.resolve_options({"format": args.format} if args.format else {})
    result = cls().run(opts, ctx)
    if result and result.ok:
        ctx.console.good(result.summary)
        for art in result.artifacts:
            ctx.console.info(f"report: {art}")
        return 0
    return 1


def cmd_version(args: argparse.Namespace) -> int:
    print(f"redkit {__version__}")
    return 0


# ---------------------------------------------------------------------------
# interactive shell
# ---------------------------------------------------------------------------
def cmd_shell(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    console = ctx.console
    console.banner("redkit interactive", f"engagement: {ctx.engagement.data['name']}")
    console.raw("commands: list | search <t> | info <m> | use <m> | report | back | quit")
    current = None
    current_opts: Dict[str, str] = {}
    while True:
        try:
            prompt = f"redkit({current.name})> " if current else "redkit> "
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            console.raw("")
            break
        if not line:
            continue
        parts = line.split()
        cmd, rest = parts[0], parts[1:]

        if cmd in ("quit", "exit"):
            break
        elif cmd == "list":
            cmd_list(args)
        elif cmd == "search" and rest:
            ns = argparse.Namespace(term=rest[0])
            cmd_search(ns)
        elif cmd == "info" and rest:
            cmd_info(argparse.Namespace(module=rest[0]))
        elif cmd == "use" and rest:
            cls = registry.get(rest[0])
            if not cls:
                console.bad(f"no such module: {rest[0]}")
            else:
                current, current_opts = cls, {}
                cmd_info(argparse.Namespace(module=rest[0]))
        elif cmd == "set" and len(rest) >= 2 and current:
            current_opts[rest[0]] = " ".join(rest[1:])
            console.good(f"{rest[0]} = {current_opts[rest[0]]}")
        elif cmd == "options" and current:
            for k, v in current_opts.items():
                console.raw(f"  {k} = {v}")
        elif cmd in ("back", "unset") and current:
            current, current_opts = None, {}
        elif cmd == "run" and current:
            run_ns = argparse.Namespace(
                engagement=args.engagement,
                verbose=args.verbose,
                dry_run=args.dry_run,
                module=current.name,
                option=[f"{k}={v}" for k, v in current_opts.items()],
            )
            cmd_run(run_ns)
        elif cmd == "report":
            cmd_report(argparse.Namespace(engagement=args.engagement, verbose=args.verbose, dry_run=args.dry_run, format=None))
        elif cmd == "help":
            console.raw("commands: list | search <t> | info <m> | use <m> | set <k> <v> | options | run | report | back | quit")
        else:
            console.warn(f"unknown command: {cmd}")
    return 0


# ---------------------------------------------------------------------------
# argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redkit",
        description="portable, offline, no-AI red team toolkit",
    )
    parser.add_argument("--version", action="version", version=f"redkit {__version__}")
    parser.add_argument("-e", "--engagement", default="default", help="engagement workspace name")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument("--dry-run", action="store_true", help="print commands without executing external tools")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="list modules")

    p_search = sub.add_parser("search", help="search modules")
    p_search.add_argument("term")

    p_info = sub.add_parser("info", help="show module options")
    p_info.add_argument("module")

    p_run = sub.add_parser("run", help="run a module")
    p_run.add_argument("module")
    p_run.add_argument("-o", "--option", action="append", metavar="key=value", help="module option (repeatable)")

    p_report = sub.add_parser("report", help="generate engagement report")
    p_report.add_argument("-f", "--format", choices=["markdown", "md", "json"], default=None)

    sub.add_parser("shell", help="interactive menu")
    sub.add_parser("version", help="print version")
    return parser


DISPATCH = {
    "list": cmd_list,
    "search": cmd_search,
    "info": cmd_info,
    "run": cmd_run,
    "report": cmd_report,
    "shell": cmd_shell,
    "version": cmd_version,
}


def main(argv: Optional[List[str]] = None) -> int:
    modules.load_all()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    handler = DISPATCH.get(args.command)
    if not handler:
        parser.print_help()
        return 1
    return handler(args)
