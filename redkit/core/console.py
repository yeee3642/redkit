"""Terminal console: colored status output, tables, banners.

Pure stdlib. Colors auto-disable when output is not a TTY or NO_COLOR is set.
"""
from __future__ import annotations

import os
import sys
from typing import Iterable, List, Sequence


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("REDKIT_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


# On Windows 10+ this enables ANSI escape processing for the current console.
if os.name == "nt":
    try:
        os.system("")
    except Exception:
        pass


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"


class Console:
    """Minimal colored console. Never raises on encoding issues."""

    def __init__(self, verbose: bool = False, use_color: bool | None = None):
        self.verbose = verbose
        self.use_color = _color_enabled() if use_color is None else use_color

    def _paint(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{Ansi.RESET}"

    def _emit(self, tag: str, msg: str, color: str, stream=None) -> None:
        stream = stream or sys.stdout
        prefix = self._paint(tag, color)
        try:
            print(f"{prefix} {msg}", file=stream)
        except UnicodeEncodeError:
            safe = f"{prefix} {msg}".encode("ascii", "replace").decode("ascii")
            print(safe, file=stream)

    def info(self, msg: str) -> None:
        self._emit("[*]", msg, Ansi.BLUE)

    def good(self, msg: str) -> None:
        self._emit("[+]", msg, Ansi.GREEN)

    def warn(self, msg: str) -> None:
        self._emit("[!]", msg, Ansi.YELLOW)

    def bad(self, msg: str) -> None:
        self._emit("[-]", msg, Ansi.RED, stream=sys.stderr)

    def debug(self, msg: str) -> None:
        if self.verbose:
            self._emit("[D]", msg, Ansi.GREY)

    def raw(self, msg: str = "") -> None:
        print(msg)

    def banner(self, title: str, subtitle: str = "") -> None:
        line = "=" * max(len(title) + 4, len(subtitle) + 4, 40)
        self.raw(self._paint(line, Ansi.CYAN))
        self.raw(self._paint(f"  {title}", Ansi.BOLD))
        if subtitle:
            self.raw(self._paint(f"  {subtitle}", Ansi.GREY))
        self.raw(self._paint(line, Ansi.CYAN))

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
        rows = [[("" if c is None else str(c)) for c in row] for row in rows]
        widths: List[int] = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(cell))
        header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        self.raw(self._paint(header_line, Ansi.BOLD))
        self.raw(self._paint("  ".join("-" * w for w in widths), Ansi.GREY))
        for row in rows:
            self.raw("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))
