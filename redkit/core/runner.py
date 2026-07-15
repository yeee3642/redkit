"""Subprocess runner with tool detection and evidence logging.

All external-tool invocations funnel through here so they can be logged,
dry-run gated, and timed out consistently. Pure stdlib.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Union

Command = Union[str, Sequence[str]]


@dataclass
class ProcResult:
    cmd: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def text(self) -> str:
        return (self.stdout or "") + (self.stderr or "")


@dataclass
class Runner:
    console: "object"
    evidence_log: Optional[Path] = None
    dry_run: bool = False
    _tool_cache: dict = field(default_factory=dict)

    def which(self, tool: str) -> Optional[str]:
        if tool not in self._tool_cache:
            self._tool_cache[tool] = shutil.which(tool)
        return self._tool_cache[tool]

    def have(self, tool: str) -> bool:
        return self.which(tool) is not None

    def require(self, tool: str) -> Optional[str]:
        path = self.which(tool)
        if not path and self.console is not None:
            self.console.warn(f"external tool '{tool}' not found in PATH")
        return path

    @staticmethod
    def _as_list(cmd: Command) -> List[str]:
        if isinstance(cmd, str):
            return shlex.split(cmd)
        return [str(c) for c in cmd]

    def run(
        self,
        cmd: Command,
        timeout: Optional[float] = 120,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        input_data: Optional[str] = None,
    ) -> ProcResult:
        argv = self._as_list(cmd)
        printable = " ".join(shlex.quote(a) for a in argv)
        if self.console is not None:
            self.console.debug(f"exec: {printable}")
        if self.dry_run:
            self._log(printable, "(dry-run, not executed)")
            return ProcResult(argv, 0, "", "")

        start = time.time()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                input=input_data.encode() if input_data is not None else None,
            )
            res = ProcResult(
                argv,
                proc.returncode,
                _decode(proc.stdout),
                _decode(proc.stderr),
                duration=time.time() - start,
            )
        except subprocess.TimeoutExpired as exc:
            res = ProcResult(
                argv,
                -1,
                _decode(exc.stdout),
                _decode(exc.stderr),
                timed_out=True,
                duration=time.time() - start,
            )
        except FileNotFoundError:
            res = ProcResult(argv, 127, "", f"command not found: {argv[0] if argv else ''}")
        except OSError as exc:  # e.g. permission denied
            res = ProcResult(argv, 126, "", f"OS error: {exc}")

        self._log(printable, res.text)
        return res

    def _log(self, cmd: str, output: str) -> None:
        if not self.evidence_log:
            return
        try:
            with open(self.evidence_log, "a", encoding="utf-8") as fh:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                fh.write(f"\n### [{stamp}] $ {cmd}\n")
                if output:
                    fh.write(output.rstrip() + "\n")
        except OSError:
            pass


def _decode(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    return raw.decode("utf-8", "replace")
