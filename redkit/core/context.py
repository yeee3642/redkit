"""Execution context handed to every module's ``run`` method."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .console import Console
from .engagement import Engagement
from .runner import Runner


@dataclass
class Context:
    engagement: Engagement
    console: Console
    runner: Runner
    workdir: Path      # per-engagement working directory (loot, evidence, output)
    data_dir: Path     # bundled data (wordlists, cred DBs)

    def artifact_path(self, name: str) -> Path:
        """Return a path inside the engagement workdir for writing output."""
        self.workdir.mkdir(parents=True, exist_ok=True)
        return self.workdir / name
