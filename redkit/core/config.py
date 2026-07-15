"""Paths and workspace resolution."""
from __future__ import annotations

import os
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent.parent   # .../redkit/redkit
DATA_DIR = PKG_ROOT / "data"
WORDLISTS = DATA_DIR / "wordlists"
CREDS_DIR = DATA_DIR / "creds"


def workspace_root() -> Path:
    """Base directory holding engagements. Override with ``REDKIT_HOME``."""
    return Path(os.environ.get("REDKIT_HOME", Path.home() / ".redkit"))


def engagement_dir(name: str) -> Path:
    return workspace_root() / "engagements" / name


def wordlist(name: str) -> Path:
    return WORDLISTS / name


def creds_file(name: str) -> Path:
    return CREDS_DIR / name
