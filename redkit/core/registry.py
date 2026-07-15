"""Global module registry.

Modules register themselves via the ``@register`` decorator at import time.
``redkit.modules.load_all()`` imports every module file so the registry is
populated before the CLI queries it.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Type

_REGISTRY: Dict[str, Type] = {}

PHASES = ["recon", "access", "postex", "lateral", "payloads", "report", "misc"]


def register(cls: Type) -> Type:
    """Class decorator that registers a Module subclass by its ``name``."""
    name = getattr(cls, "name", None)
    if not name or name == "base.module":
        raise ValueError(f"module {cls!r} must define a unique 'name'")
    if name in _REGISTRY and _REGISTRY[name] is not cls:
        raise ValueError(f"duplicate module name: {name}")
    _REGISTRY[name] = cls
    return cls


def get(name: str) -> Optional[Type]:
    return _REGISTRY.get(name)


def all_modules() -> Dict[str, Type]:
    return dict(sorted(_REGISTRY.items()))


def by_phase() -> Dict[str, List[Type]]:
    grouped: Dict[str, List[Type]] = {}
    for cls in all_modules().values():
        grouped.setdefault(getattr(cls, "phase", "misc"), []).append(cls)
    return grouped


def search(term: str) -> List[Type]:
    term = term.lower()
    hits = []
    for cls in all_modules().values():
        haystack = f"{cls.name} {cls.description}".lower()
        if term in haystack:
            hits.append(cls)
    return hits
