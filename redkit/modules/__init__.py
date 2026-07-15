"""Module auto-discovery.

``load_all()`` walks this package and imports every submodule so that each
``@register``-decorated class populates the registry. Dropping a new
``*.py`` file into any subpackage is enough to make its modules available —
no manual wiring required.
"""
from __future__ import annotations

import importlib
import pkgutil
import warnings


def load_all() -> None:
    package = importlib.import_module(__name__)
    for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        # skip private/helper modules by convention (leading underscore)
        leaf = info.name.rsplit(".", 1)[-1]
        if leaf.startswith("_"):
            continue
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # a broken module must not kill the whole CLI
            warnings.warn(f"failed to load module '{info.name}': {exc}")
