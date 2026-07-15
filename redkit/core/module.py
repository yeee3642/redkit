"""Module contract.

Every attack/recon capability in redkit is a subclass of ``Module`` decorated
with ``@register``. The CLI discovers them automatically. Keep modules pure and
deterministic: NO network calls to any AI/LLM service, ever.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Option:
    """A single module option, supplied by the operator as ``-o name=value``."""

    name: str
    help: str = ""
    default: Any = None
    required: bool = False
    choices: Optional[List[str]] = None

    def coerce(self, raw: Any) -> Any:
        """Best-effort type coercion based on the default value's type."""
        if raw is None:
            return self.default
        if isinstance(self.default, bool):
            if isinstance(raw, bool):
                return raw
            return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")
        if isinstance(self.default, int) and not isinstance(self.default, bool):
            try:
                return int(raw)
            except (TypeError, ValueError):
                return self.default
        return raw


@dataclass
class Result:
    """Structured module outcome. ``data`` is JSON-serializable."""

    ok: bool = True
    summary: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)


class Module:
    """Base class for all modules.

    Subclasses set the class attributes and implement :meth:`run`.
    """

    name: str = "base.module"
    description: str = "base module"
    phase: str = "misc"  # recon | access | postex | lateral | payloads | report
    options: List[Option] = []
    requires_tools: List[str] = []  # optional external tools (soft dependency)
    references: List[str] = []

    def run(self, opts: Dict[str, Any], ctx: "Context") -> Result:  # noqa: F821
        raise NotImplementedError(f"{self.name} does not implement run()")

    # -- option handling helpers ------------------------------------------
    @classmethod
    def option_map(cls) -> Dict[str, Option]:
        return {opt.name: opt for opt in cls.options}

    @classmethod
    def resolve_options(cls, provided: Dict[str, Any]) -> Dict[str, Any]:
        """Merge provided options with defaults and validate required ones.

        Raises ``ValueError`` if a required option is missing or a choice is
        invalid.
        """
        provided = provided or {}
        resolved: Dict[str, Any] = {}
        omap = cls.option_map()
        unknown = [k for k in provided if k not in omap]
        if unknown:
            raise ValueError(f"unknown option(s): {', '.join(unknown)}")
        for opt in cls.options:
            value = opt.coerce(provided.get(opt.name, opt.default))
            if opt.required and (value is None or value == ""):
                raise ValueError(f"required option missing: {opt.name}")
            if opt.choices and value is not None and value not in opt.choices:
                raise ValueError(
                    f"option '{opt.name}' must be one of: {', '.join(opt.choices)}"
                )
            resolved[opt.name] = value
        return resolved
