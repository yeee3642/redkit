"""redkit core framework: console, runner, engagement store, module contract."""
from .console import Console
from .context import Context
from .engagement import Engagement
from .http import (
    WEB_COMMON_OPTIONS,
    HttpClient,
    Response,
    client_from_opts,
    parse_headers,
)
from .module import Module, Option, Result
from .registry import all_modules, by_phase, get, register, search
from .runner import ProcResult, Runner

__all__ = [
    "Console",
    "Context",
    "Engagement",
    "Module",
    "Option",
    "Result",
    "ProcResult",
    "Runner",
    "HttpClient",
    "Response",
    "WEB_COMMON_OPTIONS",
    "client_from_opts",
    "parse_headers",
    "register",
    "get",
    "all_modules",
    "by_phase",
    "search",
]
