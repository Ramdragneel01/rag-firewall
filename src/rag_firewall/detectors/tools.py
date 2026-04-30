"""Defense layer 2: tool-use allowlist.

Inspects OpenAI/Anthropic-style ``tools`` arrays on chat-completion requests
and rejects any tool whose name is not on the allowlist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, List, Sequence


@dataclass
class ToolScanResult:
    blocked: bool = False
    rejected_tools: List[str] = field(default_factory=list)


def _extract_tool_names(payload: dict[str, Any]) -> Iterable[str]:
    """Yield tool names from common request shapes."""
    tools = payload.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict):
                # OpenAI style: {"type": "function", "function": {"name": "..."}}
                fn = tool.get("function")
                if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                    yield fn["name"]
                # Anthropic style: {"name": "...", "input_schema": {...}}
                elif isinstance(tool.get("name"), str):
                    yield tool["name"]
    # Legacy ``functions`` array
    functions = payload.get("functions")
    if isinstance(functions, list):
        for fn in functions:
            if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                yield fn["name"]


def scan_tools(payload: dict[str, Any], allowlist: Sequence[str]) -> ToolScanResult:
    """Reject requests that declare disallowed tools.

    An empty ``allowlist`` disables the check (allow-all).
    """
    if not allowlist:
        return ToolScanResult()

    allowed = set(allowlist)
    rejected = [name for name in _extract_tool_names(payload) if name not in allowed]
    return ToolScanResult(blocked=bool(rejected), rejected_tools=rejected)
