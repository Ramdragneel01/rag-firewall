"""Inspection pipeline shared by the proxy and unit tests.

Pulled out of the FastAPI route so the defense logic is independently
testable without an HTTP server or upstream dependency.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List

from .config import Settings
from .detectors import scan_input, scan_output, scan_tools


@dataclass
class InspectionDecision:
    allowed: bool
    status_code: int = 200
    error_code: str = ""
    public_message: str = ""
    audit_classes: List[str] = field(default_factory=list)
    score: float = 0.0


def _extract_user_text(payload: dict[str, Any]) -> str:
    """Concatenate all user-controlled text from a chat-completion payload.

    Supports OpenAI ``messages`` and Anthropic ``messages`` shapes plus
    legacy ``prompt`` strings.
    """
    parts: List[str] = []

    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        parts.append(prompt)

    messages = payload.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") == "system":
                # System messages are operator-controlled; don't scan them.
                continue
            content = msg.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                # Multi-modal content blocks
                for block in content:
                    if isinstance(block, dict):
                        text = block.get("text")
                        if isinstance(text, str):
                            parts.append(text)

    return "\n".join(parts)


def inspect_request(payload: dict[str, Any], settings: Settings) -> InspectionDecision:
    """Run input + tool defense layers against an outbound request."""
    if settings.enable_tool_allowlist:
        tool_result = scan_tools(payload, settings.tool_allowlist)
        if tool_result.blocked:
            return InspectionDecision(
                allowed=False,
                status_code=403,
                error_code="tool_not_allowed",
                public_message="Request rejected by firewall policy.",
                audit_classes=["tool_not_allowed"],
            )

    if settings.enable_input_scanner:
        text = _extract_user_text(payload)
        result = scan_input(text, settings.injection_threshold)
        if result.blocked:
            return InspectionDecision(
                allowed=False,
                status_code=400,
                error_code="prompt_injection_detected",
                public_message="Request rejected by firewall policy.",
                audit_classes=result.matched_classes,
                score=result.score,
            )

    return InspectionDecision(allowed=True)


def inspect_response_text(text: str, settings: Settings):
    """Run output defense layer over a model response. Returns scan result."""
    if not settings.enable_output_scanner:
        from .detectors.output import OutputScanResult
        return OutputScanResult(sanitized=text)
    return scan_output(text)
