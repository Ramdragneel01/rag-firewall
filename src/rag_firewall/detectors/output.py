"""Defense layer 3: output PII / secret scanner.

Runs before the model response leaves the firewall. Catches the case where
benign-looking inputs cause the model to emit secrets or personal data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple

# (pattern, label, redaction)
_RULES: List[Tuple[re.Pattern[str], str, str]] = [
    # Secrets / API keys
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_api_key", "[REDACTED:OPENAI_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key", "[REDACTED:AWS_ACCESS_KEY]"),
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "aws_secret_key", "[REDACTED:AWS_SECRET]"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "github_pat", "[REDACTED:GITHUB_PAT]"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"), "private_key", "[REDACTED:PRIVATE_KEY]"),
    # PII
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "us_ssn", "[REDACTED:SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "credit_card", "[REDACTED:CC]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "email", "[REDACTED:EMAIL]"),
    # System prompt leak markers (echoes of injected admin text)
    (re.compile(r"(?i)\bmy\s+system\s+prompt\s+(is|was)\b"), "system_prompt_echo", "[REDACTED:SYSTEM_PROMPT]"),
]


@dataclass
class OutputScanResult:
    findings: List[str] = field(default_factory=list)
    sanitized: str = ""
    blocked: bool = False


# Categories that should hard-fail the response rather than redact.
_HARD_FAIL = {"private_key", "aws_secret_key"}


def scan_output(text: str) -> OutputScanResult:
    """Redact known-bad patterns from model output.

    Returns the sanitized text and the list of finding labels. If a hard-fail
    category is detected, the result is marked ``blocked`` and callers should
    refuse to forward the response.
    """
    if not text:
        return OutputScanResult(sanitized=text)

    findings: List[str] = []
    sanitized = text
    blocked = False

    for pattern, label, redaction in _RULES:
        if pattern.search(sanitized):
            findings.append(label)
            sanitized = pattern.sub(redaction, sanitized)
            if label in _HARD_FAIL:
                blocked = True

    return OutputScanResult(findings=findings, sanitized=sanitized, blocked=blocked)
