"""Defense layer 1: input prompt-injection / jailbreak detection.

The scanner is heuristic-first by design: it gives a usable, dependency-light
defense out of the box. Production deployments can plug in a classifier
(Llama Guard / Prompt Guard) by replacing :func:`score_classifier`.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import List, Tuple

# Patterns are intentionally conservative; each carries a weight and a class.
# Higher weight = stronger signal of an attack.
_PATTERNS: List[Tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|messages)", re.I), 0.85, "instruction_override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)", re.I), 0.85, "instruction_override"),
    (re.compile(r"forget\s+(everything|all)\s+(you|that).*(told|said|know)", re.I), 0.7, "instruction_override"),
    (re.compile(r"you\s+are\s+now\s+(a\s+)?(dan|jailbroken|unrestricted|developer\s+mode)", re.I), 0.95, "persona_hijack"),
    (re.compile(r"\b(dan|do\s+anything\s+now)\b", re.I), 0.6, "persona_hijack"),
    (re.compile(r"(reveal|print|show|output|dump)\s+(the\s+)?(system\s+)?(prompt|instructions)", re.I), 0.9, "system_prompt_leak"),
    (re.compile(r"what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions|prompts)", re.I), 0.85, "system_prompt_leak"),
    (re.compile(r"(/etc/passwd|/etc/shadow|\.ssh/id_rsa|\.aws/credentials)", re.I), 0.95, "data_exfiltration"),
    (re.compile(r"\bcurl\s+.*\|\s*sh\b", re.I), 0.95, "command_injection"),
    (re.compile(r"<\s*script\b", re.I), 0.6, "xss_payload"),
    (re.compile(r"\bsudo\s+rm\s+-rf\b", re.I), 0.95, "command_injection"),
    (re.compile(r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(an?\s+)?(unrestricted|uncensored|evil)", re.I), 0.8, "persona_hijack"),
    (re.compile(r"(translate|encode|decode)\s+(the\s+)?(following|this)\s+(into|to)\s+base64.{0,200}(api|key|secret|password)", re.I), 0.7, "obfuscation"),
]

_BASE64_PROBE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@dataclass
class ScanResult:
    """Outcome of a defense scan."""

    score: float
    blocked: bool
    reasons: List[str] = field(default_factory=list)
    matched_classes: List[str] = field(default_factory=list)


def _decode_base64_safely(text: str) -> str:
    """Try to decode embedded base64 blobs to expose obfuscated payloads.

    Failures are silently ignored — base64-looking strings are common in
    legitimate payloads (images, tokens, etc.).
    """
    decoded_chunks: List[str] = []
    for match in _BASE64_PROBE.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
            if decoded and any(c.isalpha() for c in decoded):
                decoded_chunks.append(decoded)
        except Exception:
            continue
    return "\n".join(decoded_chunks)


def score_heuristic(text: str) -> ScanResult:
    """Rule-based scoring. Cheap, deterministic, no external deps."""
    if not text:
        return ScanResult(score=0.0, blocked=False)

    surfaces = [text]
    decoded = _decode_base64_safely(text)
    if decoded:
        surfaces.append(decoded)

    max_score = 0.0
    matched_classes: List[str] = []
    reasons: List[str] = []

    for surface in surfaces:
        for pattern, weight, attack_class in _PATTERNS:
            if pattern.search(surface):
                if weight > max_score:
                    max_score = weight
                if attack_class not in matched_classes:
                    matched_classes.append(attack_class)
                    reasons.append(f"matched:{attack_class}")

    return ScanResult(
        score=max_score,
        blocked=False,  # caller applies threshold
        reasons=reasons,
        matched_classes=matched_classes,
    )


def score_classifier(text: str) -> ScanResult:  # pragma: no cover - extension point
    """Pluggable classifier hook. Replace with Llama Guard / Prompt Guard.

    The default implementation is a no-op so the firewall runs without GPU
    or large model dependencies.
    """
    return ScanResult(score=0.0, blocked=False)


def scan_input(text: str, threshold: float) -> ScanResult:
    """Combine heuristic and classifier signals into a single decision."""
    heur = score_heuristic(text)
    clf = score_classifier(text)
    score = max(heur.score, clf.score)
    reasons = heur.reasons + clf.reasons
    classes = list({*heur.matched_classes, *clf.matched_classes})
    return ScanResult(
        score=score,
        blocked=score >= threshold,
        reasons=reasons,
        matched_classes=classes,
    )
