"""Trust hierarchy and data classification.

Authority order (highest first)::

    TRUSTED_POLICY > OPERATOR_INPUT > EXECUTION_POLICY > DERIVED_AGENT_DATA
                   > TOOL_OUTPUT > TARGET_CONTENT > EXTERNAL_CONTENT

Content discovered inside a target is *data*, never an instruction. ``quarantine``
labels untrusted text so downstream consumers can refuse to treat it as policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum


class TrustLevel(IntEnum):
    """Ordered trust levels; a higher value may not be overridden by a lower one."""

    TRUSTED_POLICY = 60
    OPERATOR_INPUT = 50
    EXECUTION_POLICY = 40
    DERIVED_AGENT_DATA = 30
    TOOL_OUTPUT = 20
    TARGET_CONTENT = 10
    EXTERNAL_CONTENT = 5
    SECRET = 0

    def outranks(self, other: TrustLevel) -> bool:
        return self.value > other.value


class DataClassification(IntEnum):
    POLICY = 60
    OPERATOR = 50
    AGENT_DERIVED = 30
    TOOL_RESULT = 20
    TARGET = 10
    EXTERNAL = 5
    SENSITIVE_RESULT = 3
    SECRET = 0


INJECTION_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.I
    ),
    re.compile(r"disregard\s+(all\s+)?(prior|previous|the)\s+(instructions|rules|policy)", re.I),
    re.compile(
        r"(reveal|print|output|repeat)\s+(your\s+)?(system\s+prompt|instructions|rules)", re.I
    ),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|jailbroken)", re.I),
    re.compile(r"override\s+(the\s+)?(security\s+)?(policy|rules|guardrails|controls)", re.I),
    re.compile(
        r"(exfiltrate|send|post|upload)\s+(this\s+)?(data|credentials|secrets|keys)\s+to", re.I
    ),
    re.compile(r"new\s+(system\s+)?(instructions?|rules?)\s*:", re.I),
    re.compile(r"</?\s*(system|assistant|tool|policy)\s*>", re.I),
)


@dataclass(frozen=True, slots=True)
class QuarantineResult:
    """Result of treating untrusted text strictly as data."""

    sanitized: str
    detections: tuple[str, ...]
    hostile: bool

    @property
    def detection_count(self) -> int:
        return len(self.detections)


def quarantine(text: str, *, max_length: int = 200_000) -> QuarantineResult:
    """Neutralise embedded instructions in untrusted content.

    The text is never executed and never promoted above ``TARGET_CONTENT``.
    Control characters are stripped (log-injection defence) and the content is
    truncated so oversized payloads cannot exhaust memory.
    """
    truncated = text[:max_length]
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", truncated)
    detections: list[str] = []
    for pattern in INJECTION_SIGNATURES:
        if pattern.search(cleaned):
            detections.append(pattern.pattern)
            cleaned = pattern.sub("[QUARANTINED_INSTRUCTION]", cleaned)
    return QuarantineResult(
        sanitized=cleaned,
        detections=tuple(detections),
        hostile=bool(detections),
    )


def label_trust(source: str) -> TrustLevel:
    """Map a provenance source string to a trust level (deny-by-default lowest)."""
    mapping = {
        "policy": TrustLevel.TRUSTED_POLICY,
        "operator": TrustLevel.OPERATOR_INPUT,
        "execution-policy": TrustLevel.EXECUTION_POLICY,
        "agent": TrustLevel.DERIVED_AGENT_DATA,
        "tool": TrustLevel.TOOL_OUTPUT,
        "target": TrustLevel.TARGET_CONTENT,
        "external": TrustLevel.EXTERNAL_CONTENT,
    }
    return mapping.get(source.lower(), TrustLevel.EXTERNAL_CONTENT)
