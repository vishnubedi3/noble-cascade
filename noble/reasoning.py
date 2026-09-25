"""Evidence → hypothesis → validation → disproof → confidence → finding.

Severity models potential impact. Confidence models the *strength of proof*;
they do not stand in for each other. Generic static matches are candidates,
never confirmed vulnerabilities.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .errors import EvidenceValidationFailed
from .evidence import redact_sensitive
from .models import (
    ConfidenceAssessment,
    Evidence,
    EvidenceStatus,
    FalsePositiveAnalysis,
    Finding,
    FindingState,
    Reproduction,
    RiskTier,
    SeverityAssessment,
    new_id,
    utcnow,
)
from .trust import quarantine


def evaluate_observation(
    observation: dict[str, Any],
    evidence: list[Evidence],
    *,
    request_id: str,
    target: str,
    tool: str,
    version: str,
    operator: str,
    grant_id: str,
) -> Finding:
    """Construct a defensible finding from validated evidence only."""
    if not evidence or any(e.target != target or e.request_id != request_id for e in evidence):
        raise EvidenceValidationFailed("evidence is missing or tied to the wrong execution")
    source = next((e for e in evidence if e.category == "source-code"), None)
    if not source or source.content_hash != hashlib.sha256(source.content.encode()).hexdigest():
        raise EvidenceValidationFailed("source evidence was not independently integrity-checked")

    def safe(value: str) -> str:
        return quarantine(redact_sensitive(value), max_length=500).sanitized

    verified = bool(observation["verified"])
    reproduced = any(
        e.category == "test-result" and e.provenance.get("independent_validation") is True
        for e in evidence
    )
    if verified and not reproduced:
        raise EvidenceValidationFailed("verified claim lacks an independent reproduction")
    confidence = ConfidenceAssessment(
        score=94 if verified else 45,
        level="HIGH" if verified else "LOW",
        evidence_count=len(evidence),
        contradictions=0,
        rationale=(
            "Known fixture hash and source AST match; in-memory SQLite reproduction independently confirmed"
            if verified
            else "Only a syntax-level signature was observed; taint and exploitability unproven"
        ),
    )
    false_positive = FalsePositiveAnalysis(
        claim=safe(observation["title"]),
        supporting=tuple(e.evidence_id for e in evidence),
        missing=()
        if verified
        else (
            "Confirm that the interpolated value comes from an untrusted input",
            "Reproduce the issue safely with a local test",
        ),
        benign_explanations=()
        if verified
        else (
            "The value may be constant or already validated",
            "The SQL client may perform its own parameterization",
        ),
        contradictory=(),
        validation_steps=(
            "Independently re-check fixture digest and AST",
            "Compare interpolated and parameterized SQL in isolated in-memory SQLite",
        )
        if verified
        else ("Manual data-flow review", "Controlled non-destructive reproduction"),
        verdict=EvidenceStatus.CONFIRMED if verified else EvidenceStatus.INCONCLUSIVE,
        notes="Synthetic local fixture only" if verified else "Candidate, not confirmed",
    )
    severity = SeverityAssessment(
        vector="local synthetic fixture / no production exposure"
        if verified
        else "undetermined exposure",
        tier=RiskTier.MEDIUM,
        impact=5,
        exploitability=3 if verified else 1,
        exposure=0,
        rationale="Local-only evidence; production impact was not assessed",
    )
    reproduction = None
    if verified:
        reproduction = Reproduction(
            steps=(
                "Verify the known fixture's SHA-256 and interpolated SQL AST",
                "Create an in-memory SQLite table with two synthetic records",
                "Contrast unsafe interpolated query (2 rows) with parameterized query (0 rows)",
            ),
            non_destructive=True,
            controlled=True,
            result="Reproduced against the local synthetic fixture only",
        )
    return Finding(
        finding_id=new_id("finding"),
        title=safe(observation["title"]),
        category=observation["category"],
        target=target,
        description=safe(observation["description"]),
        evidence_ids=tuple(e.evidence_id for e in evidence),
        confidence=confidence,
        severity=severity,
        impact=safe(observation["impact"]),
        affected_component=redact_sensitive(f"{observation['file']}:{observation['line']}"),
        reproduction=reproduction,
        remediation=safe(observation["remediation"]),
        references=("https://cwe.mitre.org/data/definitions/89.html",),
        state=FindingState.CONFIRMED if verified else FindingState.CANDIDATE,
        status=EvidenceStatus.CONFIRMED if verified else EvidenceStatus.SUSPECTED,
        provenance={
            "source": "trusted-local-worker",
            "tool": tool,
            "tool_version": version,
            "operator": operator,
            "grant_id": grant_id,
            "request_id": request_id,
            "classification": "synthetic" if verified else "candidate",
            "false_positive_analysis": false_positive.to_dict(),
            "assessed_at": utcnow().isoformat(),
        },
        cwe=observation["cwe"],
    )
