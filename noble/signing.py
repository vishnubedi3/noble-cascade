"""Signed findings — integrity metadata for tamper detection.

Findings become security artifacts. We generate:
    finding_hash, evidence_hash, report_hash

Objective is tamper detection, not encryption. Uses SHA-256 over canonical JSON.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()


def hash_evidence(evidence: dict[str, Any]) -> str:
    # Hash only the content + provenance that matters for integrity
    payload = {
        "evidence_id": evidence.get("evidence_id"),
        "content": evidence.get("content"),
        "content_hash": evidence.get("content_hash"),
        "target": evidence.get("target"),
        "tool": evidence.get("tool"),
        "provenance": evidence.get("provenance"),
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def hash_finding(finding: dict[str, Any]) -> str:
    payload = {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "target": finding.get("target"),
        "evidence_ids": sorted(finding.get("evidence_ids", [])),
        "confidence": finding.get("confidence"),
        "severity": finding.get("severity"),
        "provenance": finding.get("provenance"),
        "state": finding.get("state"),
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def hash_report(report_data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(report_data)).hexdigest()


def sign_finding(finding: dict[str, Any], evidence_list: list[dict[str, Any]]) -> dict[str, str]:
    evidence_hashes = {e["evidence_id"]: hash_evidence(e) for e in evidence_list}
    finding_h = hash_finding(finding)
    # Composite: finding hash bound to its evidence hashes
    composite = hashlib.sha256(
        _canonical({"finding": finding_h, "evidence": sorted(evidence_hashes.values())})
    ).hexdigest()
    return {
        "finding_hash": finding_h,
        "evidence_hashes": evidence_hashes,  # type: ignore
        "composite_hash": composite,
    }


def verify_finding_integrity(
    finding: dict[str, Any], evidence_list: list[dict[str, Any]], expected_finding_hash: str
) -> bool:
    return hash_finding(finding) == expected_finding_hash
