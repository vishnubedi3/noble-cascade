"""Report only persisted, provenance-backed findings. No placeholder claims."""

from __future__ import annotations

import hashlib
import html
import json
from typing import Any

from jsonschema import Draft7Validator

from .errors import InvalidOutput
from .models import utcnow
from .store import Store

FINDING_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": [
        "finding_id",
        "title",
        "category",
        "target",
        "description",
        "evidence_ids",
        "confidence",
        "severity",
        "impact",
        "affected_component",
        "reproduction",
        "remediation",
        "references",
        "state",
        "status",
        "provenance",
        "created_at",
    ],
    "properties": {
        "finding_id": {"type": "string", "pattern": "^finding-[0-9a-f]{16}([0-9a-f]{16})?$"},
        "title": {"type": "string", "minLength": 1},
        "category": {"type": "string", "minLength": 1},
        "target": {"type": "string", "minLength": 1},
        "description": {"type": "string", "minLength": 1},
        "evidence_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "confidence": {
            "type": "object",
            "required": ["score", "level", "evidence_count"],
            "properties": {"score": {"type": "integer", "minimum": 0, "maximum": 100}},
        },
        "severity": {
            "type": "object",
            "required": ["tier", "impact", "exploitability", "exposure", "rationale"],
            "properties": {"tier": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}},
        },
        "impact": {"type": "string"},
        "affected_component": {"type": "string"},
        "reproduction": {"type": ["object", "null"]},
        "remediation": {"type": "string"},
        "references": {"type": "array", "items": {"type": "string"}},
        "state": {
            "enum": [
                "candidate",
                "validated",
                "confirmed",
                "rejected",
                "inconclusive",
                "remediated",
                "accepted-risk",
            ]
        },
        "status": {
            "enum": [
                "OBSERVED",
                "SUSPECTED",
                "SUPPORTED",
                "VALIDATED",
                "CONFIRMED",
                "INCONCLUSIVE",
                "REJECTED",
            ]
        },
        "provenance": {
            "type": "object",
            "required": ["tool", "request_id", "operator", "grant_id"],
        },
        "created_at": {"type": "string", "format": "date-time"},
    },
}


class Reporter:
    def __init__(self, store: Store) -> None:
        self.store = store

    def collect(self) -> list[dict[str, Any]]:
        findings = self.store.list_findings()
        for finding in findings:
            errors = list(Draft7Validator(FINDING_SCHEMA).iter_errors(finding))
            if errors:
                raise InvalidOutput("persisted finding does not match reporting schema")
            for evidence_id in finding["evidence_ids"]:
                evidence = self.store.get_evidence(evidence_id)
                if (
                    not evidence
                    or evidence["request_id"] != finding["provenance"]["request_id"]
                    or evidence["target"] != finding["target"]
                    or evidence["content_hash"]
                    != hashlib.sha256(evidence["content"].encode()).hexdigest()
                ):
                    raise InvalidOutput("finding references absent, unrelated or tampered evidence")
            if finding["state"] == "confirmed" and (
                not finding["reproduction"]
                or len(finding["evidence_ids"]) < 2
                or not any(
                    (item := self.store.get_evidence(eid))
                    and item["category"] == "test-result"
                    and item["provenance"].get("independent_validation") is True
                    for eid in finding["evidence_ids"]
                )
            ):
                raise InvalidOutput("confirmed finding lacks independent reproduction")
        return findings

    def as_json(self) -> str:
        data = {
            "generator": "Noble Cascade local runtime",
            "generated_at": utcnow().isoformat(),
            "scope": "Authorized offline local analysis only",
            "data_classification": "SENSITIVE_RESULT",
            "findings": self.collect(),
        }
        return json.dumps(data, indent=2, ensure_ascii=True)

    def as_markdown(self) -> str:
        findings = self.collect()

        def safe(text: Any) -> str:
            # Never let untrusted fields create headings, links or code blocks.
            value = str(text).replace("\r", " ").replace("\n", " ")
            return (
                html.escape(value, quote=True)
                .replace("`", "&#96;")
                .replace("[", "&#91;")
                .replace("]", "&#93;")
                .replace("*", "&#42;")
            )

        lines = [
            "# Noble Cascade — authorized local findings",
            "",
            "Classification: SENSITIVE_RESULT — handle as restricted research output.",
            f"Generated: {utcnow().isoformat()}",
            "",
            "This report includes only persisted results; static matches are candidates, not vulnerabilities.",
            "Synthetic reproductions do not establish production exposure.",
            "",
            f"Findings: {len(findings)}",
            "",
        ]
        for f in findings:
            lines.extend(
                [
                    f"## {safe(f['title'])}",
                    "",
                    f"ID: {safe(f['finding_id'])} | Status: {safe(f['state'])} | CWE: {safe(f.get('cwe') or 'unclassified')}",
                    f"Target: {safe(f['target'])} | Component: {safe(f['affected_component'])}",
                    f"Severity: {safe(f['severity']['tier'])} | Confidence: {f['confidence']['score']}/100",
                    "",
                    safe(f["description"]),
                    "",
                    f"Impact: {safe(f['impact'])}",
                    f"Evidence IDs: {', '.join(safe(eid) for eid in f['evidence_ids'])}",
                    f"Remediation: {safe(f['remediation'])}",
                    "",
                ]
            )
            if f["reproduction"]:
                lines.append(f"Controlled reproduction: {safe(f['reproduction']['result'])}")
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"
