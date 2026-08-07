# Architecture Documentation

## Overview
Noble Cascade is structured around 7 core modular categories that encapsulate the entire lifecycle of authorized security research, from governance and scope enforcement to reasoning, code analysis, security review, operations, resilience, and reporting.

## Component Mapping & Provenance

| Category | Capability | Primary Open-Source Project | Integration Wrapper / Location |
| :--- | :--- | :--- | :--- |
| **Governance** | scope-enforcement | OpenGuardrails | `agent-skills/governance/scope-enforcement/enforce_scope.py` |
| | authorization-policy | Microsoft Agent Governance Toolkit | `agent-skills/governance/authorization-policy/authz.py` |
| | safety-policy | Agent Guardrails Template | `agent-skills/governance/safety-policy/guardrails.go` |
| | human-approval | Agent Guardrails Template | `agent-skills/governance/human-approval/approval_gate.py` |
| | escalation | SecOpsAgentKit | `agent-skills/governance/escalation/escalate.py` |
| **Reasoning** | evidence-analysis | Cloudflare Security Audit Skill | `agent-skills/reasoning/evidence-analysis/SKILL.md` |
| | hypothesis-testing | Cloudflare Security Audit Skill | `agent-skills/reasoning/hypothesis-testing/HUNTING.md` |
| | false-positive-analysis | Cloudflare Security Audit Skill | `agent-skills/reasoning/false-positive-analysis/VALIDATION.md` |
| | confidence-assessment | NVIDIA SkillSpector | `agent-skills/reasoning/confidence-assessment/confidence.py` |
| | severity-assessment | Anthropic Cybersecurity Skills | `agent-skills/reasoning/severity-assessment/SKILL.md` |
| **Code** | repository-analysis | Cloudflare Security Audit Skill | `agent-skills/code/repository-analysis/RECON.md` |
| | language-detection | SecOpsAgentKit | `agent-skills/code/language-detection/detect.py` |
| | multi-language-analysis | SecOpsAgentKit (Semgrep/Bandit) | `agent-skills/code/multi-language-analysis/run_sast.py` |
| | dependency-analysis | Security Skills (OSV-Scanner) | `agent-skills/code/dependency-analysis/audit_deps.py` |
| | secure-code-review | Anthropic Cybersecurity Skills | `agent-skills/code/secure-code-review/SKILL.md` |
| **Security** | web-security | Anthropic Cybersecurity Skills | `agent-skills/security/web-security/SKILL.md` |
| | api-security | Anthropic Cybersecurity Skills | `agent-skills/security/api-security/SKILL.md` |
| | authentication | Anthropic Cybersecurity Skills | `agent-skills/security/authentication/SKILL.md` |
| | authorization | Anthropic Cybersecurity Skills | `agent-skills/security/authorization/SKILL.md` |
| | cryptography-review | Anthropic Cybersecurity Skills | `agent-skills/security/cryptography-review/SKILL.md` |
| | secrets-analysis | Security Skills (Gitleaks) | `agent-skills/security/secrets-analysis/scan_secrets.py` |
| | configuration-security | SecOpsAgentKit (Checkov) | `agent-skills/security/configuration-security/scan_iac.py` |
| **Operations** | safe-reconnaissance | Cloudflare Security Audit Skill | `agent-skills/operations/safe-reconnaissance/recon.py` |
| | controlled-testing | Anthropic Cybersecurity Skills | `agent-skills/operations/controlled-testing/SKILL.md` |
| | sandbox-execution | Agent Sandbox | `agent-skills/operations/sandbox-execution/docker-compose.yml` |
| | rate-limiting | Agent Guardrails Template | `agent-skills/operations/rate-limiting/ratelimit.py` |
| | audit-logging | Agent Guardrails Template | `agent-skills/operations/audit-logging/logger.py` |
| **Resilience** | prompt-injection-defense | OpenGuardrails | `agent-skills/resilience/prompt-injection-defense/sanitize.py` |
| | untrusted-content-handling | Anthropic Cybersecurity Skills | `agent-skills/resilience/untrusted-content-handling/SKILL.md` |
| | tool-output-validation | NVIDIA SkillSpector | `agent-skills/resilience/tool-output-validation/validate_output.py` |
| **Reporting** | vulnerability-reporting | Cloudflare Security Audit Skill | `agent-skills/reporting/vulnerability-reporting/report_generator.py` |
| | reproduction | Cloudflare Security Audit Skill | `agent-skills/reporting/reproduction/poc_builder.py` |
| | remediation | Cloudflare Security Audit Skill | `agent-skills/reporting/remediation/remediate.py` |
| | responsible-disclosure | Anthropic Cybersecurity Skills | `agent-skills/reporting/responsible-disclosure/SKILL.md` |
