# Noble Cascade: AI-Assisted Authorized Security-Research Platform

Noble Cascade is a production-grade, modular, and policy-governed agent skill ecosystem designed for authorized vulnerability research, secure code review, and penetration testing.

## Core Architecture & Safety Model

Operating an AI agent in security-sensitive contexts requires strict governance where **the control layer strictly outranks the model layer**. Noble Cascade implements a rigorous control hierarchy:

```
[Human Operator]
      │
      ▼ (Authorized Scope & Goal)
[Human Approval Gate] (Risk-tier classification: LOW, MEDIUM, HIGH)
      │
      ▼ (Policy Enforcement)
[Governance & Scope Engine] (Deny-by-default, OpenGuardrails spec)
      │
      ▼ (Safety Guardrails)
[Command Validation & Rate Limiting]
      │
      ▼ (Execution Container)
[Sandbox Execution Layer] (Docker container + iptables firewall + mitmproxy sidecar)
      │
      ▼ (Security Reasoning & Code Skills)
[Code Analysis & Reasoning Layer] (SAST, SCA, Secret Scanning, 6-phase audit)
      │
      ▼ (Verification & Evidence)
[False-Positive Analysis & Schema Validation]
      │
      ▼ (Structured Reporting)
[Vulnerability Reports & Remediation]
```

## Directory Structure

```
agent-skills/
├── governance/        # Scope enforcement, authorization, safety policy, human approval, escalation
├── reasoning/         # Evidence analysis, hypothesis testing, false-positive analysis, confidence & severity assessment
├── code/              # Repository analysis, language detection, multi-language SAST, dependency auditing, secure code review
├── security/          # Web security, API security, authentication, authorization, cryptography review, secrets analysis, configuration security
├── operations/        # Safe reconnaissance, controlled testing, sandbox execution, rate limiting, audit logging
├── resilience/        # Prompt injection defense, untrusted content handling, tool output validation
└── reporting/         # Vulnerability reporting, reproduction PoCs, remediation, responsible disclosure
```

## Getting Started & Quick Validation

To validate the installed skill ecosystem and security controls:

```bash
python3 agent-skills/tests/validate-stack.py
```

See the [Operator Guide](docs/operator-guide.md) and [Security Model](docs/security-model.md) for full operational instructions.
