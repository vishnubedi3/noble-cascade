# Operator Guide

## Operating the Authorized Security Platform

Noble Cascade is designed for operators who possess basic programming knowledge but require strong technical capabilities, strong explanations, and robust safety controls.

### 1. Scope Configuration
Before conducting any analysis, verify your target scope in `agent-skills/governance/scope-enforcement/scope-policy.yaml`. Unlisted targets are automatically blocked by the deny-by-default engine.

### 2. Human Approval Workflow
Operations are classified into three risk tiers:
- **LOW:** Static analysis, dependency audits, secret scanning (Automatic approval).
- **MEDIUM:** Code patching, non-destructive testing (Logged and audited).
- **HIGH:** Active fuzzing, PoC execution, exploit verification (Explicit human operator sign-off required via `--approve`). The agent cannot self-approve high-risk actions.

### 3. Reviewing Findings & False-Positive Analysis
When findings are generated in `agent-skills/reporting/vulnerability-reporting/findings.json`, subject them to Phase 3 disproof validation (`VALIDATION.md`) before approval or reporting. Use the provided plain-language explanations to understand the weakness regardless of programming language.

### 4. Running Validation Tests
To ensure system integrity at any time, run:
```bash
python3 agent-skills/tests/validate-stack.py
```
