# Security Model & Threat Model

## Security invariants

1. No tool runs without allowlisted scope, an active exact-target/action/purpose/permission grant, and registry preconditions. Unknown is deny.
2. A local OS caller cannot claim a different principal through `USER`/`LOGNAME`. A forged requester or grant ID cannot create authorization.
3. A HIGH/CRITICAL action requires a separate target/scope/risk/request-bound human approver. This local version registers no high-risk executable tools; a boolean `--approve` is refused.
4. No untrusted target content, source comment, filename, or tool output becomes policy or a trusted instruction. All source data is labeled/quarantined.
5. Raw scanner stdout cannot become a confirmed finding. Output must match schema, request, target, version and source; the only confirmed path separately checks the synthetic fixture and re-runs an in-memory reproduction.
6. Every execution passes a rate/concurrency reservation and records policy/execution/validation decisions; a pre-execution audit failure prevents launching a tool.
7. If a required sandbox/network/credential boundary is unavailable, the tool is refused; no silent fallback or generic shell runner exists.
8. Findings must reference existing hashed evidence from the same target and request; reports distinguish certainty (confidence) from consequence (severity).

Automated coverage: `tests/invariants/`, `tests/security/`, and `tests/regression/`. A passing suite is **not** a proof of security outside these boundaries.

## Threats, controls, detection, response

| Threat → trust boundary | Control | Detection → response |
| --- | --- | --- |
| Malicious operator tries out-of-scope repo, lookalike domain, CIDR expansion, encoded URL or symlink | Normalize first; anchored rules; forbidden rules take precedence; CIDR must be fully contained; local paths realpath inside root | PolicyDecision DENY/UNKNOWN + audit; no tool selected |
| Forged/expired grant or impersonated principal | Random grant ID, OS UID identity, exact target/action/purpose/role/privileges, bounded expiration | AuthorizationDenied + audit; no execution |
| Replayed/concurrent request ID | SQLite `BEGIN IMMEDIATE` reservation, never auto-expires | InvalidInput; prior result untouched; new ID required for recovery |
| Forged/expired/reused/self-issued approval | PENDING→APPROVED/REJECTED/EXPIRED/REVOKED, compare-and-swap, separate granted principal, request fingerprint/scope/risk/expiration | ApprovalRequired/Invalid/Expired + audit; no HIGH tool registered |
| Malicious filename/argument → shell | Registry-fixed `python -I` worker path; JSON-schema params; subprocess argv list and `shell=False`; untrusted text never becomes executable code | InvalidInput/ToolUnknown/InvalidOutput; process killed on timeout/output overflow |
| Compromised third-party scanner → filesystem or network escape | No external scanner registered. Reference Docker compose has `network_mode: none`; Python worker is trusted, read-only builtin only | ToolUnavailable/SandboxFailure, not a fake successful scan |
| Malicious repo prompt injection/tainted code | Treat source as data, control-char sanitization/quarantine, no target code import or arbitrary `eval`; snippets are untrusted even when evidence is recorded | `quarantined=true` provenance, no change in authority |
| Malicious tool output → false report/data poisoning | JSON Schema, duplicate-key rejection, ID/target/tool/version/size and exact file-line checks; fixture digest and independent SQLite check | InvalidOutput; zero findings from invalid output |
| Credential in URL/source/log | URLs with credentials/query rejected; field-aware redaction; no raw stdout in logs; state permissions 0700/0600 | Sanitized audit/evidence, no secret supplied to worker |
| Audit tampering/log injection | Owner-only SQLite; escaped JSON, bounded fields, SHA-256 event chain; `noble audit --verify` | Chain mismatch reported; this is **not** protection from a malicious same-UID process rewriting the DB and hashes |
| Rate/concurrency abuse | Atomic per-principal+tool+target 60 s limit + global count + active leases; child wall/CPU/memory/fd/output limits | RateLimited/ToolTimeout with audit; stale leases expire after timeout grace |
| Supply-chain/version drift | Version constraints plus hash-pinned runtime and dev lockfiles; no auto-fetch of scanner rules or code | Hash-locked installation and manual test/audit catch drift; `noble doctor` names unavailable upstream projects. CI enforcement is active (`.github/workflows/`); owner-level branch protection remains a manual step (see `docs/maintainer-security-checklist.md`). |
| Network exfiltration, DNS rebinding, redirect | **No network-capable registered tool**; network policy always denies and process boundary forbids network-marked tools | NetworkDenied/SandboxFailure; never follow redirects or resolve DNS |

## Assumptions and known limitations

- **Trust anchor:** repo-owned code, `config/runtime.yaml`, scope YAML and the local OS account are trusted. This is not a security boundary against code already running as that OS user, direct database edits, an attacker changing the checkout, or a malicious grant issuer. The `noble authorize` step is an explicit local administrative act **not an independently verified legal authorization**. Obtain real authorization separately.
- **Isolation:** process limits cap resources but do not prevent file reads or outbound sockets if the trusted worker code is compromised. There is no seccomp, container runtime, dedicated non-root OS account, or egress firewall integrated with `NobleEngine`; therefore **only trusted, offline, read-only built-ins** are permitted. The reference Docker YAML is never invoked by the CLI.
- **Scope** for repo/domain/IP is informational until a compatible registry tool exists. No network scan, fuzz, production verification, exploit, auth testing, repository clone, credential acquisition, destructive command, or unaudited subprocess capability is registered. Even a permitted `.local` host cannot cause a network request.
- **Evidence coverage** is intentionally narrow: AST flags interpolated `.execute()` calls; it does not perform interprocedural taint analysis, SCA, general secret scanning, cryptographic review, full path traversal/SSRF/XSS detection, or continuous monitoring. Synthetic confirmation proves only the *fixture*, not a real-world target.
- **Secrets:** field-aware redaction handles common key/value formats and known token shapes; it is not a complete DLP system. Do not put real secrets in target content or free-form fields. Do not feed raw tool output to an LLM as instructions.
- **Approvals:** state-machine primitives are tested, but a single-user CLI plus owner-only state cannot attest an independently authenticated second human. No HIGH action is available until an external identity, audit-atomic approval service, and sandbox are implemented.
- **Audit:** append chain detects some tampering but same-user filesystem access permits replacing the entire SQLite file; external/WORM shipping is not implemented. Final audit or persistence failure after a tool ran can make a result unavailable; pre-execution failures stop the tool.
- **Platform:** designed/tested on Linux and Python 3.11; `pwd`, POSIX rlimits, process groups, and SQLite are expected. No browser/API surface exists, so API authentication/browser checks are not applicable.

Never use the local fixture outside a controlled test; its intentionally unsafe SQL is not suitable for deployment.
