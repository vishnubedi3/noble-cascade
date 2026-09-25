# Compatibility and Deprecation Policy — Noble Cascade

## Compatibility guarantees

The following surfaces are versioned under `pyproject.toml` `version`
(current: 0.2.0) and covered by the guarantee matrix:

| Surface | Guarantee |
|---|---|
| CLI (`noble <command> [--json]`) | Flag and subcommand names stable within a minor version; `--json` schemas only gain optional keys |
| Replay records (`noble replay --json`) | `request_id`, `execution_id`, `read_only: true`, evidence/findings shape stable; consumers must ignore unknown keys |
| Audit records (`noble audit --json`) | Chained event schema stable; chain verification accepts records written by the same major version |
| Findings (`noble findings --json`) | Finding IDs and hash fields stable |
| Policies (`agent-skills/governance/scope-enforcement/scope-policy.yaml`, `config/runtime.yaml`) | Schema validated by `noble/config_schema.py`; unknown keys rejected, so additions are explicit |
| Release artifacts (`release/*.json`) | Key additions only; `noble release --verify` from version N verifies artifacts created by version N |
| `docs/security-spec.json` | `noble spec --verify` fails on drift; regeneration is a reviewed change |

Breaking changes require a minor (0.x) version bump and a note in the release
attestation (`release/ATTESTATION.md`); removal of a security-relevant
interface requires a major version bump once 1.0 exists.

## Deprecation policy

Every deprecated interface must carry, in code and docs:

1. introduction version (when it first shipped)
2. deprecation reason (why it is going away)
3. migration path (exact replacement command/config)
4. removal target (version after which it stops working)

Rules:

- Deprecated interfaces keep working (with a warning) until the removal target.
- Security-relevant interfaces are never silently removed: removal is a
  security-critical change (`governance-kernel` rule) needing governance review.
- `noble spec --verify` must keep passing across a deprecation: the spec
  records deprecated surfaces until removal.

## Current deprecations

None. The legacy `agent-skills/` wrappers were never registered runtime tools
and are not covered by this policy (historical inventory only).
