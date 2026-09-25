# Drift Report — Example

This is an example drift report. Generate a live one via:

```bash
noble drift --json
noble drift
noble drift --baseline  # to establish new baseline after authorized change
```

## Current baseline (2026-09-25)

```json
{
  "policy_version": "1.0.0",
  "policy_hash": "069153344401179e451cff7f39ea59be6c07f4db20b8e32af89d18d3e2c4d72d",
  "configuration_hash": "72e5f9f8c956cf242a5659807d27642f174c3c2455a184ee8078d129596e763c",
  "worker_image_digest": "cfdeaeb1877498f89fe054f44206eeafa6bd5a500ec9ee3c455fe3034f768f78",
  "dependency_hash": "d0fd4e1d9a99218255fa1903d4a4f2021ce48b2cb455ddd9168f1ba7c80c53a0",
  "tool_versions_hash": "422bf65994e9404d1311fa4f2d24045e6657de7a6b579e6361ff85f61f869ff8"
}
```

## When drift is detected

Example output after modifying `config/runtime.yaml`:

```
DRIFT DETECTED:
  configuration_hash:
    baseline: 72e5f9f8...
    current:  9a1b2c3d...
  policy_hash:
    baseline: 06915334...
    current:  abcd1234...
```

The system records `policy_hash` etc. per execution in the ledger, so historical executions remain attributable to the exact policy that governed them, even after drift.

## How to handle drift

1. Review the change: `git diff config/runtime.yaml` or `git diff agent-skills/governance/scope-enforcement/scope-policy.yaml`
2. Verify it was authorized: check approval, PR, and `noble audit` events
3. If authorized, establish new baseline:

```bash
noble drift --baseline
```

4. If unauthorized, investigate: `noble audit --verify`, `noble ledger`, `noble health`

## What drift detection covers

- Worker image changed (digest of `noble/builtins/worker.py`)
- Tool version changed (hash of registry tool versions)
- Policy changed (hash of `scope-policy.yaml`)
- Dependency changed (hash of `requirements.lock`)
- Configuration changed (hash of `config/runtime.yaml`)

See `noble/drift.py` for implementation.
