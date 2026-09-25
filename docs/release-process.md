# Reproducible Release Process (Phase 1 & 2)

Every release is cryptographically reproducible and SLSA L1 provenance-tracked.

## Immutable inputs

- Git tag (immutable) + commit SHA
- `pyproject.toml`, `requirements.lock` (hash-pinned), `requirements-dev.lock`
- `config/runtime.yaml` (configuration_hash)
- `agent-skills/governance/scope-enforcement/scope-policy.yaml` (policy_hash)
- `noble/builtins/worker.py` (worker_image_digest)
- `docs/security-spec.json` (security_spec_hash)

All hashed via SHA-256.

## Release creation

```bash
noble release --create 0.2.0
# or auto-tag from git
noble release --create
```

Creates `release/`:

```
release/
├── RELEASE.json              # version, commit, hashes, test manifest
├── SBOM.spdx.json            # SPDX 2.3
├── SBOM.cyclonedx.json       # CycloneDX 1.5
├── PROVENANCE.json           # SLSA v1 provenance
├── POLICY_HASHES.json        # policy/config/worker/spec hashes
├── TEST_RESULTS.json         # pytest summary
├── SECURITY_SPEC_HASH.json   # spec + hash
├── WORKER_DIGESTS.json       # worker digest
├── ATTESTATION.md            # human-readable attestation
└── ATTESTATION.json          # machine attestation (HMAC-SHA256)
```

## Release tags as security boundaries (Master Prompt IV)

```
Commit -> Verified main -> Release candidate -> Certification -> Tag
  -> Artifacts -> Attestation
```

A release tag identifies exactly which source was certified: tags are created
only from verified `main` (maintainer discipline, see
`docs/maintainer-security-checklist.md`), and `noble release --verify` binds
the tag to the certified source mechanically (below). Release flow:

```bash
git checkout main && git pull --ff-only
./verify-everything.sh            # all 20 checks must pass
noble certify                     # must print CERTIFIED
git tag -a vX.Y.Z -m "Noble Cascade vX.Y.Z"
noble release --create vX.Y.Z     # artifacts bound to tag + commit
noble release --verify            # no-drift proof must pass
git push origin main vX.Y.Z
```

## Verification without trust (no release drift)

```bash
noble release --verify
# or
python -m noble release --verify --json
```

Proves `certified source == tagged source == built source == attested source`.
Any mismatch fails:

- All 9 required files present
- Certified source is HEAD or an ancestor of HEAD with no governed file changed since certification (no release drift; regenerate after any source change). `RELEASE.json` records whether the build tree was clean — authoritative release evidence comes from a clean CI checkout
- Exact git tag == stored `git_tag` when HEAD is tagged (no tag drift)
- Artifact bytes == `POLICY_HASHES.json` hashes (no artifact replacement)
- Attestation HMAC verifies against repo-derived key (worker.py hash)
- Stored policy/config/worker hashes == current (no drift)
- SBOMs are valid SPDX/CycloneDX

Noble attestation (HMAC-SHA256 over canonical JSON) is the primary chain. If
GitHub artifact attestations are adopted later, they form cross-system
provenance (`Noble attestation + GitHub attestation`) — never a replacement.

## Reproducibility

```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout <commit-from-RELEASE.json>
noble release --create <same-version>
diff -r release release/  # hashes must match
```

## SBOM & Provenance

- SBOM includes runtime deps, build deps, tool binaries (python3, git), licenses, purls, hashes
- Provenance `predicateType: https://slsa.dev/provenance/v1` with builder `local+noble-cascade`, materials = git commit + all input hashes
- Both generated as part of `noble release` and via `noble sbom` / `noble provenance`

## Attestation

Local deterministic HMAC-SHA256 over canonical JSON of all artifact hashes. Key = SHA256(worker.py + workspace_root). For production, replace with Sigstore/cosign; verification is offline.

```
payload = {release,spdx,cyclonedx,provenance,policy_hashes,...}
signature = HMAC(key, canonical_json(payload))
```

Verify: `noble attest --file release/RELEASE.json` or `noble release --verify`

## Digest pinning

Every artifact answers “Exactly which source created me?” via:

- `release/PROVENANCE.json` -> git commit + input hashes
- `release/POLICY_HASHES.json` -> policy/config/worker/spec digests
- `release/SBOM.*.json` -> purl + hash per dependency

No network fetch at verification time.

## CI

Hardened workflow `.github/workflows/ci-hardened.yml` pins actions by SHA, forbids `pull_request_target`, uses `persist-credentials: false`, hash-checks locks, verifies SBOM/provenance, and uploads release as tamper-evident artifact.
