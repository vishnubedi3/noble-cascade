# Noble Cascade Release Attestation

Version: 0.2.0-8fd3c88
Commit: 8fd3c880f26daae46f8d8eaf86a70dbabf256f4a
Created: 2026-09-25T16:17:18.220128+00:00

## Hashes

- RELEASE.json: 8109d42a64d33af8c27ebcfe29c3cdb7c1f74a63f1f19c0e6a62663bce417160
- SBOM.spdx.json: 7e816ab8afddd174405f7541cb2bbcf6974a532347a5268b7d37d4d481ae1cd4
- SBOM.cyclonedx.json: a0b4918f264ba28439aeaf61e5951bb35faad162bec269a0a79fd03a354eb0e7
- PROVENANCE.json: 36df8262489d31600d4484adf40295158cdaca6423c7a68b2d11984cfbd49933
- POLICY_HASHES.json: bdc1107a559d4ac39fdd429e149d7bbafc58c85fd66c6e163a7274b6782f0c48
- TEST_RESULTS.json: 74aa5c0e610485af06b8d946c1219161b7210720cd61833b60146208dbe37c43
- SECURITY_SPEC_HASH.json: c7d595490a51b65ec2ca5bd34dd002ec045307e0f998231094bb04964f1ff492
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: e688cb0fe75a51f6114aa29895267a39b2a9e86f89d6af8bffab5ac75b6a62ec
Signature: f9891f45ee8729cdac88744d5cb6090a18ef8828e4df7879a7a2cea12d224a45
Key ID: 126b652aa1c3ef41

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout 8fd3c880f26daae46f8d8eaf86a70dbabf256f4a
noble release --create 0.2.0-8fd3c88
# compare hashes in release/
```
