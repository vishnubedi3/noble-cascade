# Noble Cascade Release Attestation

Version: 0.2.0-be4e56f
Commit: be4e56f271568cb32c5b4d8c30e4cda7de1dc5e8
Created: 2026-09-25T16:20:13.498335+00:00

## Hashes

- RELEASE.json: 7d193b231889ff4cb7c1be8c8b6e4dd5d2ea41c2f852e25e5bc2336bab2b812e
- SBOM.spdx.json: e8ae73cee1f3b3356a07cd007ab19a01228230464f7118f8a969e6e71ebb63fb
- SBOM.cyclonedx.json: 4fb071790b81d6dfc283fd046c87d4b099d8c73da2c4e27c914482d84aebe18f
- PROVENANCE.json: 13c7819ec86740744fdbc23fa25ba27119992050b9c652ea9350f7ab2941197c
- POLICY_HASHES.json: e53b4643dafb09d4e8e1e9946ecef019da3d200ad63a625bd8fd694f1bef9fea
- TEST_RESULTS.json: 1c4c089acccc7416cdfcf9bd4250efab65aa0fe6e0bdc7e623fdd4e26337175a
- SECURITY_SPEC_HASH.json: c7d595490a51b65ec2ca5bd34dd002ec045307e0f998231094bb04964f1ff492
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: 2aba9937a9f9369a82dac62ab35b7ad686b6f7a11334b42d6979750f9c71dbf8
Signature: c49b996e844c9b094e66a6e34e617fe4239e524aa124eea1b21ee3892a74e0ff
Key ID: 126b652aa1c3ef41

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout be4e56f271568cb32c5b4d8c30e4cda7de1dc5e8
noble release --create 0.2.0-be4e56f
# compare hashes in release/
```
