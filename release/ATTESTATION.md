# Noble Cascade Release Attestation

Version: 0.2.0-46a7404
Commit: 46a74040beb1484887731bc9ac8b41875debcc2e
Created: 2026-09-25T15:47:32.389826+00:00

## Hashes

- RELEASE.json: e186bc6ce157b47b0ff9f392b5ec14881342fb88205b5bba8a6d7f090246bad2
- SBOM.spdx.json: 0b30848d16b8f10639684d5e08f8dcbf5feb2081e6fbe54ba3ce690247e6f910
- SBOM.cyclonedx.json: 1be5528dea75d1f85f96f1205ab9f9021090d7e7e0ee1635a21b30ee891a6320
- PROVENANCE.json: b98b25129ed152700ebe8172373bab3949200d121594537c916c4f596bd92892
- POLICY_HASHES.json: b65a19e7d3b77fcdcb0b374ddfd248623e2326d9713d6d94874c1f9a2e7a6f1e
- TEST_RESULTS.json: 35c620960bed8d315e3b0833a89900eaecaaa1186dfcf2f2b8486fbbcae9caaa
- SECURITY_SPEC_HASH.json: cca29e37addf76211bc7fbe4f88e1c214224248a6eb1ede7e14d748b3ad71d0b
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: 2bc636545485404fb52c9866d749bfb5ea7de00389ae6a85f5798037254b6110
Signature: 3fb505e17e12a12627f47aa3ea3fbfe8516c99d5e823109749a262debbbcbce4
Key ID: db309be0c4d8e96a

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout 46a74040beb1484887731bc9ac8b41875debcc2e
noble release --create 0.2.0-46a7404
# compare hashes in release/
```
