# Noble Cascade Release Attestation

Version: v0.2.0
Commit: 6a7aee02cff55f45022a9029d52166912ed22cf8
Created: 2026-09-26T04:03:15.971145+00:00

## Hashes

- RELEASE.json: 77b40ce6c12987ddc4ac234cef0425a909b1b4ce2000a5cfac0860ea021bea82
- SBOM.spdx.json: 2a6456178d6e0ecd050c2f58697d452075fa2cb86aa46c14466fc543172bee3d
- SBOM.cyclonedx.json: 2f8a3b034f60615da8741f38b725977cb5c3e21dcd7046fccfbba779b0254a55
- PROVENANCE.json: 659ef66ce3f39f6f1985f1f0a66deba6dd7332202ea94a32d15cc9a94268120f
- POLICY_HASHES.json: 007b0795cdda42c0691bfd9f03ba86210fce2b4897964fdf4896f0a90cc91dec
- TEST_RESULTS.json: 0aa6d0d8baf26051f5b4c72053e4c27612f4a7811df07ba7505df257be13475c
- SECURITY_SPEC_HASH.json: c7d595490a51b65ec2ca5bd34dd002ec045307e0f998231094bb04964f1ff492
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: 3cd4aece542fdaa3199c3a7bb9592b9a85038583ca65e6744fb2a8eeaa9d6a48
Signature: c2ac514f01d195fbb6e2a332a9fd28a848fe778a365f644509b35e1601feee57
Key ID: 126b652aa1c3ef41

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout 6a7aee02cff55f45022a9029d52166912ed22cf8
noble release --create v0.2.0
# compare hashes in release/
```
