# Noble Cascade Release Attestation

Version: 0.2.0-b313e18
Commit: b313e181d4b495be1802c4a9df199dae35334112
Created: 2026-09-25T16:35:09.923575+00:00

## Hashes

- RELEASE.json: 902b3b7e53ed66be66e1b918785be943e4967e4a8ab9af29a8ddd3a5de234f82
- SBOM.spdx.json: ca637cc0937f6836535f121442c89c0658f72f3bf7fd9c292b00a35ce1848476
- SBOM.cyclonedx.json: 46c457e15729b6669e2dd740f861ea54c82b8f689a8cc7e2868a927bea12320a
- PROVENANCE.json: a7bd3468573b40ab266af3f755e751236bcb6dc47cb22ea7e3a8e32f9311a6ac
- POLICY_HASHES.json: 8adbbfed6a1244e1d87dd8eebde381373f020d3517f65c57b6352fb80f8d864a
- TEST_RESULTS.json: 5751ca4582278cad7488585bd6c79c5269e3c2d7dd58f464896cecbd39c4fd3f
- SECURITY_SPEC_HASH.json: c7d595490a51b65ec2ca5bd34dd002ec045307e0f998231094bb04964f1ff492
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: eda58018361a34eab2cb4d05707bde7f82b652d253c274a6c87bb0a7abe625b0
Signature: 46b1924d9c81161a36df4a3815996c86b56e278f09712bebdcfb4b4abbaf5d77
Key ID: 126b652aa1c3ef41

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout b313e181d4b495be1802c4a9df199dae35334112
noble release --create 0.2.0-b313e18
# compare hashes in release/
```
