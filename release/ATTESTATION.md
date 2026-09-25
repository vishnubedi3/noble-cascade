# Noble Cascade Release Attestation

Version: 0.2.0-de40871
Commit: de408712a75726585a857b5be3db011afbb12ee7
Created: 2026-09-25T16:13:54.278085+00:00

## Hashes

- RELEASE.json: 213300aaa3cd31d22d62c4cf5606350354188dd960b9b54c34862fffa8611390
- SBOM.spdx.json: 6741401bba4c2028ac8f0cc33f7fa04f126bf5e6bb92439eaa2ab857d7ab9fa6
- SBOM.cyclonedx.json: f5a521a5e36610234984c8777b36c7b0cfc26056d0f4819251d97cea9a63e147
- PROVENANCE.json: c605718047c1989e7ea9e3bd68f7f7a3e695201d4ad745ab8212bf9e84ab0a83
- POLICY_HASHES.json: d056ffdf1e32892fea44c37067c1c778a89e86216c4e7afa6b284e0838b566e9
- TEST_RESULTS.json: ceff486a2cc12c540c970bbf0cc6fc73fb5d99854739f4748c31e8676e4d047d
- SECURITY_SPEC_HASH.json: c7d595490a51b65ec2ca5bd34dd002ec045307e0f998231094bb04964f1ff492
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: 5f017b19fe137aea463126a28a144e3addb09284f82cc4e66549317f223f3e92
Signature: 25e1450600a2414b451675896923da74bf2371c99727642f6048b648c787496b
Key ID: db309be0c4d8e96a

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout de408712a75726585a857b5be3db011afbb12ee7
noble release --create 0.2.0-de40871
# compare hashes in release/
```
