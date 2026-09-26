# Noble Cascade Release Attestation

Version: v0.2.0
Commit: c8709e7a0da277b059aa90d26b4a422de374edbe
Created: 2026-09-26T04:10:24.674816+00:00

## Hashes

- RELEASE.json: 66d7883b59b502e2c91c9e50f82999b58a777b73a01391ac34f22df0bf6fde06
- SBOM.spdx.json: 1bdc9222fe26dbb3d07dce61b74a574bc60286444ff6070b6f77531388c3f461
- SBOM.cyclonedx.json: afef1fee8809a58cec42e58a0816e8e553566eeb5ffb6f1bc7bb03f1c6cbef1e
- PROVENANCE.json: c4b8ad59344b56749c812c6f6f96afa096b3e72f3980f624eca3b27bdde66427
- POLICY_HASHES.json: b35923483f7ab4770d89117690b8dfb4faaa6a64b733ddca920a6c1072186ced
- TEST_RESULTS.json: ee93d84a8dbfe5ac65394f9e1f682c101d0628dbbc540d49e2bf8421dc61b2ad
- SECURITY_SPEC_HASH.json: c7d595490a51b65ec2ca5bd34dd002ec045307e0f998231094bb04964f1ff492
- WORKER_DIGESTS.json: 213da6da3d3212dbdaee7c972b8c7ac464f36fa2193c97f9e77576b41782a83f

## Attestation

Algorithm: HMAC-SHA256
Digest: 5364c2129952b62c956a874f395e7e1903fa590f7f04729624221143889cc1a3
Signature: e5c7f325b77eab13a4960ac5b25f91151515c2038b8fde801add7fbda7f87b09
Key ID: 126b652aa1c3ef41

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout c8709e7a0da277b059aa90d26b4a422de374edbe
noble release --create v0.2.0
# compare hashes in release/
```
