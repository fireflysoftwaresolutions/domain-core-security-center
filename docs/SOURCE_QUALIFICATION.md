# Source-parent qualification and release boundary

The receiver candidate uses generic Jafly principal, tenant-projection and strict-policy APIs present in published framework `26.10.23`. The service still declares released `firefly-parent:26.10.6`; that immutable published parent selected framework `26.10.20`. Ordinary released-parent compilation/adoption is therefore blocked until the coordinated parent/BOM release is published and deliberately adopted. This candidate does not overwrite parent 6 or add individual framework version overrides.

The isolated hosted workflow checks out the exact public corrected parent source `6442bd51733ade4d5f4583e1afe812dd2c520b40`. In the ephemeral source fixture only, it changes one owning parent `relativePath` to that source file. Both source parent and BOM references must equal `26.10.23`. No version, SDK, specification or other source is rewritten. The parent is not installed or deployed over the released artifact.

## Successful hosted source qualification — 2026-10-31

[PR #1](https://github.com/fireflysoftwaresolutions/domain-core-security-center/pull/1), head `88d8a018930379c30e783bfa7dd7fed438e7313f`, completed [hosted run 41239679109](https://github.com/fireflysoftwaresolutions/domain-core-security-center/actions/runs/41239679109) with **SUCCESS**. The run executed the PR merge checkout `f886ff74047b4a19f5b6b4d9746e649cfb40f4fa`; this is the executed source identity, distinct from the PR head.

The bounded [source-summary artifact 13057490095](https://github.com/fireflysoftwaresolutions/domain-core-security-center/actions/runs/41239679109/artifacts/13057490095) records Maven exit **0** with the exact source parent `6442bd51733ade4d5f4583e1afe812dd2c520b40` and Jafly train `26.10.23`. The fixture changed **one owning parent `relativePath` only**, with no version, SDK or specification rewrite and no installation/publication over released parent 6.

| Observed result | Count |
| --- | ---: |
| Reported tests | 160 |
| Passed | 138 |
| Skipped | 22 |
| Failures | 0 |
| Errors | 0 |

All 22 skips are native integration coverage: **6 Cognito, 7 Keycloak, and 9 Redis tests**. They are not provider or cache acceptance. `ReceiverOpenApiContractTest` passed its one test through the actual original producer `/v3/api-docs` harness, including emitted bearer authentication metadata and absent unsupported legacy operations; no generated specification or SDK was hand-edited to obtain that result.

The artifact records these exact POM identities:

- Original service POM SHA-256: `7ef089bf4d60d0be52156bc470a27fb03e01b2d9abda30c725811bd23f3018ba`.
- Source-fixture POM SHA-256: `782c32c8d58b4c3b5d31b887d40a439f853030cb7b9b3247e3e385160ccb2c31`.

This successful run establishes the **exact source-parent fixture's compilation, test and original-producer assertions**. It does **not** establish ordinary published `firefly-parent:26.10.6` adoption, a new service/SDK publication, strict native cache/revocation capability, native-provider qualification, delegated machine-to-human acceptance, or production acceptance. No local Java/Maven/test/dependency/container execution was performed to update this record.

The workflow runs the genuine Maven `verify` lifecycle with an isolated repository and reports the exact service/parent source identities, the two POM hashes, Maven exit and observed JUnit counts. A green source-fixture job is **not** published parent adoption, a new service/SDK release, native cache revocation proof or live-provider/consumer acceptance. Dependency resolution, compiler, test or original-producer failures remain failures; the fixture does not invent successful evidence or bypass missing producer generation.

Raw provider/Maven logs stay private to the ephemeral runner. Only a bounded redacted error summary and report counts are exposed. Generated SDK/spec files are not hand-edited. Any resulting original producer output needs its own provenance/review before publication.

Session-cache integration also remains open until a genuine shared primary-only/no-L1/no-fallback capability propagates storage failures and is qualified with the real backend. The candidate's positive liveness/generation fences assume coherent backend operations and do not convert cache fallback or a stale restore into authoritative revocation. The upstream framework lane owns that provider-neutral capability.
