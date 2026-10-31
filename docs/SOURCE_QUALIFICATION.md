# Source-parent qualification and release boundary

The receiver candidate uses generic Jafly principal, tenant-projection and strict-policy APIs present in published framework `26.10.23`. The service still declares released `firefly-parent:26.10.6`; that immutable published parent selected framework `26.10.20`. Ordinary released-parent compilation/adoption is therefore blocked until the coordinated parent/BOM release is published and deliberately adopted. This candidate does not overwrite parent 6 or add individual framework version overrides.

The isolated hosted workflow checks out the exact public corrected parent source `6442bd51733ade4d5f4583e1afe812dd2c520b40`. In the ephemeral source fixture only, it changes one owning parent `relativePath` to that source file. Both source parent and BOM references must equal `26.10.23`. No version, SDK, specification or other source is rewritten. The parent is not installed or deployed over the released artifact.

The workflow runs the genuine Maven `verify` lifecycle with an isolated repository and reports the exact service/parent source identities, the two POM hashes, Maven exit and observed JUnit counts. A green source-fixture job is **not** published parent adoption, a new service/SDK release, native cache revocation proof or live-provider/consumer acceptance. Dependency resolution, compiler, test or original-producer failures remain failures; the fixture does not invent successful evidence or bypass missing producer generation.

Raw provider/Maven logs stay private to the ephemeral runner. Only a bounded redacted error summary and report counts are exposed. Generated SDK/spec files are not hand-edited. Any resulting original producer output needs its own provenance/review before publication.

Session-cache integration also remains open until a genuine shared primary-only/no-L1/no-fallback capability propagates storage failures and is qualified with the real backend. The candidate's positive liveness/generation fences assume coherent backend operations and do not convert cache fallback or a stale restore into authoritative revocation. The upstream framework lane owns that provider-neutral capability.
