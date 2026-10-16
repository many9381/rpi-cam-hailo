# Source and image version preservation — 2026-10-16

Local annotated tag **`validated-20261016T111625Z`** preserves this firmware
snapshot on `master`. The companion Yocto repository carries the same tag on
`feature/root-firmware-layers`; its tag message identifies the firmware commit.
No branch merge or remote push is part of this preservation task.

The tag relates to accepted development image
**`20261016T111625Z-e664cb9647e7`**, profile `rpi5-camera-hailo`.
The compressed WIC SHA-256 is
`49417cfdc898f1cb0ab9aae7a2f78de92d19f45666a0e4c0a5f2d4276f7a9c12`.
This image predates the snapshot commits: its application was built from
`ba503a1fbc4ed68c1fd29aace7214a5c330d7021` plus reviewed layer patches through
`0010`. That recipe pin and patch chain remain unchanged. The new tag does
not claim that the image was built from the new commit ID.

## Source identity and checks

All **431** inputs in
[`scan-2026-10-16-static-warning-review/source-sha256.json`](scan-2026-10-16-static-warning-review/source-sha256.json)
still match, including production sources, C++ tests, web sources and quality
configuration. All **170** production files in the consumer-review manifest
also match the compiled recipe source and the packaged development checkout.
In the Yocto repository, all **296** recorded integration inputs match their
original hashes/modes; source-archive and image artifact checksums pass.

Fresh local checks for preservation:

- Yocto host suite: **372 tests pass**.
- Web: **770 tests / 56 files pass**, and production build passes.
- C++ formatting: all **257** source/header files pass.
- Quality-gate helper regressions: **8 pass**.
- SBOM hash conversion regressions: **4 pass**.
- Image scripts: **20** shell syntax checks pass.

The first host-suite attempt was interrupted because the sandbox blocked
the test fixture's loopback listener. The complete rerun with local socket
access passed in 91.329 seconds. Its QEMU launcher tests use fixtures; they
do not build or boot a QEMU image. Web dependencies were restored from the
existing lockfile without running a fresh dependency audit.

Existing target results remain explicitly historical: the
[October 16 warning review](static-warning-review-2026-10-16.md) ran **361**
selected target tests and 79 analysis units with 0 errors / 198 warnings;
the preceding [quality gate](static-analysis-2026-10-15.md) ran **1,356** CTest
passes with **10** explicit hardware skips. Source hashes above establish the
relationship to those records. No new target tests, image build, QEMU build,
Pi reboot or hardware test were performed for this Git snapshot. The existing
[installed-device acceptance](static-warning-deployment-validation-2026-10-16.md)
continues to cover video, Hailo and three Wi-Fi reboot cycles.

## Boundaries

This is a development checkpoint, not a security-clean release. The
[consumer review disposition](consumer-boundary-review-2026-10-16.md) and
[agreed exclusions](README.md#agreed-work-exclusions) remain unchanged.
Long-duration operation tests and additional MOV/common-allocator redesign
are not reopened. Closed caller-review tasks remain outside active work;
the residual advisory ledger is retained.

Generated files, local login sessions and models remain Git-ignored. The
companion workspace retains private validation logs under
`.state/version-preservation-2026-10-16/`. Its
[snapshot runbook](../../../docs/runbooks/validated-snapshot-2026-10-16.md)
documents private build prerequisites and why later builds require a new ID
after committing. Existing accepted image/provenance files are preserved.

Privacy follow-up: the shared tag now points to the sanitized checkpoint.
See [address redaction](privacy-cleanup-2026-10-16.md) for rewritten history,
fixture changes and the remaining GitHub retention boundary. The test counts
above remain the results of the original preservation task.
