# CoDel and libmount remediation — 2026-10-14

This record follows the October 14 image security refresh. It addresses three
source-open associations in the accepted Hailo image
`20261014T152325Z-e664cb9647e7`: kernel CVE-2026-98427 and util-linux
CVE-2026-53612 / CVE-2026-53613. It does not claim that all remaining findings
are resolved. Hardware acceptance was pending at build completion; the subsequent
[October 15 deployment validation](codel-mount-deployment-validation-2026-10-15.md)
records installed-image checks, three reboots and user-confirmed camera/Hailo.

## Changes and compatibility

The kernel patch follows upstream commit
[7f4a5ec6258f](https://github.com/torvalds/linux/commit/7f4a5ec6258fd7c92633ec4b0493fc51166d9398):
control-law progress is at least one time unit, and a shared `codel_dequeue()`
invocation drops at most 256 packets before rescheduling. This is a bound on
that invocation, not a universal bound on an outer fq_codel scheduling call.
The shipped `sch_fq_codel` module uses these headers. Only patch context was
adapted; upstream added/deleted code is unchanged. Kernel version and configuration
remain pinned; the final compiled-image verification below confirms this.

The mount patch incorporates the target-descriptor and ownership corrections
from the [ownership advisory](https://github.com/util-linux/util-linux/security/advisories/GHSA-g8wm-75wr-g2vh)
and [target advisory](https://github.com/util-linux/util-linux/security/advisories/GHSA-8gj5-72r3-428g),
including later stable-branch corrections. Merely applying the initial two
patches leaves target reopening, legacy fallback, and post-mount handling gaps.
The local backport explicitly retains the authorized target FD separately from
the authoritative mounted-tree FD returned by the new mount API. Restricted
ownership changes use only the latter. For restricted mounts, literal fstab targets are pinned before
privileged target operations; a later ordinary rename cannot redirect that FD.

Compatibility rules for non-root restricted mounts are explicit:

- Symlinks in any target component are rejected; `openat2` and usable `/proc`
  are required. The legacy API does not fall back to a pathname when FD paths
  are unavailable.
- Owner/group/mode and ID-map operations using legacy mounts or external helpers
  fail before mounting because those routes cannot supply a safe mounted-root FD.
- Restricted legacy propagation and bind operations requiring a follow-up
  remount for flags such as `ro`, `nosuid`, `nodev` or `noexec` are also rejected.
- Helper propagation, namespace-based subdirectory mounts, and ID-mapped
  move/remount/propagation-only replacement are rejected. New-API ordinary and
  bind mounts retain supported ID mapping.
- Root retains the original `lchown`/`chmod` behavior, including final symlink
  ownership semantics and operation without `/proc`. Subdirectory ownership and
  context reset/reuse were specifically checked.

These restrictions do not alter the stock image's root-only boot mounts: its
fstab has no `user`, `users`, or `X-mount.*` entries. The final WIC confirms
that mount and umount retain root ownership and mode `04755`, alongside the
other privileged metadata checks. Intermediate host file permissions were not
used to infer this result.

## Regression and review evidence

- CoDel: four regression groups fail on the accepted real headers; all seven
  groups pass after the patch, including ordinary dequeue, ECN, empty queues,
  short catch-up and unsigned time/count wrapping. Eight bounded backlog/idle
  cases exercise the 256-drop limit. UBSan reports no failure.
- The complete actual `sch_fq_codel.c` translation unit compiles with retained
  ARM64 Yocto flags and candidate headers; undefined-symbol delta is empty.
- libmount: actual native libraries are compiled from both source versions.
  The initial 12 cases pass on the final candidate; the old code fails eight
  assertions. The extended suite passes 33/33; the baseline fails 25 cases and
  43 assertions. Privileged mount, namespace and helper operations are wrapped;
  directory FDs are used to check userspace identity and policy decisions.
- Independent review found and corrected root-subdirectory ownership, helper
  propagation, optional feature guards, ID-map replacement, early subdirectory
  cleanup, root proc/symlink compatibility and clone-state reset issues before
  integration. Separate root-subdirectory and missing-proc probes pass.
- Existing host tests: 365 passed after layer integration.

These are bounded regression and compilation results. They are not live-kernel
race/DoS tests, setuid transition tests, or a substitute for new-image boot and
camera/Hailo acceptance.

The new util-linux patch is limited to `class-target`; native and SDK tools
retain the accepted source. An initial attempt with an unqualified patch was
stopped after detecting unnecessary host-tool rebuilds, and its log/provenance
are retained separately. The completed image uses the narrowed recipe scope.

The first strict binary comparison stopped on rebuild differences; the initial
failure records and verifiers are retained. Investigation found two narrowly
defined generated-data cases:

- Six additional util-linux programs changed only their 20-byte GNU build ID and
  four-byte debuglink CRC. Five inserted header lines shifted DWARF locations of
  the unchanged `is_same_inode` inline helper through `blkdev.c`. Their complete
  disassemblies and every remaining installed ELF byte match. The narrow check
  rejects 30 code/data/header/filename mutations across those six files.
- libcamera and librpicam_app differ only in generated version timestamps,
  build ID/debuglink CRC, and libcamera's embedded IPA public key. Every other
  ELF byte matches the accepted WIC. Both IPA module payloads are unchanged;
  accepted and new signatures validate against their respective embedded keys.
  Twelve code/data/key/module/signature negative controls are rejected. Source
  pins, four camera patch hashes, layer inputs and retained configure evidence
  match; current modified sources also replay from those patches. The accepted
  source directory was not independently archived, so source identity relies on
  those retained records, while binary equivalence uses the actual accepted WIC.

No private signing key was read for these checks. These exact comparisons replace
the overly strict unchanged-file assumptions; they do not permit unrelated code
or data differences. The expected fq_codel change is also checked against its
compiled module before permitting its protected-file hash to change.

## Evidence and build result

Build **`20261014T170636Z-e664cb9647e7`**, profile `rpi5-camera-hailo`,
completed successfully: all 7,884 BitBake tasks succeeded, with 7,151 reused.
The completed compressed WIC SHA-256 is
`29f43e854fa7d9c1200c8c8bee464e2e2e6a97fb50850ee5e318548c16fa14fd`.
Its SPDX SHA-256 is
`bcffd0069e0db2f0dfd381abec4fd7d94a468f6627c5628ab2e59341b67a1849`.

Final checks passed:

- The complete 69-patch kernel stack reverses/reapplies to the pinned source.
  Configuration, kernel image and exported symbol CRCs are unchanged. All 27
  shipped modules match their expected imports (2,452 checks, 54 negative
  controls); only `sch_fq_codel` changed. Its installed code matches the actual
  compiled module, and the seven CoDel groups pass against final built headers.
- All 187 shared-library paths/SONAMEs remain, with no removed exported symbols.
  Four util-linux libraries changed from the reviewed helper/mount backport;
  the two camera-library differences are limited as documented above. This is
  an exported-interface check, not a full ABI or runtime proof.
- All 13 changed util-linux source files match the reviewed candidate and replay
  exactly. All 118 installed util-linux ELF files match normalized actual
  compiler outputs. Of 119 package files, 52 changed: 46 expected shared-helper
  consumers and six debug-metadata-only consumers. Mount/umount executables are
  unchanged; their corrected behavior comes from libmount.
- Read-only extraction of the actual WIC matches 378 selected files, covering
  the 264-file protected baseline, all 27 modules, 119 util-linux files, libraries
  and security policies. All 16 privileged file ownership/mode records match.
  Boot configuration, board DTB, IMX708 overlay and kernel image are unchanged.
  Camera/Wi-Fi rootfs checks, source provenance and camera public identity pass.
- The manifest has the same 460 installed packages and versions. No packages
  were added. Codex authentication, generated app credentials/device TLS keys
  and the copied timesync clock are absent from the pristine image at the
  explicitly checked paths.
- `scripts/install-ssd.sh` selects this completed image by default. This check
  did not access or write an SSD.

The revised post-build verifier review binds 565 immutable inputs. It also
corrected a result-reporting gap: assessment reconciliation now requires the
successful same-build scan gate and matching final CSV, scan metadata, SPDX
and package-manifest hashes. Nine invalid-input controls are rejected.

## Same-database rescan and remaining findings

The final SPDX was rescanned offline using the same verified `sbom-cve-check`
1.3.5 and October 14 NVD/CVEList snapshots as the preceding refresh. Database
SHA-256 remains
`9c45b7d5f0ca34dbca3ea0ef56bd065e8aed411684fcd154571897cfec1d772d`.
Every one of the 24,395 installed recipe/CVE associations was compared with the
previous result, with unchanged identities and scores.

| Raw scanner result | Before | After |
|---|---:|---:|
| Fixed | 23,960 | 23,965 |
| Affected | 405 | 400 |
| Not affected | 30 | 30 |

Five raw verdicts change from affected to fixed: the three selected source fixes
plus the two util-linux CVEs repeated under `util-linux-libuuid`, which shares
the util-linux CPE. The input SPDX attributes the new patch only to util-linux;
libuuid bytes are unchanged. Those two libuuid source-reviewed findings retain
**notaffected**, so they are not counted as additional source fixes.

The existing 546-association assessment ledger now has **200 fixed, 331 not
affected, 12 open, two partially mitigated/open and one unassessed**. Exactly
three source dispositions changed; all other dispositions are preserved.
The twelve open records concern ACL, two binutils findings, BusyBox awk/ash,
Expat, glibc, libxml2, three policy-mitigated kernel findings and FFmpeg. Avahi
and libevent remain partially mitigated; one kernel record remains unassessed.
The separately noted cross-component BusyBox `cp` issue remains outside this
546-association ledger.

Subsequent October 15 investigation classified that separate BusyBox `cp`
finding as **not affected in this image configuration**, with no rebuild
required. See the [BusyBox cp follow-up](busybox-cp-followup-2026-10-15.md)
for source, configuration and installed-device regression evidence.

These counts are tracked associations and raw version/patch matches, not a
whole-image security clearance. The preceding refresh's coverage limits for
bundled/vendor software and application ecosystem dependencies still apply.

## Evidence and deployment boundary

The working evidence is `.state/codel-mount-remediation-2026-10-14/`.
The public evidence bundle location is:

```text
artifacts/20261014T170636Z-e664cb9647e7/rpi5-camera-hailo/security/codel-mount-remediation-2026-10-14/
```

It includes source/patch regressions, independent reviews, initial failed
comparison records, the narrowly revised verifier proofs, final image checks,
raw scanner outputs and integrated assessments. `ARCHIVE.json` maps retained
source and archived digests; `SHA256SUMS` verifies archived contents. Large
records use lossless gzip with decompressed SHA-256 checks. Full DB caches,
private keys, authentication files and native build trees are excluded; helper
scripts may refer to retained workspace dependencies, so the bundle is not
claimed to be a standalone reproduction environment. The final completion
record is `.state/codel-mount-remediation-2026-10-14/completion.json`.

**Hardware acceptance at build completion: NOT_RUN.** The earlier three-reboot/video/Hailo acceptance
belongs to baseline `20261014T152325Z-e664cb9647e7`. At that point the new image still required
SSD installation and Pi boot/automatic-service, Wi-Fi, camera and Hailo checks.
Those checks subsequently passed in the
[October 15 deployment record](codel-mount-deployment-validation-2026-10-15.md);
the original build-stage evidence is preserved.
After connecting the intended SSD to the build PC, the existing installer is
`./scripts/install-ssd.sh`; no new per-install script is needed.

## Workspace maintenance

Historical DB/log files were losslessly compressed with decompressed SHA-256
verification, reclaiming 6,099,981,467 bytes. Unused QEMU cortexa57 target cache
entries were removed (11,339,931,284 bytes); Pi cortexa76, shared native/allarch
caches, source/work trees, accepted images and evidence were retained. No QEMU
image, SSD write, or running-Pi change is part of this task.
