# Residual image security follow-up — 2026-10-15

All 15 residual associations from accepted image
`20261014T170636Z-e664cb9647e7` were revisited using October 15 primary records
and actual built sources. Two compatible FFmpeg cleanup corrections are now
included in Hailo image **`20261015T110905Z-e664cb9647e7`**. FFmpeg moves from
open to **partially mitigated/open**; no complete advisory is newly closed.
The remaining count is **11 open, three partially mitigated/open and one
unassessed**. Hardware acceptance was **NOT_RUN** at build completion; the subsequent
[deployment validation](security-residual-deployment-validation-2026-10-15.md)
records successful installation checks, three reboots and user-confirmed video/Hailo.

The subsequent [MOV append follow-up](ffmpeg-mov-append-2026-10-15.md) adds
incremental serialization. This report preserves the earlier cleanup-only
build and its original findings.

Current work disposition: the later
[fragment follow-up and firmware exposure review](ffmpeg-mov-fragment-followup-2026-10-15.md)
records the user's decision to exclude additional MOV implementation from current
required firmware work. Existing patches remain; the advisory stays partial/open.
Reconsideration depends on a relevant input path or new correction evidence, not
the residual count alone. The table below preserves this earlier audit's findings.

## Applied changes

The layer append is
`meta-rpi5-cam/recipes-multimedia/rpidistro-ffmpeg/rpidistro-ffmpeg_7.1.13.bbappend`.
Despite the append filename, its pinned built version is **7.1.5**, source
`2fe08f3bd52c6e795df8353d29deb89596b5099d`.

- `0003-encryption-init-release-list-iteratively.patch` replaces recursive
  encryption-init list destruction with an iterative loop. It uses the exact
  code change in the [upstream proposed commit 94924d045d5d](https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/94924d045d5dce70f5557d400bb6d6b99c0ab96b).
  The proposal is unmerged. Long valid lists and error-path cleanup no longer
  consume one call-stack frame per list node.
- `0004-encryption-init-handle-missing-key-array.patch` is a local correction
  found during independent review. Allocation records the key count before
  allocating the key array; failed allocation or zero key size can leave that
  array NULL. Cleanup now checks the array before walking its elements, while
  freeing the other owned fields and nodes. This patch has not been submitted
  upstream and is not a separately assigned CVE.

The full [CVE-2026-107678 proposal](https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/24593)
also concerns quadratic work while appending MOV PSSH data. Each append still
reparses and serializes the prior list. The cleanup patches do not fix that
behavior. They deliberately have no complete-fix `CVE:` metadata or CVE-bearing
filenames, preventing the scanner from incorrectly closing the whole advisory.

The two reusable fixtures are `tests/integration/ffmpeg-encryption-init.c` and
`tests/integration/ffmpeg-encryption-init-allocation.c`. Red/green results cover
long-list free, roundtrip and truncated-final-record cleanup, all six allocation
failure sites, NULL/empty/small normal cases and zero key count/size. Long-list
tests use 20,000 populated nodes, a 256 KiB stack, CPU/wall-time bounds and no
core dumps. Before the corresponding fixes, three long-list cases and two
allocation/zero-size cases fail. After both fixes, **32 checks pass**: 16 plain
and 16 with ASan/UBSan/LSan, including the upstream encryption-info unit test.
Owned-allocation tracking also verifies complete cleanup.

These tests compile the real production translation unit with native host
`libavutil.so.58` allocation helpers. They are not target execution, full FATE,
arbitrary malformed caller-list validation, or proof that every zero-size
serialization path is supported. Independent source review passed after the
allocation-path correction. The existing project host suite passed **365 tests**.

## Findings retained and concrete next steps

The CNA records are pinned at [CVEList revision 8c0f52229867](https://github.com/CVEProject/cvelistV5/tree/8c0f52229867aa9e04a263a863eb31ac17688657).
All 15 records and additional primary-source responses have retrieval times
and SHA-256 records in the evidence bundle. Rechecking these selected records
is distinct from refreshing the whole scanner database.

| Component / advisory | Disposition | October 15 result and remaining requirement |
|---|---|---|
| FFmpeg / CVE-2026-107678 | Partial | List cleanup is corrected; near-linear MOV append still needs preserved side-data bytes/order, ownership, stream/fragment transitions and allocation-failure tests. |
| libxml2 / CVE-2026-6732 | Open | The official callback change remains incompatible with tested valid schema/entity behavior. A local reparse candidate corrected schema verdicts but lost reader-visible element nodes in five entity cases; rejected. A complete correction must preserve schema callbacks and reader traversal, including repeated/nested entities and resource caching. |
| Expat / CVE-2025-66382 | Open | Exact issue 1076/1160 trigger and parser path remain unavailable publicly. October 15 record metadata changed, while its CNA payload did not. A matching correction or precise upstream non-applicability explanation is required. |
| ACL / CVE-2026-54369 | Open | Official 2.4.0 retains legacy pathname semantics; new `_at` APIs require callers to adopt safe descriptor traversal. Existing systemd procfd behavior passes seven controls, while libarchive pathname fallbacks remain. A blanket no-symlink change breaks supported use. |
| glibc / CVE-2010-4756 | Open | Current upstream glob code matches the deployed source. Twenty installed ELF paths import glob, including opaque vendor libhailort. Complete caller input bounds or a compatible resource strategy have not been established. |
| Avahi / CVE-2025-59529 | Partial | Existing limits/deadline/backoff remain. Fifty legitimate browser clients can still occupy capacity beyond the initial timeout; the 51st request is refused and releasing clients restores access. Replacement PR 975 is a draft, not a complete compatible closure. |
| libevent / CVE-2026-63385 | Partial | Existing request-framing hardening remains. Percent-decoded binary data may contain NUL: a length-aware consumer rejects four problematic controls while ordinary/binary API controls pass. Relevant consumers still need verified length/path validation. |
| BusyBox awk / CVE-2026-38752 | Open | Matching native source still reproduces unbounded-recursion stack overflow. Valid recursion depths 20/1000/1001/1500 pass; a proposed arbitrary 1000 cap changes valid behavior. Compatible resource handling and failure unwinding remain necessary. |
| BusyBox ash / CVE-2026-38755 | Open | CNA describes evalcommand heap overflow, but the linked proposal limits evalfun recursion. Three ordinary controls do not resolve that mismatch; a matching trigger/correction is required. |
| binutils / CVE-2026-6844 | Open | No matching complete public trigger/correction was established. Unrelated ELF validation patches are not evidence of closure. |
| binutils / CVE-2026-6845 | Open | Red Hat's PR33697 NULL-section-header guard is already present in 2.46.1. Its relationship to the broader reported 2.46 resource-exhaustion condition remains unresolved; the vendor-fixed subset does not establish whole-advisory equivalence. |
| Linux / CVE-1999-0524 | Open, policy mitigated | Timestamp handler remains compiled. Accepted-image inbound request/outbound reply drop policy is preserved; keep source status distinct from enforced policy. |
| Linux / CVE-2010-4563 | Open, policy mitigated | Existing policy covers unicast destinations in link-layer multicast. The original report's multicast-destination/unknown-option error variant remains; a compatible correction needs normal IPv6 controls. |
| Linux / CVE-2021-3864 | Open, policy mitigated | The current-identity dumpability decision remains. Existing pipe-to-`/bin/false` policy prevents relative core-file placement. Upstream task-state setters differ, so only the decision predicate was compared, not whole-function equality. |
| Linux / CVE-2007-2764 | Unassessed | Sun-Brocade advisory still lacks an identified defective function/patch/trigger; Oracle alert retrieval returned HTTP 412. Platform age alone is insufficient exclusion evidence. |

Relevant primary sources include the [libxml2 callback change](https://github.com/GNOME/libxml2/commit/226b560837b90dea9b14431eca6e6fda8fb01ab4),
[Expat issue 1076](https://github.com/libexpat/libexpat/issues/1076),
[ACL maintainer announcement](https://www.openwall.com/lists/oss-security/2026/06/29/1),
[Avahi PR 975](https://github.com/avahi/avahi/pull/975),
[libevent advisory](https://github.com/libevent/libevent/security/advisories/GHSA-jcwh-pvf2-73p2),
and the Red Hat [PR33697 backport](https://gitlab.com/redhat/hummingbird/rpms/-/commit/6a6b47f71d84810d7c4acb9bb6d1e2caf665e906)
and [retirement in 2.46](https://gitlab.com/redhat/hummingbird/rpms/-/commit/e4496bfd87e22b86ab1d933ea2d8372a33cd6001).
Exact source comparisons, controls and per-finding limitations are preserved
in the four workstream assessments; rejected XML changes are not in a layer.

## Built image and scan checks

Only `rpi5-camera-hailo` was built. All **7,884 BitBake tasks succeeded**,
with 7,804 reused. Compressed WIC SHA-256:
`d885c45a7f0173c492723b88580158164bcfc9114ebfc63234acf445a18630bb`.
SPDX SHA-256:
`1853a4cb11b93f1973752794aa1c95b12f927d948cb54308652636af951fce4a`.

- The actual final encryption-info source reverses through both patches to the
  exact recorded baseline hash, then reapplies to the reviewed final hash.
  Package and rootfs libavutil hashes match; actual WIC extraction matches it.
- All **187 top-level ELF shared-library paths, SONAMEs and export sets** match
  the accepted baseline. Only libavutil and librpicam_app bytes changed.
  This is an exported-interface comparison, not a universal C ABI/runtime proof.
- librpicam_app differs only in its parsed version timestamp, GNU build ID and
  debuglink CRC. All other bytes match; code and unrelated data mutations are
  rejected. libcamera, both IPA modules, embedded public key and signatures
  remain byte-identical. The initial verifier assumed a regenerated key from
  the preceding build; its failure is retained, and the revised check permits
  only this narrower app-metadata case. No private signing key was read.
- Read-only extraction of the actual WIC matches **378 protected files**, all
  **27 kernel modules** and four boot files. All **16 privileged ownership/mode
  records** match. Kernel, board DTB, IMX708 overlay and boot configuration are
  unchanged. Camera/Wi-Fi rootfs, source provenance and camera public-identity
  checks pass. All **460 package names and versions** are unchanged.
- Explicit pristine-image checks find no Codex auth file at either known user
  location, generated app configuration, device TLS private key or copied
  timesync clock. This is a check of the documented paths, not a claim about
  arbitrary filesystem secrets.
- The installer selection check chooses this completed build by default,
  without discovering, mounting or writing an SSD.

The final SPDX was scanned offline with the same `sbom-cve-check` 1.3.5 and
October 14 database as the accepted baseline. Database SHA-256:
`9c45b7d5f0ca34dbca3ea0ef56bd065e8aed411684fcd154571897cfec1d772d`.
All **24,395 installed scanner rows are identical**, including identities,
statuses, scores and notes: 23,965 fixed, 400 affected and 30 not affected.
FFmpeg CVE-2026-107678 correctly remains raw **affected**.

The separate source-reviewed ledger retains its **546 associations**:
**200 fixed, 331 not affected, 11 open, three partially mitigated/open and one
unassessed**. Only FFmpeg's disposition changes. All 531 non-selected records
are preserved exactly, as is the separate configuration-specific
[BusyBox cp exclusion](busybox-cp-followup-2026-10-15.md), outside that denominator.
Reconciliation requires successful same-build image/scan gates and matching
WIC, SPDX, manifest, raw CSV and scan-metadata hashes. Historical before-source
review hashes are retained and explicitly connected to the final source by
the reverse/reapply check; they are not overwritten with current hashes.

These counts do not mean the whole image is vulnerability-free. Existing
coverage limits for bundled/vendor software and application ecosystems remain.

## Evidence and deployment boundary

Working evidence: `.state/security-residual-followup-2026-10-15/`.
Curated evidence:
`artifacts/20261015T110905Z-e664cb9647e7/rpi5-camera-hailo/security/security-residual-followup-2026-10-15/`.
The bundle contains checked primary responses, source identities, bounded test
results, reviews, initial verifier failure, image/scan checks and reconciled
assessments. `ARCHIVE.json` maps source and archived hashes; `SHA256SUMS`
verifies retained files, with lossless compression for large records. Private
keys, credentials, whole databases and native build trees are excluded. Scripts
may depend on retained workspace tools, so this is not a standalone toolchain.

**Hardware acceptance at build completion: NOT_RUN.** Subsequent checks passed
in the [deployment record](security-residual-deployment-validation-2026-10-15.md). The prior successful Pi boot,
Wi-Fi, video and Hailo acceptance belongs to the
[previous image](codel-mount-deployment-validation-2026-10-15.md).
The user subsequently installed and booted this image; the linked deployment
record documents that validation. The original build task did not write an SSD, reboot the Pi,
build QEMU, or perform a long-duration soak test.
