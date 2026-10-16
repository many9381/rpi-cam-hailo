# Raspberry Pi kernel security follow-up — 2026-10-12

This reviews the **403 raw affected kernel associations** from deployed image
`20261012T031641Z-e664cb9647e7`. The source remains Raspberry Pi Linux **6.18.55**,
commit `4103a989a46196239b830bd07693277e42b8f992`, plus the existing IPv4 RCU fix
and the backports below. Board configuration and the downstream camera/Hailo
integration are retained. Version associations are not confirmed exploits.

## Layer changes

The twelve patches are registered in
`meta-rpi5-cam/recipes-kernel/linux/linux-raspberrypi_6.18.bbappend`.
Exact hashes, upstream patch hashes and adaptation notes are in
`.state/security-followup-2026-10-12/kernel/backport-manifest.json`.

| Candidate | Backport and primary source |
| --- | --- |
| CVE-2026-90347 | [arm64 ptrace syscall-argument synchronization](https://github.com/torvalds/linux/commit/88b839ce497ccb1ff92f7ae742c78dd2937ba572) |
| CVE-2026-53257 | [cfg80211 HE/EHT element validation](https://github.com/torvalds/linux/commit/cb9959ab5f99611d27a06586add84811fe8102dc) |
| CVE-2026-98134 | [BPF null-inference validation](https://github.com/torvalds/linux/commit/d3ef6c097ba078e1f8c7239d76a0ce8b61e75095), using the existing 6.18 `reg_not_null` signature |
| CVE-2026-98043 | [BPF pointer-offset bounds](https://github.com/torvalds/linux/commit/67b529f521a6676cdfc78b91b0217d7eaa84216b), using 6.18 signed-bound fields |
| CVE-2026-98058 | [BPF syscall helper sleepability](https://github.com/torvalds/linux/commit/d05524794240b52fdc3b6c1220dd05505715824d) |
| CVE-2026-98364 | [XFRM device references under RCU](https://github.com/torvalds/linux/commit/9fa903b24b1f46b4ff5443bcd4aca23e5c57f9c1) |
| CVE-2026-90335 | [TTY registered cdev validation](https://github.com/torvalds/linux/commit/c3b5623fd97648f2747444aa8932ae604662df93) |
| CVE-2026-90336 | [Serial freed-driver pointer cleanup](https://github.com/torvalds/linux/commit/61a2fb25551be0375bc16ef2a70c987dfca26183) |
| CVE-2026-89537 | [SUNRPC short MIC rejection](https://github.com/torvalds/linux/commit/b94f6719dcd9f7a609bc5f459f85795900e77d25), using the initialized 6.18 `cksumobj.len` |
| CVE-2026-98284 | [Netlink group-bitmap reader RCU protection](https://github.com/torvalds/linux/commit/ceac0de741bfb47ca255eee075257b3bb31f0651), preserving the 6.18 inode format |
| CVE-2026-90104 | [NFS referring-call array initialization](https://github.com/torvalds/linux/commit/8fa4804fe62ca4155a2d8fc2789d630376cbf2fc), changing the existing `kmalloc_array` to `kcalloc` |
| CVE-2026-74723 | [Btrfs inline LZO input bounds](https://github.com/torvalds/linux/commit/0fa78ef637deb5dbe341582f88553a4bce496de0), retaining the existing error return |

All twelve reverse checks pass against the combined candidate source without
fuzz. Independent review found an initial SUNRPC adaptation referring to a
variable absent from 6.18; it was corrected to the existing initialized field
and re-reviewed. No unresolved important code finding remains in this reviewed
patch set. Integrated compilation and actual-image acceptance are recorded
separately in the overall security follow-up.

For final image `20261012T080118Z-e664cb9647e7`, kernel and module compilation,
all twelve actual-source checks and unchanged configuration checks passed.
The actual WIC kernel and seven camera/fan/Wi-Fi/Hailo modules match the build;
module vermagic is `6.18.55-v8-16k`. The final source/configuration ledger keeps
the counts below. Raw scanner associations fall 403→391, which is separate
from that ledger. Subsequent [deployment validation](security-deployment-validation-2026-10-12.md)
passed three Wi-Fi reboots and matching loaded-module checks. These do not
establish execution or safety of every affected kernel path.

## Assessment and evidence

`dispositions.json` and `dispositions.csv` retain all 403 associations, their
primary records, exact source/configuration evidence and remaining actions.
Candidate-source counts are:

| Disposition | Count |
| --- | ---: |
| Source-fixed: 14 already present and 12 new backports | 26 |
| Specific architecture/configuration/component exclusions | 176 |
| Missing source changes or identified vulnerable ownership patterns; open | 108 |
| Source equivalence or applicability remains inconclusive | 93 |
| **Total** | **403** |

The 93 inconclusive records remain explicitly `unassessed`; each identifies its
evidence gap and affected paths, where mapped. They are not cleared by a kernel
version comparison, an absent advisory version range, a renamed source file or
the fact that a module was not observed loaded. Open source findings also do
not establish exploitability of an installed device.

An immutable snapshot retains the original affected source files. Reviewed
pre-fix blocks, missing post-fix blocks, fixing commits, source hashes and build
rules are recorded individually. Matching mode is explicit where whitespace
normalization is needed. A broad parent feature does not establish that an
optional implementation is built. Independent review corrected three such
overestimates using specific disabled EROFS on-demand, transparent-huge-page
and legacy-xtables paths (`optional-path-evidence.json`). The two older fixed
findings CVE-2022-0286 and CVE-2022-3646 use ordered guards in the current
`bond_ipsec_add_sa` and `nilfs_attach_log_writer` functions, not generic added
lines that could occur elsewhere.

CVE-2007-4998 describes userspace `cp`, so its kernel association is excluded.
The image's `cp` resolves to BusyBox; its destination-symlink behavior remains
a separate unresolved userspace follow-up. This is not a whole-image exclusion.
No blanket recipe-level `CVE_STATUS` suppression was added.

## Bounded regressions and limits

Existing source fixtures fail before and pass after the relevant changes:
eleven BPF checks, eight ptrace checks, 100 short MIC lengths and three valid
MIC widths. The complete MIC function compiles with `-Werror`. The NFS fixture
checks ten list scenarios (ten failing pointer assertions before, none after);
the LZO fixture checks thirteen lengths/control cases (five fail before, none
after). The exact saved results and generated-function hashes are retained.

These are isolated function/block checks. NFS does not execute full callback
free/error paths; LZO uses decoder/folio stubs. The fixtures do not establish
full verifier, scheduler, RCU concurrency, filesystem, network-service or
hardware acceptance. New-image boot and loaded-module checks remain a separate
deployment step. Long-duration tests are excluded at the user's request.

## Important remaining candidate

**CVE-2026-93047 (V3D BO lifetime) remains open.** The enabled 6.18 CSD and
flush-CL paths attach BO references and implicit reservation waits to a trailing
clean job. The upstream fix uses a later submission architecture. A safe 6.18
adaptation needs review of BO sharing, consumer-job dependencies and error
cleanup, followed by GPU/camera tests. Its source/configuration evidence is
retained; this record does not silently disable the camera GPU path or claim
that the incompatible upstream rewrite was applied.
