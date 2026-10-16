# Raspberry Pi kernel residual follow-up — 2026-10-13

This pass reassesses the **45 open and 18 inconclusive kernel associations**
after acceptance of image `20261013T124642Z-e664cb9647e7`.
The [accepted deployment](kernel-deployment-validation-2026-10-13.md) remains
separate from this new image, **`20261013T204349Z-e664cb9647e7`**.

**The integrated Hailo build and actual SSD-image checks passed. This new image
has not been installed or accepted on the Pi.**

| Kernel disposition | Before | After |
|---|---:|---:|
| Source-fixed | 55 | 76 |
| Specific source/configuration/image/board exclusions | 285 | 289 |
| Identified unresolved condition | 45 | 27 |
| Applicability or source equivalence unresolved | 18 | 11 |
| **Original associations** | **403** | **403** |

These are advisory associations, not confirmed exploits. Fourteen new patches
correct **17 associations**; another **four existing source fixes** were
established by tracing the original defects into current implementations.
Four new exclusions are limited to this configuration, installed modules or
the measured Pi hardware. The other **340 kernel records** retain their
previous conclusions. No feature disablement or blanket `CVE_STATUS` suppression
is used.

## Layer changes

The image keeps Raspberry Pi Linux **6.18.55**, source pin
`4103a989a46196239b830bd07693277e42b8f992`, release **6.18.55-v8-16k**,
and the accepted kernel configuration. Patches **0100–0105** and **0120–0127**
are registered in `meta-rpi5-cam/recipes-kernel/linux/linux-raspberrypi_6.18.bbappend`,
alongside the existing 26 patches.

| CVE | Correction and primary source |
|---|---|
| CVE-2026-98033 | Preserve map identity across all verifier callback arguments. [upstream 1](https://git.kernel.org/linus/b90c5d770dad910fb89e6c1b15052a8a1e8db752), [upstream 2](https://git.kernel.org/stable/c/66ff2eff093d2a0838f39c713eeb590bc0946c2a) |
| CVE-2026-93144 | Reject writes through untrusted BTF pointers before either write handler. [upstream 1](https://git.kernel.org/linus/ac65c710cc643cbc52b899627577357867249530), [upstream 2](https://git.kernel.org/stable/c/19d5566b84ca1af0256d0d0003e1a081580c3ba3) |
| CVE-2026-90317 | Invalidate RCU pointers on spin/resource unlock when leaving the final protecting context; preserve existing explicit-RCU unlock policy. [upstream 1](https://git.kernel.org/linus/180c7000712db77063b3a26f4c97e7dd9038f449), [upstream 2](https://git.kernel.org/stable/c/7ae71629357d0a6d0bdadb929c7b296d5b7e61c2) |
| CVE-2026-93044, CVE-2026-93135, CVE-2026-93270 | Keep a per-program JIT requirement for arena, architecture-inline helpers and per-CPU map instruction generators; reject unsupported interpreter fallback. [upstream 1](https://git.kernel.org/linus/34746b5a84ec37c0ea2bf6808c65c5ed8790eb51), [upstream 2](https://git.kernel.org/linus/f1c27922576edccb99d0257827d09bd05c0304a6), [upstream 3](https://git.kernel.org/linus/7a0855e73757ee9cf25ba635a1c735018ecba742) |
| CVE-2026-68399 | Clear inherited socket storage immediately after copying, before subsequent fallible clone operations; preserve parent and child ownership. [upstream 1](https://git.kernel.org/linus/7cbd0c4cebe4c9f678d15e6b9ba975e1155a107f) |
| CVE-2026-53106 | Reject all four fallible local-storage deletion frontends in NMI; retain no-fail owner/map teardown. [upstream 1](https://git.kernel.org/linus/350de5b8a9befaa2a68861c51f671d4f5f751ca5) |
| CVE-2026-74307 | Reject cross-superblock ext4 donors before acquiring write access or move-extents locks. [upstream 1](https://git.kernel.org/stable/c/c143957520c6c9b5cd72e0de8b52b814f0c576fe) |
| CVE-2026-90267 | Release SCSI special payload on every setup failure and clear ownership for idempotent cleanup. [upstream 1](https://git.kernel.org/stable/c/bb31844d88b77138b67aa20c3600203baff40140) |
| CVE-2026-74754 | Pair SCSI EH runtime-PM get/put using one flag snapshot and corresponding UFS writes. [upstream 1](https://git.kernel.org/stable/c/872f486259ae0bc6b73ca4735a15d013241f73e9) |
| CVE-2026-74561, CVE-2026-74562 | Protect every IPv6 nexthop list walk and invalidate routes without reversing nested lock order. [upstream 1](https://git.kernel.org/stable/c/4787a6d2629b4e8c0b6bacab1f75c1660eca44d9) |
| CVE-2026-98338 | Own the IBSS BSS reference in the queued event; release it on every error and consumption path. [upstream 1](https://git.kernel.org/stable/c/708f9d43d6a2eb9c6b83fe62af628de9dffd9314) |
| CVE-2026-53017 | Wait for the F2FS checkpoint before reading NAT flags, preserving node/NAT lock order. [upstream 1](https://git.kernel.org/stable/c/238e14eb7226f883b72caccd2d37bf5707df066b) |
| CVE-2026-64283 | Use unsigned guest-memory offsets and lengths through KVM declarations, stubs and implementation. [upstream 1](https://git.kernel.org/stable/c/eba85fee7fc6cf28fec38a5bf3c378bef9a79ca6) |
| CVE-2026-68441 | Reject REDIRECT verdicts in the common qdisc wrapper and all callers, retaining existing redirect-helper context guards. [upstream 1](https://git.kernel.org/stable/c/c8fd74445e86f88096d2f6cf0f9e4d54d8ed1781) |

The manifests retain upstream/stable patch hashes, local API adaptations and
complete caller/ownership/error-path reviews. In particular, the JIT requirement
uses the spare final flag bit without shifting earlier flags; the SCSI flag
becomes an independently readable boolean. These internal type changes can alter
kernel symbol CRCs even when the release string is unchanged.

## Reassessment boundaries

Existing fixes were established for **CVE-2021-3669** (IPC iteration),
**CVE-2021-3759** (persistent IPC allocation accounting, including the deliberate
temporary-buffer revert), **CVE-2022-1462** (PTY insertion/commit locking), and
**CVE-2022-3435** (separate nexthop objects cannot enter legacy indexing).
Original affected implementations fail bounded controls; the current complete
functions and valid-operation controls pass. These four cases add no layer patch.

**CVE-2018-6559** is excluded only because overlayfs is a module absent from
the actual image and builtin metadata. **CVE-2022-3523** is excluded by the
DEVICE_PRIVATE configuration and compiled false swap-entry stub; HMM_MIRROR is
independently unselected. Neither conclusion claims that optional source is fixed.

For **CVE-2026-90121**, the measured board and exact WIC DTB expose the GIC-400
controller, without the GICv5/IRS startup bindings. For **CVE-2026-63941**, the
measured CPUs lack SVE, and current capability, KVM admission and both affected
restore paths require that feature. These two findings are **exact-board
exclusions with source defects still open**. They do not exclude general KVM
issues and must be revisited for different hardware or DT/configuration.

The whole-image ledger retains all **539 original associations**:
**165 fixed, 325 specifically
excluded, 36 open, 2 partially
mitigated/open and 11 inconclusive**. All 136
non-kernel records are preserved. Raw scanner affected/under-investigation
associations changed **442 →
425**, with
**0 additional unresolved raw associations** outside
the original comparison. The scan uses the retained **2026-10-11 database**;
this is not a new whole-database update. Source review and exact-image assessment
are distinct from raw version/patch metadata results.

## Verification

The project host suite passed **365 tests**. Independent review approved all
14 patches, their combined source, every reassessment and the verification
gates. Seven new BPF regression families and eight other-path fixtures exercise
actual source with kernel-boundary adapters; pre-fix controls fail and combined
corrections pass. Other-path fixtures also pass ASan/UBSan. Ten historical
red/current/configuration controls pass their exact expected status checks.
The 13 prior regression groups and all new groups pass against the final BitBake
source. These are bounded host tests, not full kernel concurrency, memory-ordering
or target exploit tests.

The first integrated attempt, `20261013T195250Z-e664cb9647e7`, failed to compile
the KVM patch because this retained tree has no `uoff_t` type. The original host
adapter supplied that typedef and concealed the dependency; the first source
review also missed it. The corrected backport uses the existing `u64` type in
the implementation, declaration and disabled stub, with actual ARM64-header
compilation added before renewed review. The failed attempt and superseded
reviews are retained separately; they are not successful image evidence.

The second attempt, `20261013T201250Z-e664cb9647e7`, exposed the same validation
gap in F2FS: newer lock-tracing wrappers were absent, while the host adapter had
supplied them. The backport now uses the retained semaphore wrappers with the
same acquisition/release order. Actual ARM64 complete-translation-unit and
header coverage was expanded across the modified production paths before the
next integrated build. All 30 changed C files compiled with the real ARM64
headers and warnings treated as errors; all five changed headers appeared in
recorded compiler dependencies. Disabled-configuration controls are identified
separately and do not change the image's feature selections.

That expanded compilation also exposed an undefined RCU-invalidation helper in
the initial BPF backport before the next image build. A host adapter had supplied
the helper, masking the missing production definition. The final patch adapts
the retained verifier's own invalidation implementation. Real-object symbol
checks accompany the renewed source review; a compiler exit status alone was
not treated as evidence that all helper definitions were present.

All **40 patches** reverse/reapply with zero fuzz and explicit direction.
The **35 changed source paths** match the reviewed combined candidate;
**632 other assessed paths** retain their
baseline identities. The compiled Image matches the deployed image.

The compiled and exported configurations differ only in the automatically detected `CONFIG_CC_CAN_LINK` toolchain probe; every other line is identical. The exported configuration remains byte-identical to the accepted baseline.

The symbol table contains **19428 exports**, with
**8097 changed export records** reviewed separately.
Replaying the actual commands for **901 source units**
reproduces every changed export's old and new CRC using only the baseline/current `bpf.h` and
`scsi_host.h` definitions, with **1734 unchanged
export controls**. This accounts for the changes without an inferred symbol
allowlist or a claim that the kernel's internal ABI stayed unchanged.
All **25 installed modules** have matching required kernel CRCs across
**2254 imports**. Fifty mutation controls reject missing
or incorrect imports. Their measured hashes are bound through kernel verification
to the files extracted from the actual WIC. This validates the shipped module
set; it does **not** promise compatibility with old or external modules.

The WIC preserves **51 protected userspace files**, **16 privileged executable
modes/owners**, the package version/set and **182 shared libraries at the same
paths with identical bytes**. Libcamera and both IPA modules/signatures remain
unchanged. Camera/Wi-Fi rootfs rules, startup ordering, source provenance,
signing identity and artifact checksums pass. Boot configuration, IMX708 overlay
and the board DTB are identical to the accepted baseline. Image credentials,
generated app configuration, device TLS private key and provisioned clock state
remain absent.

| Artifact | SHA-256 |
|---|---|
| Compressed WIC | `21a06bc61c811c1d9f971d451eb20766ad2fc5d4a32f86ab92510f7bbdb80cd1` |
| Kernel Image | `8530ff74a7ba573600d9d6bdebe8a02145967f1b4ec84f68ebfefd08a6a0dcc8` |
| Kernel configuration | `751ecdb597addf24fb7e2eb954cc28e4fc523983665e294c032dd11cd0ca8250` |
| Board DTB | `03ce4742452ad52e3e8ec2259a0c705b496970e2b75e6e0b4e5446475ea1b926` |

## Remaining work and evidence

The remaining kernel work is **27 open records and 11 inconclusive records**.
The ledgers give the precise missing prerequisite, source equivalence,
ownership/lifetime proof or exposure evidence for each. Complex BPF state and
layout changes, other filesystem/network lifetimes and unresolved historical
reports remain explicit; no unresolved backport was counted as fixed.
Non-kernel library, FFmpeg MOV and separate BusyBox follow-up are unchanged.

Install this image using `scripts/install-ssd.sh`, then separately verify the
new kernel/module identities, Wi-Fi boot and automatic startup, camera video
and Hailo inference. The prior image's accepted reboots and browser confirmation
do not establish acceptance of this image. This work changed no running Pi
configuration and performed no installation or reboot.

Curated non-secret evidence, complete CSV/JSON ledgers, primary records,
regressions, reviews and layer inputs are retained with `SHA256SUMS` at
`artifacts/20261013T204349Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-residual-evidence/`.
The large exact-CRC replay JSON is stored losslessly as `.json.gz`;
`compressed-origins.json` maps its original path and uncompressed review hash
to the archived file and checksum.
Working evidence is `.state/kernel-residual-2026-10-13/` (Git-excluded).
