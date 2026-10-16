# Raspberry Pi kernel follow-up — 2026-10-14

This pass reviews all **27 open and 11 inconclusive kernel associations** after
acceptance of `20261013T204349Z-e664cb9647e7`.
The [previous hardware acceptance](kernel-residual-deployment-validation-2026-10-14.md)
does not transfer to the new image **`20261014T064455Z-e664cb9647e7`**.

**The integrated Hailo build and actual SSD-image checks passed. Installation
and hardware acceptance of this new image have not been performed.**

| Kernel disposition | Before | After |
|---|---:|---:|
| Source-fixed | 76 | 102 |
| Specific source/configuration/image/board exclusions | 289 | 292 |
| Identified unresolved condition | 27 | 8 |
| Applicability or source equivalence unresolved | 11 | 1 |
| **Original associations** | **403** | **403** |

These are advisory associations, not confirmed exploits. **20
new patches correct 22 associations**. Four additional
original defects are already corrected in the retained source; their complete
caller and ownership paths were re-established. Three exclusions apply only to
the measured image or current hardware, and explicitly retain affected source.
The other 365 kernel assessments and all 136 non-kernel assessments are preserved.

## Layer changes

The image retains Raspberry Pi Linux **6.18.55**, source pin
`4103a989a46196239b830bd07693277e42b8f992`, release **6.18.55-v8-16k**,
and the accepted feature configuration. The 20 new patches
are registered beside the existing 40 in
`meta-rpi5-cam/recipes-kernel/linux/linux-raspberrypi_6.18.bbappend`.
No blanket vulnerability suppression or feature disablement was added.

| Patch | Advisory associations |
|---|---|
| `0200-bound-allocated-btf-object-walks.patch` | [CVE-2026-93148](https://www.cve.org/CVERecord?id=CVE-2026-93148) |
| `0201-preserve-fastcall-patterns-with-incoming-jumps.patch` | [CVE-2026-98048](https://www.cve.org/CVERecord?id=CVE-2026-98048) |
| `0202-keep-borrowed-refcount-acquire-nullable.patch` | [CVE-2026-98038](https://www.cve.org/CVERecord?id=CVE-2026-98038) |
| `0203-reject-large-return-reading-trampolines.patch` | [CVE-2026-90359](https://www.cve.org/CVERecord?id=CVE-2026-90359) |
| `0204-propagate-precision-for-null-helper-arguments.patch` | [CVE-2026-98019](https://www.cve.org/CVERecord?id=CVE-2026-98019) |
| `0205-account-classifier-filter-allocations.patch` | [CVE-2026-90099](https://www.cve.org/CVERecord?id=CVE-2026-90099) |
| `0220-serial-allocate-before-console-publication.patch` | [CVE-2026-90337](https://www.cve.org/CVERecord?id=CVE-2026-90337) |
| `0221-pci-copy-dynamic-id-under-lock.patch` | [CVE-2026-90421](https://www.cve.org/CVERecord?id=CVE-2026-90421) |
| `0222-iomap-release-pins-on-atomic-size-rejection.patch` | [CVE-2026-72370](https://www.cve.org/CVERecord?id=CVE-2026-72370) |
| `0223-f2fs-use-folio-owner-for-atomic-cow-read.patch` | [CVE-2026-63811](https://www.cve.org/CVERecord?id=CVE-2026-63811) |
| `0224-fbdev-serialize-user-mode-updates.patch` | [CVE-2026-80785](https://www.cve.org/CVERecord?id=CVE-2026-80785), [CVE-2026-80786](https://www.cve.org/CVERecord?id=CVE-2026-80786) |
| `0225-thermal-remove-shared-hwmon-with-parent.patch` | [CVE-2026-90311](https://www.cve.org/CVERecord?id=CVE-2026-90311) |
| `0226-ipv6-publish-multicast-lists-with-rcu.patch` | [CVE-2026-98099](https://www.cve.org/CVERecord?id=CVE-2026-98099) |
| `0227-ip6mr-drop-dst-before-report-and-unresolved-queue.patch` | [CVE-2026-90111](https://www.cve.org/CVERecord?id=CVE-2026-90111) |
| `0228-nfs-return-unrecorded-delegation-grants.patch` | [CVE-2026-90234](https://www.cve.org/CVERecord?id=CVE-2026-90234) |
| `0229-net-validate-and-pull-gso-before-transmit.patch` | [CVE-2026-53091](https://www.cve.org/CVERecord?id=CVE-2026-53091) |
| `0230-wifi-use-wiphy-work-for-owner-autodisconnect.patch` | [CVE-2026-68404](https://www.cve.org/CVERecord?id=CVE-2026-68404) |
| `0231-kvm-vgic-serialize-lpi-release-and-reregistration.patch` | [CVE-2026-74568](https://www.cve.org/CVERecord?id=CVE-2026-74568) |
| `0232-nvme-pci-close-dma-and-p2p-tracking-leaks.patch` | [CVE-2026-64019](https://www.cve.org/CVERecord?id=CVE-2026-64019), [CVE-2026-64020](https://www.cve.org/CVERecord?id=CVE-2026-64020) |
| `0240-ext4-check-reserved-inodes-before-lazy-zeroing.patch` | [CVE-2018-10876](https://www.cve.org/CVERecord?id=CVE-2018-10876) |

The changes include verifier bounds/reference/control-flow checks, classifier
accounting, serial allocation ordering, PCI dynamic-ID ownership, iomap pin
cleanup, F2FS atomic COW ownership, fbdev locking, thermal shared-device lifetime,
IPv6 list/route lifetime, NFS delegation returns, GSO validation, cfg80211 work
cancellation, VGIC LPI lifetime, NVMe DMA cleanup and ext4 reserved-inode bounds.
Each adaptation follows this older branch's actual APIs and complete local
callers rather than relying on patch application alone.

NVMe IOVA cleanup uses the complete mapped-state size, including failures at
the first and chained PRP-list allocation. Byte-ownership controls reproduce
the former partial-unmap behavior and require complete cleanup after correction;
direct mappings, host-bridge mappings, bus-address P2P and metadata paths retain
their own matching ownership rules.

The BPF arena experiment is quarantined outside the layer. Its limited host
interleavings do not prove safe VMA/MM teardown or all concurrent page lifetimes.

## Existing fixes and scoped exclusions

| CVE | Decision and boundary |
|---|---|
| CVE-2008-2544 | The exact historical request to create a readonly second proc mount now retains per-mount readonly flags and enforces them on write opens even when another mount and the superblock remain writable. Legacy creation, fsopen/fsmount creation, remount and write-open enforcement were traced separately. Bounded current source controls preserve one RW and two RO mounts on a shared synthetic superblock; the v2.6.24 negative demonstrates omission of per-mount readonly mapping. |
| CVE-2014-8171 | Both historical deadlock mechanisms now have a complete replacement chain: v1 userspace-OOM waiting is deferred until fault-stack unwind, and v2 kernel OOM retries no longer depend indefinitely on a victim releasing filesystem/mmap locks because the asynchronous reaper marks unreapable victims skipped after bounded attempts and the no-victim path returns failure. This conclusion uses the actual generic charge/reaper/selection paths as well as the accepted v1 compile gate, rather than CONFIG_MEMCG_V1 alone. |
| CVE-2019-14899 | The source-level adjacent-network VPN inference issue has no demonstrated general kernel fix, but the exact accepted deployment has no configured VPN/tunnel service, no corresponding executable/configuration packages and only lo/eth0/wlan0 links with ordinary WLAN and link-local routes. TUN/WireGuard/XFRM_USER are modules and absent from the accepted installed inventory. This closes the configured VPN precondition for this exact deployment, not for future VPN use; loose rp_filter is not credited as a mitigation. |
| CVE-2020-10742 | The original reused NFS page-vector overflow is removed: both direct read and write allocate a new vector for every current iterator chunk with iov_iter_get_pages_alloc2. The previous assertion that NFS used iov_iter_extract_pages was wrong and is corrected. Actual allocator controls confirm capacity/refcount bounds for IOVEC, UBUF and BVEC, misalignment, partial GUP and cleanup. FOLIOQ/XARRAY bounds and both scheduling release paths were reviewed statically. A separate zero-return scheduling contract remains unresolved and is explicitly preserved below; this is not an all-NFS correctness claim. |
| CVE-2020-1749 | All original IPv6 XFRM-bypass consumers now route through a flow lookup that performs xfrm_lookup_route; the original fix changed eight consumer files and three stub/interface files. The previously missing Geneve/VXLAN helper, every relevant cache population site, cache validity and policy-change invalidation have now been retained and traced. The complete current UDP helper/flow/cache-get control passes transformed-route, stale-cache, policy-denial and circular-route cases; the historical API negative returns an untransformed route without XFRM. |
| CVE-2023-6238 | The missing metadata bound is now concretely traced: passthrough ioctl and io_uring metadata_len reaches blk_rq_integrity_map_user without reconciliation against opcode/namespace NLB geometry. PCI metadata-SGL commands carry explicit lengths, but the supported non-SGL MPTR branch supplies only an address and remains unchecked. This source issue is open. The accepted Pi currently has no NVMe controller or /dev/nvme node, providing an exact current-hardware exclusion; CONFIG_BLK_DEV_NVME=y and privilege checks are not used as exclusions. |
| CVE-2023-6240 | The RSA timing source remains open: pkcs1pad_decrypt_complete still exits on secret-dependent padding values and scans for a secret-dependent zero separator; no public matching upstream timing correction was identified despite issued RHEL errata. The accepted image excludes the identified KEYCTL private-key oracle: pkcs8_parser is the only assignment of key_is_private=true, CONFIG_PKCS8_PRIVATE_KEY_PARSER=m, and pkcs8_key_parser is absent from both the exact 25-module inventory and the hash-matched builtin list. RSA itself remains builtin and source-open for future private parser/module enablement. |

The separate NFS zero-return scheduling concern remains unresolved; closing the
original reused-page-vector defect does not claim that all NFS direct-I/O paths
are safe. The proc, memcg, NFS and XFRM closure dependency files are hash-bound
again to the final compiled source. Static lifetime reasoning and bounded host
controls do not constitute kernel concurrency stress testing.

## Verification

- The original 40 patch files and source pin are retained. All 60
  patches round-trip with zero fuzz against the final source; unselected assessed
  paths are checked for drift.
- All 365 project host tests passed. All 14 previous/current source-regression
  groups passed against the combined candidate and final compiled source.
  Pre-fix failures and valid-operation/error controls are retained. The legacy
  fbdev fixture gained balanced lock instrumentation without weakening bounds
  checks. A rejected evidence-output path was corrected without changing tests.
- All 32 configured changed C translation units compiled with the real ARM64
  compiler, generated headers and saved kernel flags before integration.
  Disabled PS3/SH fbdev callers were source-reviewed; they are not claimed as
  cross-architecture compile coverage. The temporary `CONFIG_CC_CAN_LINK` probe
  is recorded separately; exported configuration and effective features match.
- Every one of the **25 installed modules**, including Hailo, was matched to
  the new kernel: **2254 imported symbol CRCs** and
  50 deliberate mismatch/missing-export controls.
  The **1546 export changes** are independently reviewed;
  exact old/new `genksyms` replay reproduced 1546
  changes across 235 owner units, with 773
  unchanged controls. This is not an external-module ABI guarantee.
- The actual compressed WIC was read without mounting or flashing a device.
  Its kernel, all module paths/bytes, protected userspace files, boot configuration,
  Camera Module 3 overlay, Pi 5 DTB and 16 privileged-file ownership/mode records
  match the reviewed build. All 182 protected library files retain their bytes,
  SONAME and exports. Package versions and accepted camera/Wi-Fi configuration
  remain unchanged.
- Image checks confirm that Codex authentication, per-device application
  configuration, TLS private keys and the timesync clock seed are absent from
  the distributed image. Installation-time restoration remains separate.
- Only `rpi5-camera-hailo` was built, with `BB_NUMBER_THREADS=4` and
  `PARALLEL_MAKE=-j 4`.
  No QEMU/minimal image, operating-Pi modification or SSD write was performed.

## Remaining conditions

| CVE | Remaining work |
|---|---|
| CVE-1999-0524 | Define whether timestamp replies are allowed, then obtain a read-only ingress-rule listing or separately authorized controlled packet observation. Do not change ICMP or firewall policy during this task. |
| CVE-2007-2764 | Obtain Oracle/Brocade alert 102752 or the Fabric OS patch/reproducer details from the vendor, then identify and compare the entire defective function. The task remains inconclusive until this unavailable primary evidence is supplied. |
| CVE-2010-4563 | Resolve intended packet/capture policy and firmware receive behavior in a separately authorized controlled network. Current non-promiscuous flags and the optional sysctl do not establish a source fix. No feature or sysctl changes were made. |
| CVE-2021-3864 | Track the source transition as open. Establish ownership/persistence and intended coredump policy before claiming a stable deployment exclusion; no policy change or descendant crash test was performed. |
| CVE-2026-43174 | Implement the complete per-ifq prerequisite on the older ctx-ref provider API, then test every xa/rbuf/netdev/device/area/open/publish/copyout fault with delayed pool destruction; prove exactly-once netdev/device/area/rbuf cleanup. Compile zcrx.c and every changed header consumer before integration. |
| CVE-2026-74354 | Review provisional page-detachment/MM-lifetime synchronization independently against every VM callback, final map destruction, delayed fault PTE install, MM exit, VMA aliases and OOM fallback. Establish a complete upstream-equivalent lifetime/locking proof and real ARM64/runtime concurrency validation before proposing integration. |
| CVE-2026-89584 | Implement old-extractor mem-mask propagation across block/bio.c, blk-map.c, fops.c, iomap/direct-io.c and bio.h, validate user iterator forms and registered BVEC, then fault/test first/later misalignment and duplicate/folio pin rollback plus normal/short/passthrough controls. Audit bio_iov_iter_get_pages export CRC and complete caller rebuild. |
| CVE-2026-98032 | Port full destination-owned capacity and allocator/reuse contract across ring_buffer.c, trace.c, trace.h, ring_buffer.h and benchmark; run shrink/grow/partial-copy/wait/reallocation-failure/splice-ref tests at16K base pages, then actual ARM64 units and export/module ABI review. |
| CVE-2026-98153 | Implement constructor/query parameter adaptation and immutable plids/granularity; test concurrent shared-head discovery/reuse, FDPS absent/FDPE off, config/io-mgmt/errors, zero descriptors and allocation/SRCU/effects/mpath failures, proving no publication or leak. Compile core.c plus changed nvme.h users and review layout/CRC delta before integration. |

The 539 original whole-image associations now have these counts:
`{"fixed": 191, "notaffected": 328, "open": 17, "partially_mitigated_open": 2, "unassessed": 1}`.
Other-library, FFmpeg and separate BusyBox findings are outside this kernel pass.
The raw final-SPDX scan uses the retained **2026-10-11** database snapshot; it is
not a fresh whole-image database scan. Its unresolved association count is
**403**, with
**0** new unresolved associations outside the original ledger.
The 38 targeted primary records/source references were reviewed on 2026-10-14.
No whole-image security clearance is claimed.

## Delivery and evidence

Image: `artifacts/20261014T064455Z-e664cb9647e7/rpi5-camera-hailo/images/rpi5-camera-image-raspberrypi5.rootfs.wic.bz2`.

Install through `scripts/install-ssd.sh` when the intended SSD is connected to
the build PC. New-image boot, camera and Hailo acceptance must be recorded
separately after installation.

Curated evidence is stored beside the image under
`security/kernel-followup-evidence/`, with a SHA256 manifest. Private working
records remain in `.state/kernel-followup-2026-10-14/` and are Git-excluded.
The record retains primary-source snapshots, per-CVE reasoning, patch/file
identities, negative controls, independent reviews, build logs, module/ABI
checks and exact-image bindings. Historical accepted-build evidence is preserved.
