# Kernel deep follow-up — 2026-10-14

This pass reviews the nine remaining kernel associations after accepted image
`20261014T064455Z-e664cb9647e7`. The [previous hardware acceptance](kernel-followup-deployment-validation-2026-10-14.md)
remains evidence for that image only.

**The Hailo image `20261014T092945Z-e664cb9647e7` passed build, source/module compatibility and actual
WIC verification. It has not been installed or accepted on the Pi (`hardware_acceptance=NOT_RUN`).**

| Kernel disposition | Before | After |
|---|---:|---:|
| Source-fixed | 102 | 106 |
| Specific source/configuration/image/board exclusion | 292 | 292 |
| Open | 8 | 4 |
| Unassessed | 1 | 1 |
| Original associations | 403 | 403 |

The original whole-image 539-association ledger is now: {'open': 13, 'notaffected': 328, 'fixed': 195, 'partially_mitigated_open': 2, 'unassessed': 1}.
All 394 previously resolved kernel assessments and all 136 non-kernel assessments
are preserved. These counts describe advisory associations, not confirmed attacks
or a whole-image security clearance. The scanner database remains the retained
2026-10-11 snapshot; selected primary records were reviewed on 2026-10-14.

## Integrated layer corrections

Linux remains 6.18.55 at source pin `4103a989a46196239b830bd07693277e42b8f992`,
release `6.18.55-v8-16k`. Four new patches join the 60 accepted patches in
`meta-rpi5-cam/recipes-kernel/linux/linux-raspberrypi_6.18.bbappend`.
The accepted board configuration and protected camera/Wi-Fi/Hailo packaged files were retained.
No blanket vulnerability overrides or feature disabling were added.

| Association | Complete local correction |
|---|---|
| [CVE-2026-43174](https://git.kernel.org/stable/c/18afaff077b46655a8eb6fd7f6de1b81327be577) | Retain each ZCRX queue through delayed provider destruction, with independent context ownership, exactly-once error cleanup, spinlock-protected final uninstall publication and live-context admission with mapping-error rollback. |
| [CVE-2026-89584](https://git.kernel.org/stable/c/d44a97a3b1c00cc571245124e23e5ceb0a0225a0) | Propagate memory alignment through direct-I/O callers, including registered BVEC offsets; reject invalid later segments and unwind pins and iterator movement. |
| [CVE-2026-98032](https://git.kernel.org/stable/c/dae8dda341d2d9034a90d59e8a7d502e1263813f) | Use each read allocation's capacity across resize, partial reads, copying, zero fill, splice and benchmark; preserve immediate rejection of base-page-invalid input on empty rings. |
| CVE-2026-98153 | Initialize immutable FDP placement data and granularity before namespace-head publication; adapt unpublished-head queries/request logging and all query/multipath failure cleanup. |

The first candidate build was stopped before artifact collection after final review
identified an embedded-mutex release lifetime gap. Its results were retained as a
superseded attempt. The shipped candidate additionally rejects provider admission
after completed context shutdown and was recompiled and reviewed before the final build.

The tracing allocator's exported signature changes deliberately and its page-size
accessor is newly exported. The bio helper's source signature also changes; it is
not an exported kernel symbol in this build. All actual in-tree callers are updated.
Compatibility of arbitrary external modules is not claimed. The final ZCRX lock-release audit is
bound to the retained non-PREEMPT_RT configuration and disabled spinlock/lockdep
debug instrumentation; changing those features requires a fresh lifetime review.

## Validation

- Project host suite: 365 tests passed. No QEMU or minimal image was built.
- Actual configured ARM64 compiler commands: 19 configured units plus the optional
  tracing benchmark; two additional optional NVMe multipath controls passed.
- Existing and new actual-source regression groups: 17 passed against the compiled
  source. New source suites cover I/O17+30, 12 additional lock/context lifetime
  controls, tracing33 and NVMe45 cases; independent
  review adds real-iterator ownership and empty-splice controls. Tests model external
  kernel facilities and bounded schedules; they do not prove arbitrary concurrent
  kernel execution or weak-memory behavior.
- All 25 shipped modules match 2254 required kernel
  symbol CRCs; 50 corrupted/missing-symbol controls reject.
- All 8 changed exports reproduced from both accepted and new
  source with the real compiler/genksyms across 2 owner units.
  Independent review accounts for their exact source/type causes.
- Actual WIC checks bind 250 total extracted files, 25 modules, 182 shared
  libraries, 16 privileged metadata records and boot files. Libraries, camera IPA
  files/signatures, app/Codex/Wi-Fi files and package versions remain unchanged.
- Exported kernel feature config SHA256 remains
  `751ecdb597addf24fb7e2eb954cc28e4fc523983665e294c032dd11cd0ca8250`.
  The compiled configuration's generated `CONFIG_CC_CAN_LINK` probe is recorded
  separately; no other compiled configuration differences are accepted.
- The checked Codex auth.json paths, generated app/TLS private configuration and old
  clock seeds are absent. Local credentials remain Git-excluded.

WIC SHA256: `36a1be9352507f2651c5082713e1ec5addb4fb9c87c8a087c752c13a08c67cf3`.
Boot kernel SHA256: `4abcef0aef7f007c2e3442d4da5eaab874810437268e621207462e8485ef573d`.

## Remaining conditions

| Association | Remaining work |
|---|---|
| CVE-2026-74354 | BPF arena remains open. The rejected private experiment fails fork-alias/parent-close, delayed-PTE and OOM interleavings. A complete upstream-compatible MM/VMA/page-lifetime correction is still required; no arena experiment enters the layer. |
| CVE-1999-0524 | ICMP timestamp response policy remains open; no network behavior was changed implicitly. |
| CVE-2010-4563 | IPv6 unicast-in-L2-multicast policy remains open, with retained per-interface/default configuration boundaries. |
| CVE-2021-3864 | Coredump policy remains open. Prior `core_pattern` observations identify an older build and are not promoted to current-image runtime mitigation. |
| CVE-2007-2764 | Sun/Brocade advisory source equivalence remains unassessed; product/name matching alone cannot resolve it. |

Independent additional finding: the existing NVMe FDP response parser trusts a
reported descriptor count beyond its fixed 126-descriptor transfer buffer. This
behavior predates patch0340 and is **not corrected or declared safe** by the
publication-lifetime fix. Protocol semantics and complete response-length bounds
need a separate follow-up; see `nvme/review/ruhs-count-followup.json` in the evidence.
It is not silently added to or removed from the original 403-association ledger.

## Delivery and evidence

Image: `artifacts/20261014T092945Z-e664cb9647e7/rpi5-camera-hailo/images/rpi5-camera-image-raspberrypi5.rootfs.wic.bz2`.
Install using `scripts/install-ssd.sh` after connecting the intended SSD. Installation
and fresh boot/web/camera/Hailo acceptance remain separate user/device actions.

Reviewed evidence is retained under `.state/kernel-deep-followup-2026-10-14/`
and archived with a checked SHA256 manifest under
`artifacts/20261014T092945Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-deep-followup-evidence/`.
The archive contains source regressions, accepted/rejected attempt evidence,
patch manifests, source/config/export/module/image bindings and independent reviews.
Historical test inputs retain references to earlier evidence; the archive does not
guarantee self-contained re-execution.
