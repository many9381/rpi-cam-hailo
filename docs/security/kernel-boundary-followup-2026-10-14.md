# Kernel boundary follow-up — 2026-10-14

BPF arena mapping lifetime and NVMe FDP response bounds are corrected in the
Hailo image `20261014T125728Z-e664cb9647e7`. Build, actual-source regressions, module compatibility
and extracted WIC checks passed. **This new image has not been installed or
accepted on the Pi (`hardware_acceptance=NOT_RUN`).**

The preceding image `20261014T092945Z-e664cb9647e7` passed three reboots and
explicit user confirmation of video, Hailo readiness, increasing frames and
object/confidence output. Its [deployment acceptance](kernel-deep-followup-deployment-validation-2026-10-14.md)
applies only to that preceding image.

## Layer corrections

The two new patches join all 64 accepted patches in
`meta-rpi5-cam/recipes-kernel/linux/linux-raspberrypi_6.18.bbappend`.
Linux remains at source pin `4103a989a46196239b830bd07693277e42b8f992`,
release `6.18.55-v8-16k`; the accepted feature configuration is unchanged.

| Patch | Result |
|---|---|
| `0400-bpf-arena-protect-mapped-vma-lifetimes.patch` | Replace saved raw VMA pointers with inode-pinned mapping records. Walk the existing mapping interval tree under its read lock, filter both arena operations and map identity, and zap only overlapping ranges. Fork aliases remain visible after parent close; final record removal and new-map lookup share the arena mutex. |
| `0401-nvme-bound-fdp-response-parsing.patch` | Limit FDP placement parsing to the 126 descriptors requested, while accepting valid partial responses with larger total counts. Validate first and refreshed configuration-log sizes, every descriptor header, declared length, alignment and remaining bytes before access or advancement. Preserve ordinary namespace operation and existing publication/cleanup behavior. |

The arena correction addresses [CVE-2026-74354](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/74xxx/CVE-2026-74354.json)
through a locally reviewed adaptation to this retained implementation. Its mapping
lock pattern follows `unmap_mapping_pages()` in the pinned kernel. It avoids adding
`mmap_lock` below the arena mutex or changing the existing free/allocate/reserve
serialization. Delayed faults retain their page references; this is not a promise
that a concurrent free permanently forbids later mapping. Existing range-tree
allocation-failure availability limitations remain outside this correction.

NVMe behavior was checked against the complete official
[NVM Express Base Specification 2.1](https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-Revision-2.1-2024.08.05-Ratified.pdf),
sections 7.3/7.3.1.1 and the FDP configuration-log definitions. The response-bound
findings are recorded separately from the previously corrected FDP publication
lifetime issue. They receive no invented CVE assignment and do not alter the
original association count.

## Validation

- Project host suite: 365 tests passed.
- Complete affected `kernel/bpf/arena.c` and `drivers/nvme/host/core.c` compiled
  with the retained real ARM64 compiler commands and `-Werror` before integration.
  The complete Hailo kernel and image then built with at most four workers.
- 20 current and retained source-regression groups passed
  against the final compiled source. Earlier input failures, normal behavior,
  error cleanup and bounded concurrency schedules are retained in the evidence.
  These host controls and source review do not claim live kernel stress or weak-memory proof.
- All 25 shipped modules match 2254 imported symbol CRCs;
  50 corrupted/missing-symbol controls reject. Exported symbols
  and CRCs are unchanged from the accepted baseline.
- All 66 patches reverse exactly to the pinned source and reapply
  without fuzz. Unselected assessed source files remain identical.
- The actual WIC was checked for 250 extracted files, 25 modules,
  182 shared libraries, 16 privileged metadata records and boot files.
  Protected camera IPA/signature, Wi-Fi, Hailo, application and Codex files,
  shared-library contents and package versions remain identical.
- The checked Codex authentication files, generated app/TLS private configuration
  and old clock seeds are absent from the image. Local credentials remain Git-excluded.
- No QEMU or minimal image was built. No SSD or running Pi was modified for this build.

WIC SHA256: `3c4cbab248fd9b284dac380573a3356e9c2d42fc9caf415e61310e4cd0721ded`.
Boot kernel SHA256: `61457fcafe4578b940ba8573fcafab34c6c7676f791a37f86d6cb53775b309e4`.
Configuration SHA256: `751ecdb597addf24fb7e2eb954cc28e4fc523983665e294c032dd11cd0ca8250`.

## Assessment boundaries and remaining work

| Kernel disposition | Before | After |
|---|---:|---:|
| Source-fixed | 106 | 107 |
| Specific source/configuration/image/board exclusion | 292 | 292 |
| Open | 4 | 3 |
| Unassessed | 1 | 1 |
| Original associations | 403 | 403 |

The whole-image 539-association ledger is now `{'open': 12, 'notaffected': 328, 'fixed': 196, 'partially_mitigated_open': 2, 'unassessed': 1}`.
All other 402 kernel assessments and all 136 non-kernel assessments are preserved.
The scanner database remains the **2026-10-11 snapshot**; only the selected primary
records/specification were reviewed on 2026-10-14. Counts are advisory associations,
not confirmed attacks or a whole-image security clearance.

The ICMP timestamp, IPv6 L2-multicast and coredump-policy associations remain open.
The Sun/Brocade advisory equivalence remains unassessed. Other library/application
open and partially mitigated findings retain their previous status.

## Delivery and evidence

Image: `artifacts/20261014T125728Z-e664cb9647e7/rpi5-camera-hailo/images/rpi5-camera-image-raspberrypi5.rootfs.wic.bz2`.
Use `scripts/install-ssd.sh` with the intended SSD connected. New-image installation
and boot/web/camera/Hailo acceptance are the next separate device step.

Reviewed evidence is in `.state/kernel-boundary-followup-2026-10-14/` and archived
with a checked SHA256 manifest under
`artifacts/20261014T125728Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-boundary-followup-evidence/`.
The archive includes patch/source manifests, primary-source provenance, regression
inputs/results, compiler checks, image bindings and independent reviews. Historical
controls reference earlier evidence; standalone re-execution is not guaranteed.
