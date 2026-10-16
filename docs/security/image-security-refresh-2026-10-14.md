# Installed-image security refresh — 2026-10-14

The accepted image `20261014T152325Z-e664cb9647e7` was rescanned against pinned
October 14 vulnerability data, including the seven packages added by the kernel
policy change. The refresh identifies **three additional source-open findings**:
one in kernel CoDel/FQ-CoDel and two in util-linux mount. Four other newly
affected recipe/CVE associations have image-specific exclusions below.

This is an assessment update. It changes no layer code, image, installed device,
or input SPDX/VEX annotation. Existing [Pi acceptance](kernel-policy-deployment-validation-2026-10-14.md)
remains valid for the same image; it does not establish resistance to these newly
reviewed vulnerabilities. Rebuilding or reinstalling the unchanged image would
not resolve them.

## Inputs and reproducibility

| Input | Identity |
|---|---|
| Build | `20261014T152325Z-e664cb9647e7` |
| Installed inventory | 460 packages, mapped exactly once to 148 SPDX recipe groups |
| WIC bz2 SHA-256 | `60c48862a4df7a085961907128d33050ad9f5a35fcd71646d49bb5b4d68774b6` |
| Input SPDX SHA-256 | `c3d4c77abadf07a61f4f3167cff5121f06751e12680e1a59720a2b75bb088ea7` |
| Manifest SHA-256 | `5a3d5741df4c3964778b3019eab5303ab549d3c3653becda31ba68a1bc66ab9a` |
| Kernel | 6.18.55-v8-16k, patched source `7055acd80eb1dcec2a72e8754b9a76da64a13bff` |
| Scanner | sbom-cve-check 1.3.5, upstream commit `56b6b51e158e0dcfa8672e04bfd20814343896a0` |
| NVD feed | [FKIE NVD mirror v2026.10.14-084743](https://github.com/fkie-cad/nvd-json-data-feeds/releases/tag/v2026.10.14-084743), published 09:09:55 UTC; 407,463 records |
| CVE List | [cve_2026-10-14_1500Z](https://github.com/CVEProject/cvelistV5/releases/tag/cve_2026-10-14_1500Z), midnight snapshot plus 15:00 delta, published 15:29:08 UTC; 407,703 distinct records |

Download digests were checked against release asset metadata. The decompressed
NVD size and SHA-256 were also checked against its published metadata. The local
SQLite adapter uses the scanner's upstream NVD/CVE List parsers and version
assessment code with the same pinned product mapping. Positive, fixed, rejected
and preserved Yocto-patch controls pass. Scans run offline with updates disabled.

The same final SPDX was scanned twice: once with the retained October 11 data,
once with the October 14 data. This separates database changes from the package
delta. Both scans exited successfully and left input SPDX unchanged. A failed
initial run and diagnostic are retained: the scanner attempted to create its
lock in a read-only home cache; its supported database-directory setting was
redirected into the task workspace. Upstream scanner code was not patched.

## Raw results and assessment ledger

Counts below are **recipe/CVE associations**, not confirmed exploitable flaws.
Only exact manifest package matches are selected from the raw target report.
Build-only and native components are not counted as installed packages.

| Same final image | Raw `fixed` | Raw `not_affected` | Raw `affected` | Total |
|---|---:|---:|---:|---:|
| October 11 database | 23,915 | 30 | 398 | 24,343 |
| October 14 database | 23,960 | 30 | 405 | 24,395 |

The database refresh adds 52 associations: 46 raw fixed/version-excluded and six
raw affected. One existing Btrfs association changes from raw fixed to affected.
No associations disappear. The seven newly affected associations cover five
distinct CVEs; util-linux and its separate libuuid recipe share two matches.
The scanner's `fixed` label also includes versions before a vulnerability was
introduced; it is not proof that a local patch was applied.

The manually assessed candidate ledger retains the prior 539 associations and
adds those seven, giving **546 tracked associations**:

| Assessment | Prior 539 | Updated 546 |
|---|---:|---:|
| Fixed | 197 | 197 |
| Not affected in this image | 327 | 331 |
| Source open | 12 | 15 |
| Partially mitigated, still open | 2 | 2 |
| Unassessed | 1 | 1 |

This ledger is not the denominator for the whole raw report. The 46 additional
raw fixed/version-excluded associations remain visible in the scan delta. The
separate BusyBox `cp` destination-symlink follow-up for CVE-2007-4998 also remains
unassessed outside this historical candidate denominator.

Thirty-five previously assessed records changed between snapshots. Their
English/CNA vulnerability descriptions remain unchanged. Changes comprise
translations, analysis/ADP metadata, Red Hat downstream product advisories, NVD
version ranges and additional Linux stable fixes. The seven changed kernel
configuration exclusions were rechecked against the exact final configuration
and build rules. These changes do not invalidate the retained source/configuration
assessments. The per-record review is preserved in `prior-ledger-change-review.json`.

## Newly affected associations

| Recipe / CVE | Assessment | Image-specific evidence and follow-up |
|---|---|---|
| Linux / CVE-2026-98427 | **Open** | `sch_fq_codel.ko` is shipped. Its shared CoDel implementation lacks both the minimum control-law step and per-dequeue drop bound. Review/backport the complete fix and verify qdisc behavior with matching kernel/module builds. |
| util-linux / CVE-2026-53612 | **Open, prerequisites absent in stock configuration** | libmount 2.41.3 retains pathname `lchown`/`chmod`; `mount.util-linux` is root-owned mode 04755 in the actual WIC. Stock WIC fstab has no `user`/`users` or `X-mount.*` entries. Source correction is still needed before such privileged user-mount configurations are allowed. |
| util-linux / CVE-2026-53613 | **Open, prerequisites absent in stock configuration** | SUID mount and old target-path handling remain. Stock fstab lacks authorized user mounts. Follow-up must cover both new and legacy mount APIs, including the documented `/proc`-absent fallback; an earlier partial release fix is insufficient evidence of closure. |
| curl / CVE-2026-92392 | Not affected in this system libcurl build | HTTP/2 is disabled: `--without-nghttp2`, configure `HTTP2: no`, `USE_NGHTTP2` undefined, no nghttp2 dynamic dependency. Library bytes match the actual WIC. Reassess if HTTP/2 is enabled or a different bundled client is used. |
| Linux / CVE-2026-80734 | Not affected in this image | Btrfs is configured as a module, but is absent from the verified complete 27-module WIC inventory and is not built in. This is an absence-based exclusion, despite the changed raw version match. |
| util-linux-libuuid / CVE-2026-53612 and CVE-2026-53613 | Not affected in this separate recipe | The recipe installs only `libuuid1`; affected mount/libmount code belongs to the separately assessed util-linux recipe, which remains open. |

Primary sources:
[kernel CoDel correction](https://github.com/torvalds/linux/commit/7f4a5ec6258fd7c92633ec4b0493fc51166d9398),
[mount owner-operation advisory](https://github.com/util-linux/util-linux/security/advisories/GHSA-g8wm-75wr-g2vh),
[mount target-path advisory](https://github.com/util-linux/util-linux/security/advisories/GHSA-8gj5-72r3-428g),
[curl HTTP/2 advisory](https://curl.se/docs/CVE-2026-92392.html),
and the pinned CVE List records retained in `primary/cves/`. The current CVE List
record includes later util-linux legacy-path details that the older advisory's
headline fixed-version field alone does not capture. curl's vendor identifies
8.23.0 as fixed and disabling HTTP/2 as a workaround.

No denial-of-service or privilege-escalation reproduction was run on the Pi or
host. The new conclusions use source, build configuration, package membership
and a read-only extraction of selected files from the actual compressed WIC.
The WIC fstab is assessed directly because Wic adds mount entries after the
intermediate rootfs is assembled. Device configuration changed after installation
would require a new applicability check.

## Newly installed dependencies and coverage limits

| Newly installed userspace recipe | Version | Current result |
|---|---|---|
| nftables | 1.1.6 | One historical match, raw fixed; no affected match |
| jansson | 2.15.0 | Three historical matches, raw fixed; no affected match |
| readline | 8.3 | One historical match, raw fixed; no affected match |
| libnftnl | 1.3.1 | No CVE rows from the pinned product mapping; not a security clearance |
| rpi5-security-policy | 1.0 | Local recipe with no CVE rows; source/build/device policy evidence is recorded separately |

The two newly shipped modules `nf_tables` and `nfnetlink` are part of the kernel
assessment. CVE-2026-90061 remains **fixed**, using the verified ownership patch;
its former module-absence exclusion was already retired. The three policy-related
kernel findings retain their source-open status and their separately recorded
device policy evidence.

All 460 installed packages are represented in the SPDX, but only 92 of the 148
installed recipe groups have CVE report rows. The other 56 are listed with their
identifiers in `matching-coverage.json`. Absence of a match does not prove absence
of vulnerabilities. In particular, Hailo vendor packages, libcamera, Codex,
application/vendored sources and bundled dependencies need their own advisory
and dependency inventories. This refresh does not rerun npm audit, Rust dependency
audits, application tests or a vendor-binary audit.

## Evidence and next work

The working evidence is `.state/security-refresh-2026-10-14/`. Curated evidence,
raw reports, assessment files, primary records, tool configuration and checksums
are archived under:

`artifacts/20261014T152325Z-e664cb9647e7/rpi5-camera-hailo/security/security-refresh-2026-10-14/`

Large public database/download caches are retained once in `.state`, not copied
into the artifact archive or Git. The archive records their hashes and public
download locations. Raw CSV/Yocto/SPDX results and the separate assessment ledger
are preserved; manual exclusions do not rewrite scanner results or build VEX.

Next remediation priorities are the installed FQ-CoDel path and the two related
util-linux mount findings. Existing unresolved library/kernel findings, the two
partial mitigations, the Sun/Brocade applicability question and BusyBox `cp`
follow-up remain tracked. No image rebuild, SSD write, QEMU build or device reboot
was performed for this audit.
