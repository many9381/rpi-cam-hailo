# Security evidence (TTA 10.x)

This directory holds the artifacts that back the certification items on known
vulnerabilities (TTA 10.2) and source weaknesses (TTA 10.1). Dated reports
identify the source, image or device they assessed and distinguish automated
checks from operator observations. They are evidence records, not a claim of
certification or of zero remaining vulnerabilities.

## Agreed work exclusions

Long-duration operation/endurance testing was excluded at the user's request
on 2026-10-12, as recorded in the
[deployment scope](security-deployment-validation-2026-10-12.md#증거와-범위),
and reconfirmed on 2026-10-16. Keep it out of remaining-work lists and next-task
recommendations unless the user explicitly changes that decision. Later reports
that say this testing was not performed describe the evidence boundary; they
do not reopen the excluded task.

Additional MOV/common-allocator redesign is also excluded from current required
firmware work under the separate
[October 15 agreement](ffmpeg-mov-fragment-followup-2026-10-15.md#agreed-disposition).
These scope decisions do not turn unperformed tests into passes or close
unresolved vulnerability findings.

## Current Yocto image evidence

As of 2026-10-16, the accepted development image is
`20261016T111625Z-e664cb9647e7`, profile `rpi5-camera-hailo`.
[Build verification](static-warning-image-2026-10-16.md) and
[installed-device acceptance](static-warning-deployment-validation-2026-10-16.md)
cover that exact image. Acceptance includes 415 readable installed-file hashes,
three Wi-Fi reboots, actual capture progress, operator-confirmed video/Hailo
results and Codex 0.163.0 login/daemon checks. Setup was already complete when
inspected and remained complete after reboot.

The [version-preservation record](version-preservation-2026-10-16.md) links
local tag `validated-20261016T111625Z` in both repositories to these inputs
and distinguishes fresh snapshot checks from historical device acceptance.

The [selective warning review](static-warning-review-2026-10-16.md) and its
included `0010` patch establish 79 product units with 0 analysis errors and
198 remaining warnings, plus 361 selected target regression tests and 25 host
packaging tests. The preceding [source quality gate](static-analysis-2026-10-15.md)
records 1,356 CTest passes, 10 explicit hardware skips and 770 web tests on the
earlier 208-warning baseline; that full suite was not rerun for this deployment.

In the companion Yocto workspace, use
`artifacts/20261016T111625Z-e664cb9647e7/rpi5-camera-hailo/`:

| Relative path | What it establishes |
|---|---|
| `manifests/rpi5-camera-image-raspberrypi5.rootfs.manifest` | Installed Yocto package names, architectures and versions; 460 entries in this build |
| `manifests/image.spdx.json` | SPDX collected from this image's actual build output |
| `manifests/layer-revisions.txt` | Fetched upstream layer revisions |
| `provenance/inputs.json`, `provenance/sources.tar` | Local integration inputs, recipe pins and patch bytes; versions alone do not describe applied backports |
| `checksums/SHA256SUMS` | Image, manifest and provenance integrity |
| `security/static-warning-image-2026-10-16/` | Actual WIC verification and matching source-quality inputs |
| `security/static-warning-deployment-2026-10-16/` | Installation and hardware acceptance, with its own evidence checksums |

These generated/private artifacts remain outside Git. When this firmware
checkout is nested in the image workspace, the
[build provenance runbook](../../../docs/runbooks/build-provenance.md) explains
collection and checksum verification. `COMPLETE` means build/artifact collection
finished; it is not a security verdict or device acceptance marker.

The [October 15 residual assessment](security-residual-followup-2026-10-15.md)
retains 11 open, three partial and one unassessed association. The subsequent
source-quality builds did not run a fresh vulnerability-database scan or change
those classifications. Additional MOV allocator redesign remains
[deferred by agreement](ffmpeg-mov-fragment-followup-2026-10-15.md).

The [October 16 consumer review](consumer-boundary-review-2026-10-16.md) verified
867 ELF paths against that accepted WIC, narrowed the HailoRT `glob` call to a
fixed hardware-monitor pattern, and found no dynamic `evhttp_*` consumer.
Fourteen non-MOV primary records are unchanged. No additional layer patch or
image build was justified; retain the existing dispositions and reopen work
when the documented input-path, configuration or upstream-evidence triggers
change, rather than automatically reassigning unchanged findings.

**Current product work status: completed, no additional action for the reviewed
libevent camera/`cam` paths or HailoRT fixed-pattern `glob` call.** These are
excluded from active remaining-work lists under the
[recorded disposition](consumer-boundary-review-2026-10-16.md#product-work-status).
The library advisory ledger is retained separately; its open counts must not
be presented as an equivalent count of required development tasks.

## Dated reports and historical inventories

| File | What it is |
|---|---|
| [consumer-boundary-review-2026-10-16.md](consumer-boundary-review-2026-10-16.md) | Actual-image consumer review: 871 file hashes, fixed HailoRT glob argument, libevent event-loop-only identified consumer, fourteen unchanged primary records; no new production patch or rebuild required |
| [static-warning-deployment-validation-2026-10-16.md](static-warning-deployment-validation-2026-10-16.md) | Current image accepted: 415 readable installed files, three Wi-Fi reboots, actual capture progress, Codex 0.163.0 login/daemon checks and user-confirmed video/Hailo PASS |
| [static-warning-image-2026-10-16.md](static-warning-image-2026-10-16.md) | Hailo image built with `0010`; 417 WIC files and 257 C++ source hashes verified; configured Codex update to 0.163.0; subsequent installation/hardware acceptance PASS recorded above |
| [static-warning-review-2026-10-16.md](static-warning-review-2026-10-16.md) | Ten selected warnings removed; 79 product units, 0 errors / 198 warnings; 361 selected target tests and 25 packaging tests; subsequent image build recorded above |
| [quality-gate-deployment-validation-2026-10-16.md](quality-gate-deployment-validation-2026-10-16.md) | New quality-gate image accepted: 400 readable installed files, three Wi-Fi reboots, actual capture progress and user-confirmed video/Hailo PASS |
| [quality-gate-image-2026-10-15.md](quality-gate-image-2026-10-15.md) | Quality-gate corrections built into the Hailo image; 402 actual WIC files and 257 tested C++ inputs verified; October 16 installation and hardware acceptance recorded above |
| [static-analysis-2026-10-15.md](static-analysis-2026-10-15.md) | Previous source baseline: 79 product units, 0 analysis errors / 208 warnings, 1,356 CTest passes / 10 hardware skips, 770 web tests; later selective warning improvements recorded above |
| [ffmpeg-mov-fragment-followup-2026-10-15.md](ffmpeg-mov-fragment-followup-2026-10-15.md) | Additional MOV work deferred and excluded from current required firmware work by user agreement; no direct app input path identified; existing patches retained, advisory remains partial/open |
| [camera-capture-health-deployment-validation-2026-10-15.md](camera-capture-health-deployment-validation-2026-10-15.md) | Capture-health image accepted: 396 file hashes, 70 target runtime tests, three reboots with actual capture progress and user-confirmed video/Hailo |
| [camera-capture-health-2026-10-15.md](camera-capture-health-2026-10-15.md) | Capture liveness, protected bounded recovery, truthful web state and reusable read-only capture acceptance; deployment validation recorded separately above |
| [ffmpeg-mov-deployment-validation-2026-10-15.md](ffmpeg-mov-deployment-validation-2026-10-15.md) | MOV image accepted after cable/power recovery: retained 20 system-FFmpeg tests, fresh capture progress, three new reboots and user-confirmed video/Hailo |
| [camera-capture-failure-2026-10-15.md](camera-capture-failure-2026-10-15.md) | Historical initial capture failure and validation gap; capture recovered after cable inspection/power cycle, with subsequent acceptance linked above |
| [ffmpeg-mov-append-2026-10-15.md](ffmpeg-mov-append-2026-10-15.md) | Incremental MOV PSSH serialization; 54 native checks and 365 host tests; verified image build; parsing-boundary complexity remains partial; subsequent hardware acceptance PASS after recovery recorded above |
| [security-residual-deployment-validation-2026-10-15.md](security-residual-deployment-validation-2026-10-15.md) | Residual-security image: 376 installed files, ten system-libavutil tests, three Wi-Fi reboots and user-confirmed video/Hailo; hardware acceptance PASS |
| [security-residual-followup-2026-10-15.md](security-residual-followup-2026-10-15.md) | All 15 residual findings revisited; two tested FFmpeg cleanup fixes, exact Hailo image and unchanged raw-scan checks; 11 open, three partial and one unassessed; subsequent hardware acceptance recorded above |
| [busybox-cp-followup-2026-10-15.md](busybox-cp-followup-2026-10-15.md) | BusyBox cp CVE-2007-4998: existing safe-copy configuration verified; native negative control and 37 cases on both installed entry points; configuration-specific not affected, no rebuild required |
| [codel-mount-deployment-validation-2026-10-15.md](codel-mount-deployment-validation-2026-10-15.md) | CoDel/libmount image: 376 installed files and 27 modules matched; three Wi-Fi reboots, normal mounts and user-confirmed camera/Hailo |
| [codel-mount-remediation-2026-10-14.md](codel-mount-remediation-2026-10-14.md) | Three CoDel/libmount source fixes; bounded regressions, exact WIC and same-DB scan checks; generated-data differences verified; subsequent hardware acceptance recorded above |
| [image-security-refresh-2026-10-14.md](image-security-refresh-2026-10-14.md) | Accepted 460-package image rescanned with October 14 data; new dependency coverage, seven candidate assessments and three additional source-open findings |
| [kernel-policy-deployment-validation-2026-10-14.md](kernel-policy-deployment-validation-2026-10-14.md) | Policy image: installed files/modules matched, real timestamp drop and echo control, effective sysctls, three Wi-Fi reboots and user-confirmed camera/Hailo |
| [kernel-policy-2026-10-14.md](kernel-policy-2026-10-14.md) | ICMP timestamp, IPv6 link-multicast and discarded-core policies; nftables module ownership/serialization fixes; build and deployment status recorded separately |
| [kernel-boundary-followup-deployment-validation-2026-10-14.md](kernel-boundary-followup-deployment-validation-2026-10-14.md) | New kernel image: 249 installed files, all 25 modules and four boot files matched; three Wi-Fi reboots and user-confirmed video/Hailo inference |
| [kernel-boundary-followup-2026-10-14.md](kernel-boundary-followup-2026-10-14.md) | BPF arena lifetime and NVMe FDP response bounds corrected; exact Hailo image verified; build-stage record, subsequent hardware acceptance recorded above |
| [kernel-deep-followup-deployment-validation-2026-10-14.md](kernel-deep-followup-deployment-validation-2026-10-14.md) | New kernel image: 249 installed files, all 25 modules and four boot files matched; three Wi-Fi reboots and user-confirmed video/Hailo inference |
| [kernel-deep-followup-2026-10-14.md](kernel-deep-followup-2026-10-14.md) | Four additional kernel corrections, nine residual records reviewed, full module/export and actual-image checks; build-stage record, subsequent hardware acceptance recorded above |
| [kernel-followup-deployment-validation-2026-10-14.md](kernel-followup-deployment-validation-2026-10-14.md) | New kernel image: 249 installed files, all 25 modules and four boot files matched; three Wi-Fi reboots and user-confirmed video/Hailo inference |
| [kernel-followup-2026-10-14.md](kernel-followup-2026-10-14.md) | Twenty kernel patches covering 22 advisories, all 38 remaining records reviewed, exact-image and module/export checks; build-stage record, subsequent hardware acceptance recorded above |
| [kernel-residual-deployment-validation-2026-10-14.md](kernel-residual-deployment-validation-2026-10-14.md) | New kernel image: 75 installed files, all 25 modules and four boot files matched; three Wi-Fi reboots and user-confirmed video/Hailo inference |
| [kernel-residual-2026-10-13.md](kernel-residual-2026-10-13.md) | Fourteen kernel patches covering 17 advisories, 63 reassessed records, exact-image/board gates and shipped-module CRC verification; build-stage record, subsequent hardware acceptance recorded above |
| [kernel-deployment-validation-2026-10-13.md](kernel-deployment-validation-2026-10-13.md) | New kernel image: 75 installed files, all 25 modules and three boot files matched; three Wi-Fi reboots and user-confirmed video/Hailo inference |
| [kernel-followup-2026-10-13.md](kernel-followup-2026-10-13.md) | Thirteen reviewed kernel backports, 201 reassessed records, image-specific module exclusions, verified Hailo image and separate hardware acceptance status |
| `library-closure-deployment-validation-2026-10-13.md` | Follow-up library image: 57 installed files and two boot files matched, three Wi-Fi reboots, access controls, clock/Codex checks and user-confirmed video/Hailo inference |
| `library-closure-2026-10-12.md` | Follow-up of 16 library findings: four tested corrections, two precise glibc exclusions, libevent framing hardening, residual conditions and separate build/deployment status |
| `setup-session-deployment-validation-2026-10-12.md` | Setup-recovery image installed-file checks, error-free initial setup, three Wi-Fi reboots and user-confirmed video/Hailo inference |
| `setup-session-recovery-2026-10-12.md` | Initial setup session recovery, localized safe errors, forward-clock characterization, layer integration and separate deployment status |
| `library-deployment-validation-2026-10-12.md` | Library-remediation image installed-file checks, three Wi-Fi reboots, browser confirmation status, and open first-boot session/clock follow-up |
| `library-residual-remediation-2026-10-12.md` | 24 additional library source corrections, two configuration exclusions, further Avahi/libevent mitigations, verified Hailo image and explicit remaining/deployment boundaries |
| `security-deployment-validation-2026-10-12.md` | Security follow-up image installed-file verification, system FFmpeg regressions, three Wi-Fi reboots and user-confirmed video/Hailo inference |
| `security-followup-2026-10-12.md` | Integrated follow-up of the 539 remaining image associations, reviewed layer changes, build/image evidence and explicit unresolved findings |
| `ffmpeg-followup-2026-10-12.md` | Four additional FFmpeg backports, bounded regressions and the remaining MOV candidate |
| `kernel-followup-2026-10-12.md` | Twelve kernel backports and all 403 candidate records with source/configuration exclusions and unresolved evidence gaps |
| `libraries-followup-2026-10-12.md` | Expat/libevent updates, glibc/libxml2/util-linux fixes, partial Avahi mitigation and all 99 other-library associations |
| `platform-deployment-validation-2026-10-12.md` | Installed kernel 6.18.55, matching platform libraries/modules, system FFmpeg checks, three Wi-Fi reboots and user-confirmed video/Hailo inference |
| `platform-security-remediation-2026-10-12.md` | curl, Raspberry Pi kernel and FFmpeg layer updates, source/configuration assessment, regression evidence and remaining security work; deployment recorded above |
| `openssh-deployment-validation-2026-10-12.md` | Installed OpenSSH 10.6p1, production SSH/SFTP checks, three Wi-Fi reboots and user-confirmed video/Hailo inference |
| `openssh-remediation-2026-10-11.md` | OpenSSH 10.6p1 layer update, 25-candidate assessment, Pi isolated tests and final-image scan; later deployment validation is recorded above |
| `rtsp-deployment-validation-2026-10-11.md` | Installed corrected image identity, 170 RTSP tests with the system library, operating-service session isolation and encrypted 1080p media verification |
| `rtsp-session-isolation-remediation-2026-10-11.md` | Paired application/GStreamer session-isolation fix, red/green Pi regression and separate image/deployment status |
| `rtsp-device-regression-2026-10-11.md` | Historical installed-image RTSPS checks and session-disruption FAIL; remediation and corrected-image validation are recorded separately above |
| `yocto-image-completion-2026-10-11.md` | Final image SPDX/CVE evidence, reproducible local inputs, installed Wi-Fi reboot acceptance and first-boot clock/TLS remediation with separate hardware validation status |
| `camera-runtime-remediation-2026-10-11.md` | Missing Pi 5 camera modules, DMA heap permissions, image fix and device validation boundary |
| `dhcp-setup-2026-10-11.md` | DHCP-safe HTTPS setup, optional management IP restrictions, preserving migration and verification |
| `automatic-provisioning-2026-10-11.md` | Host signing identity, automatic SSD provisioning and first-boot app setup |
| `security-layer-remediation-2026-10-10.md` | Yocto layer security updates, source evidence, validation, and remaining device checks |
| [dependency-inventory.md](dependency-inventory.md) | Historical 2026-09-10 Debian device inventory, including that date's web/toolchain snapshot; not the Yocto package list |
| `sbom/firmware.cdx.json` | Historical Debian-device CycloneDX 1.5 SBOM; use image SPDX for Yocto |
| `sbom/web.cdx.json` | Web lockfile CycloneDX 1.5 SBOM, regenerated 2026-10-10; not an OS/image inventory |
| `vulnerability-scan-<date>.md` | The known-vulnerability scan record for that date: sources, findings with CVE/GHSA ids, status, and the remediation taken |
| `scan-<date>/` | Raw scan outputs the record was written from |
| `static-analysis-<date>.md` | TTA 10.1 record: clang-tidy/clang-format configuration, baseline counts, fixes |

The 2026-09-10 firmware inventory and Debian scan are historical device
evidence. They do not describe the current Yocto image. See the
[current image evidence](#current-yocto-image-evidence) above for the accepted
build and the [2026-10-10 layer remediation record](security-layer-remediation-2026-10-10.md)
for the original layer updates and corrected RTSP exposure assessment.
The web SBOM was regenerated from the updated lockfile on 2026-10-10; the
firmware SBOM still describes the earlier Debian device. Preserve these dated
records; add a new dated assessment when inputs or findings change instead of
relabeling old data as a current scan.

## Regenerating the SBOMs

For Yocto, use the collected image SPDX and rootfs manifest above. The command
below is for a corresponding **Debian device**; it uses `ldd` and `dpkg` and
cannot inventory Yocto RPM packages. Choose a new dated output directory to
preserve historical SBOMs:

```bash
python3 tools/security/generate_sbom.py \
  --firmware-binary build-current/livetest/apps/camera-firmware/camera-firmware \
  --out-dir "docs/security/scan-<date>/sbom"
```

Run the firmware command on the corresponding Debian device, never on a build
PC as a substitute for the target. Run it from the firmware repository root;
replace `<date>` and the binary path with the actual assessment date/input.

Offline. Uses `ldd` + `dpkg` for the runtime libraries, `cmake/Dependencies.cmake`
and `vendor/` for the vendored sources, and `web/package-lock.json` for the web.

## Running the vulnerability scan

For Yocto findings, correlate the actual image manifest/SPDX, recipe source
revisions and applied patches with upstream advisories. Keep the scan date,
database snapshot and reachable product path in the assessment. A Debian
version verdict or a successful hardware test does not establish Yocto CVE
closure. The procedures below have separate scopes:

1. **Debian packages only** — download the public tracker dump and match it offline:
   ```bash
   curl -fsSL -o /tmp/debian-security-tracker.json https://security-tracker.debian.org/tracker/data/json
   date -u +%FT%TZ > docs/security/scan-<date>/debian-tracker-snapshot-time.txt
   ldd build-current/livetest/apps/camera-firmware/camera-firmware | awk '/=>/{print $3}' \
     | xargs -r realpath | sort -u | xargs -r dpkg -S | cut -d: -f1 | sort -u > /tmp/pkgs.txt
   python3 tools/security/scan_debian.py --tracker /tmp/debian-security-tracker.json \
     --packages /tmp/pkgs.txt --release trixie \
     --markdown docs/security/scan-<date>/debian-tracker-open-cves.md \
     --json docs/security/scan-<date>/debian-tracker-findings.json
   ```
   `VULNERABLE` = the installed version is older than Debian's fix (apply the update);
   `OPEN` = Debian has no fix yet (assess exposure); `NOT-IN-TRACKER` = a Raspberry Pi /
   vendor package that Debian does not track (check upstream).
2. **Web packages** — `cd web && npm audit --json` (queries the npm advisory database).
   Fix with `npm audit fix`, or upgrade the direct dependency when the advisory spans a
   whole major line; re-run the web test suite and `npm run build`.
3. **Vendored C++ sources and vendor packages** — query NVD by keyword
   (`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<name>`) and OSV by
   commit (`POST https://api.osv.dev/v1/query {"commit": "<sha>"}`) for Drogon, Trantor,
   stb, libcamera, HailoRT. Record every hit with its affected range and our verdict.
4. Write `vulnerability-scan-<date>.md` from the outputs: one row per finding with
   component, version, id, severity, status (`fixed` / `not affected` + reason /
   `mitigated` / `open`), and the commit that closed it.

Only public package names, versions and commit ids leave the device during a scan.

## Running the source-weakness gate (TTA 10.1)

`tools/ci/check.sh` is the single entry point (format → clang-tidy → C++ build and
tests → web tests and build); `--lint` stops after clang-tidy, `--format` after the
format check. `tools/ci/install-hooks.sh` installs the pre-commit format gate and
points `git blame` past the one-time reformat commit. Configuration lives in
`.clang-format` and `.clang-tidy`; the record of the baseline, the fixes, and the
remaining warnings is `static-analysis-<date>.md`.

## Privacy of published evidence

Use documentation-only addresses (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, or `2001:db8::/32`) for device/client examples, including
URLs, test fixtures and copied logs. Keep actual site addresses, network
configuration, machine identifiers and credentials in Git-ignored local
evidence. `.gitignore` does not redact values pasted into tracked reports.
Inspect report bodies and outgoing history before publication; scanning only
for credential files or tokens is insufficient. See the
[privacy cleanup record](privacy-cleanup-2026-10-16.md).
