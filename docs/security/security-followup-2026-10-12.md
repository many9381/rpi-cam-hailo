# Remaining image security follow-up — 2026-10-12

This record covers the user-approved FFmpeg and kernel/other-library follow-up
of deployed image `20261012T031641Z-e664cb9647e7`. Long-duration operation
testing is excluded at the user's request. The new Hailo image build is
`20261012T080118Z-e664cb9647e7`; **build and image validation passed**.
Subsequent installation and Wi-Fi hardware acceptance passed; see the separate
[deployment record](security-deployment-validation-2026-10-12.md).

The baseline scanner reported 539 unresolved package/CVE associations, not
539 confirmed exploitable vulnerabilities. Original scan outputs are retained.
Source/configuration assessments and the new image's raw scan are recorded
separately. No blanket recipe-level CVE suppression is introduced.

## Applied source changes

The build freezes 37 changed layer inputs. Their exact SHA256 values match
the new build's `provenance/inputs.json`.

| Area | Change | Detailed record |
| --- | --- | --- |
| FFmpeg 7.1.5 | Four focused fixes for RTSP redirects, RASC bounds, floodfill dimensions and hqdn3d dimensions/ownership | [FFmpeg follow-up](ffmpeg-followup-2026-10-12.md) |
| Raspberry Pi Linux 6.18.55 | Twelve same-pin backports; retain the validated downstream camera, Wi-Fi, fan and Hailo configuration | [Kernel follow-up](kernel-followup-2026-10-12.md) |
| Installed libraries | Expat 2.8.5 plus two fixes, libevent 2.1.13, glibc resolver fix, eight libxml2 fixes, util-linux failed-mount cleanup, partial Avahi resource mitigation | [Library follow-up](libraries-followup-2026-10-12.md) |

Primary fixing commits, prerequisites, retained source hashes, exact patch
inputs and bounded before/after regressions are recorded in those documents
and their machine-readable ledgers. Independent code/assessment review
resolved the SUNRPC adaptation issue and corrected three optional-kernel-path
classifications. Unsupported source equivalence remains explicitly inconclusive.

## Integrated validation

The final continuation completed at 2026-10-12 11:02 UTC: all 7,786 tasks
succeeded, with 7,757 results reused. Artifact collection and provenance
verification passed. Only the Hailo image profile was built.

| Verification | Result and scope |
| --- | --- |
| Host suite | 365/365 passed in 376.326 seconds; no QEMU guest/image execution |
| Actual BitBake sources | All 29 new patches verified; overlapping library series reversed/reapplied on private copies with exact hash equality; 16 FFmpeg configuration checks and unchanged kernel configuration |
| Installed shared libraries | 182 SONAME/export comparisons passed, with no removed exported symbols; 12 changed libraries also matched their actual WIC files. This is not a complete ABI proof. |
| Isolated FFmpeg on Pi | H.264/MP4 and JPEG encode/decode passed; floodfill and hqdn3d each processed four alternating 32×24/64×48 frames, with dimensions checked before and after the filter |
| Camera rebuild | Exact binary differences explained; both installed IPA signatures verified, and altered-signature controls rejected; new PiSP IPA loaded and validated on Pi before IMX708 Wide enumeration |
| Actual WIC | Kernel plus seven camera/fan/Wi-Fi/Hailo modules, modified libraries, app, OpenSSH, retained RTSP fixes, camera detection, services, development checkout and credential exclusion passed |
| SPDX scan | Actual final image scanned with pinned sbom-cve-check 1.3.5 and the 2026-10-11 database snapshots; adapter/input verification passed; primary-source assessment date is 2026-10-12 |

The original byte-identity check correctly detected regenerated camera
artifacts. Exact full-file comparison established that libcamera changed only
its generated timestamp, IPA public key and associated build/debug identifiers.
Libpisp changed its version string and five corresponding string-constructor
instructions; librpicam_app changed its timestamp and build/debug identifiers.
All other bytes matched the baseline binaries fetched from the pinned Pi.
Independent review confirmed the narrow comparison and current-build binding.
No camera source change was needed.

The first enumeration command hid diagnostic logs, so its signature-log
assertion failed and that result was retained. A minimal CameraManager probe
then verified the private new IPA path and signature without requesting capture
or camera acquisition/configuration. Its initialization logged a busy sensor
control because production capture remained running, plus existing static
sensor-property warnings. Enumeration is not new-image capture acceptance.
Both isolated test directories were removed; boot ID, production app PID and
restart count stayed unchanged, and pinned HTTPS/setup checks passed.

The earlier component build was stopped deliberately at a task boundary after
3,193 attempted tasks succeeded, to include the final reviewed inputs in a
single image build. Its exit status was 1 because of that stop; it is not
recorded as a completed full-image build. Original logs are preserved.

The first final-image attempt hit host out-of-memory termination while compiling
LLVM-native and Node.js-native. The host kernel recorded the compiler kills;
this was not a patch compilation diagnostic. Completed package results are
retained. Continuation uses four BitBake tasks and four compiler workers per
task through a private post-read configuration, with the same frozen source
inputs and build ID. LLVM, FFmpeg and camera-firmware compilation then passed.
After the other large toolchain builds finished, the remaining Node.js task was
deliberately stopped and resumed with eight workers for that recipe only;
global limits remain four. Completed objects were retained and interrupted
outputs are rebuilt by make. That intermediate exit is recorded as intentional
cancellation, separately from the original OOM failures. The final continuation
and collector both exited successfully. These limits were private build
overrides, not a change to the frozen layer inputs.

## Final assessment

The immutable raw scan moved from **539 to 483** affected associations:
kernel 403→391, FFmpeg 37→33 and other recipes 99→59. There are no new affected
associations outside the baseline set. This comparison uses the same database
snapshots; it does not claim a fresh 2026-10-12 database download.

All 539 baseline associations are reconciled individually in
`integrated-assessment.json` and `.csv`:

| Source/configuration disposition | Associations |
| --- | ---: |
| Fixed in the built image, including existing fixes | 87 |
| Specifically excluded by architecture, configuration, source or installed component | 208 |
| Open | 149 |
| Partial mitigation, still open | 2 |
| Applicability or source equivalence remains inconclusive | 93 |
| **Total** | **539** |

Of the 87 fixed associations, 50 are covered by this follow-up's changes:
four FFmpeg, twelve kernel and 34 other-library associations. Raw version-based
results and source assessments intentionally differ. For example, Expat has no
remaining raw match after its update, but its upstream-unfixed DoS remains
open in the assessment. A separate BusyBox `cp` follow-up is also retained
outside the corrected kernel association. None of these counts is a count of
confirmed exploitable vulnerabilities or a whole-image security PASS.

## Remaining findings and deployment boundary

The enabled FFmpeg MOV candidate CVE-2026-107678 and V3D lifetime candidate
CVE-2026-93047 remain open. Their upstream changes require further compatibility
and ownership review. Avahi's 50-client cap is only a partial mitigation;
held slots and resource-exhaustion CPU behavior remain unresolved. Libevent's
URI-NUL issue also remains partial. Other open and inconclusive source findings
are retained individually, including a separate BusyBox `cp` behavior follow-up
after correcting a userspace advisory's kernel association.

At build-validation time the Pi used `20261012T031641Z-e664cb9647e7`. Isolated media testing
does not replace installation and boot/camera/Hailo verification of the complete
new image. No production package replacement, SSD installation, reboot,
QEMU/minimal image build or long-duration operation test is part of this work.

The subsequent user-installed `20261012T080118Z-e664cb9647e7` passed three Wi-Fi
reboots, installed-file/system-media checks and user-confirmed video/Hailo
inference. That [deployment validation](security-deployment-validation-2026-10-12.md)
is separate evidence; the original build-validation archive remains unchanged.

Private working evidence is under `.state/security-followup-2026-10-12/`.
A curated, checksummed copy is stored with the new
image under `security/security-followup-2026-10-12/`. The actual scan and WIC
verification are in the parent `security/` directory. Credentials, vendor
archives, private keys, copied executables and complete source trees are
excluded from that evidence archive.
