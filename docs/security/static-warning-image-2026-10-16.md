# Static-warning improvements: image verification — 2026-10-16

Hailo image **`20261016T111625Z-e664cb9647e7`** built successfully and passed
actual-image verification. It includes patch
`0010-avoid-intermediate-metadata-and-error-copies.patch` from the
[selective warning review](static-warning-review-2026-10-16.md), in both the
firmware build and optional development checkout.

**SSD installation and hardware acceptance completed on 2026-10-16: PASS.**
The installation receipt matches this image; 415 readable installed files,
three reboot/capture cycles, Codex daemon startup and operator-confirmed
video/Hailo passed. See the
[deployment validation](static-warning-deployment-validation-2026-10-16.md).
The build-stage records below retain their original scope.

## Build and image evidence

- Only `rpi5-camera-hailo` was built. All **7,884 BitBake tasks** succeeded;
  **7,800** were reused. No QEMU or minimal image was built.
- Artifact collection, source provenance and image checksums passed. The
  application pin remains `ba503a1fbc4ed68c1fd29aace7214a5c330d7021`, with the
  registered layer patches and existing local Git transport.
- All **257 C++ source/header hashes** match the warning-review source record.
  The eight changed production/test files match both prepared recipe source
  and the packaged development checkout. The actual executable matches the
  RPM split package and generated rootfs.
- Read-only extraction verified **417 files inside the compressed WIC** against
  the generated rootfs. Temporary boot/root filesystem extraction was removed.
- The image retains **460 package names**. The only package-version change is
  Codex CLI `0.162.1` → `0.163.0`, selected by the existing latest-stable policy.
- All **27 kernel modules**, the kernel image, board DTB, IMX708 overlay and
  boot configuration match the accepted baseline. All **16 recorded privileged
  ownership/mode entries** are preserved. Camera and Wi-Fi rootfs checks pass.
- Previously fingerprinted differences are limited to the firmware executable,
  build ID, three development-source files and Codex executable. Other changed
  source paths and Codex package files were added to this verification set;
  their absence from the earlier comparison set is not evidence of unchanged
  content.
- Pristine-image checks confirm absence of Codex auth files at the known user
  locations, generated signed application configuration, device TLS private
  key and saved timesync clock. The private image still contains the configured
  Wi-Fi credentials; the image and build artifacts remain Git-ignored.

WIC SHA-256:
`49417cfdc898f1cb0ab9aae7a2f78de92d19f45666a0e4c0a5f2d4276f7a9c12`.

## Codex package verification

The existing resolver selected official stable release `0.163.0`; no version
selection policy or recipe behavior was changed for this build. BitBake fetch,
license and package QA completed successfully.

The CLI, code-mode helper, package descriptor, bundled ripgrep and bubblewrap
match the downloaded release archive and packaged output. The image contains
the expected **11 regular package/license files** and **two executable links**,
with root ownership and expected modes. Its descriptor identifies the AArch64
package, entrypoint and required resource directories. Codex-related host tests
passed **33 cases**.

These build-stage checks establish package completeness and byte identity.
The subsequent deployment validation also verified version, restored login
and normal daemon start/version/stop on the Pi. Auth restoration uses the
existing installer and private local inputs.

## Installation and validation boundary

`scripts/install-ssd.sh` now selects this completed image by default; its
read-only image selector was checked at build completion. No SSD was mounted
or written during that build task. The user subsequently installed it with
the existing installer; its receipt and live-device identity now match, and
camera/Hailo, Codex and reboot acceptance are recorded separately above.

The preceding source review passed 361 selected target tests, 25 firmware
packaging tests and all 79 static-analysis units with 0 errors / 198 warnings.
Those results cover the matched sources; they are not new-image hardware
acceptance. This build did not rerun the complete CTest/web suites or perform a
fresh vulnerability-database scan. Residual security classifications and the
agreed exclusion of additional MOV allocator work remain unchanged.

## Evidence

Private evidence is under
`artifacts/20261016T111625Z-e664cb9647e7/rpi5-camera-hailo/security/static-warning-image-2026-10-16/`.
It includes actual-WIC hashes, baseline differences, package-version changes,
Codex package hashes, matched source evidence, the verification script and an
evidence SHA-256 manifest. The profile's `provenance/`, `manifests/` and
`checksums/` retain build inputs, actual SPDX/package inventory and image
checksums. Raw build logs and verification preparation are in Git-ignored
`.state/static-warning-image-2026-10-16/`.
