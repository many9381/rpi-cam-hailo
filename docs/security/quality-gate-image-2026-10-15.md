# Quality-gate corrections: image build verification — 2026-10-15

Hailo image **`20261015T204138Z-e664cb9647e7`** built successfully and passed
actual-image verification. It includes the source-selection correction and
plain bootstrap-peer validation fix described in
[the source quality-gate record](static-analysis-2026-10-15.md).

**Installation completed on 2026-10-16 at 10:26:33 UTC. New-image hardware
acceptance is PASS.** The installation receipt matches this WIC and the
registered SSD; administrator setup, three reboot/capture cycles and the final
user confirmation of video/Hailo completed. See the
[deployment validation record](quality-gate-deployment-validation-2026-10-16.md).

## Build and image evidence

- Only `rpi5-camera-hailo` was built. All **7,884 BitBake tasks** succeeded;
  7,803 were reused. No QEMU or minimal image build was performed.
- Artifact collection completed with matching source provenance and checksums.
  The existing local pinned firmware transport was used; the application
  revision remains `ba503a1fbc4ed68c1fd29aace7214a5c330d7021` plus the registered
  layer patches.
- The actual compiled source matches **all 257 C++ source/header hashes** from
  the successful quality-gate run. All six files changed by patch `0009`
  match both the prepared recipe source and the packaged development checkout.
- Read-only extraction of the compressed WIC verified **402 file hashes**
  against the generated rootfs, including the corrected firmware executable
  and development source files. The executable also matches the RPM split
  package contents.
- All **460 package names/versions**, **27 kernel modules**, kernel image,
  board DTB, IMX708 overlay and boot configuration match the accepted baseline.
  All **16 privileged ownership/mode records** retain their expected values.
  Camera-driver, downstream libcamera, DMA-access and Wi-Fi rootfs checks pass.
- Among previously fingerprinted files, changes are limited to the firmware
  executable, build ID and two updated development-source files. Four further
  development-source paths are now included in the image verification set.
- The documented pristine-image checks find no Codex auth file at either
  known user location, generated signed app configuration, device TLS private
  key or saved timesync clock. Installation adds device-specific material.
  This is not a statement that the private image contains no sensitive data:
  the configured Wi-Fi credentials remain part of it.

The registered GIGABYTE 120 GB USB SSD passed installer identity, protected-host
disk, image-checksum, signing-identity and credential-restoration preflight.
`scripts/install-ssd.sh` selects this completed image by default. Its disk-writing
stage used the build user's sudo authentication in their terminal. The installer
record confirms successful writing, Codex login restoration and camera
provisioning; the user subsequently booted the Pi from this SSD.

## Scope and evidence location

The earlier **1,356 passing CTest cases**, **10 explicit hardware skips** and
**770 passing web tests** cover the matching working sources. They are not a
claim that the new SSD image has booted. The previous accepted image's camera
and Hailo results remain specific to that previous image.

Package versions are unchanged. No fresh vulnerability-database scan or change
to residual vulnerability classifications is claimed. The agreed exclusion of
additional MOV allocator work remains in effect.

Private verification evidence is retained under
`artifacts/20261015T204138Z-e664cb9647e7/rpi5-camera-hailo/security/quality-gate-image-2026-10-15/`,
including the actual-image hashes, baseline comparison, verification script,
source-quality records and an evidence SHA-256 manifest. Build provenance,
image SPDX and image checksums are under the same profile's `provenance/`,
`manifests/` and `checksums/` directories. Temporary WIC extraction files were
removed after verification. Installation and hardware results must be added
only after those stages complete.
