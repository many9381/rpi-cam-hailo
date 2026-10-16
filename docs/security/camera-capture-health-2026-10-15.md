# Capture liveness and bounded recovery — 2026-10-15

The accepted previous image could leave the service and Hailo runtime apparently
running while the camera delivered no frames. The physical recovery is recorded
in [the capture incident](camera-capture-failure-2026-10-15.md). This change closes
the software detection and acceptance gap; it does not establish that every
capture timeout is caused by a cable.

## Applied behavior

- `CameraPipeline` uses steady-clock arrival time for usable frames. Before the
  first frame it reports `starting`; ten seconds without a first frame reports
  `E_CAMERA_NO_FRAMES`. Five seconds without another frame reports
  `E_CAMERA_CAPTURE_STALLED`. Stale snapshot availability and rates are cleared.
- The main lifecycle loop supervises capture outside libcamera callbacks. Recovery
  takes the existing protection gate and managed command mutex, serializing with
  explicit start/stop and settings replacement. No credentials, management IP
  policy, integrity checks or TLS settings change.
- Capture failure stops the graph, including AI/streams, while management HTTP
  remains available. At most three automatic restart attempts run, five seconds
  apart. Failed starts consume the budget too. Sixty continuous healthy seconds
  rearm the budget; explicit start/settings replacement start a fresh budget.
  Explicit stop/protection shutdown cancels pending retries.
- Exhaustion preserves the capture error and permits the existing protected manual
  restart. The boot coordinator recognizes a self-stopped runtime instead of
  incorrectly returning success without starting it. Status reads before the next
  supervisor tick report recovery pending, not premature exhaustion.
- The camera HTTP status exposes `capture_error`, `recovery_attempts` and
  `recovery_limit`. The web status panel displays localized capture/recovery
  guidance, without presenting this as an authentication error.

## Layer and verification

`0008-camera-capture-health-and-bounded-recovery.patch` is included by the
firmware, web and optional development checkout recipes. Patch applicability was
checked against all three prepared source trees. The original upstream commit
remains pinned; the reviewed changes remain visible in the installed development
checkout.

`scripts/test-camera-runtime.sh` is the shared, read-only development acceptance
command. It requires pinned SSH, expected build/profile/board, stable boot/PID/USB
root, increasing CFE and ISP counters, and zero capture errors. Privileged logs
are filtered to a count on the target. Hardware counters do not prove exact FPS,
browser video or Hailo detections; those still require functional acceptance.

Checks recorded under `.state/camera-health-2026-10-15/`:

- Runtime/liveness/boot tests run as an independent AArch64 binary on the existing
  Pi, without replacing its service: 70 passed.
- Web regression suite: 770 passed; final affected UI/API rerun: 100 passed.
  TypeScript/Vite production build passed.
- HTTP capture serialization and runtime protection/restart tests: 15 passed.
- Common probe tests: 7 passed (including on-target log reduction and failed
  rerun invalidating earlier PASS evidence); firmware packaging tests: 25 passed.
- The common probe passed on the previous accepted image, with positive CFE/ISP
  deltas and zero current-process capture errors. This verifies the probe, not
  deployment of the new supervisor.
- Independent review found and resolved premature recovery-exhaustion reporting;
  final review reported no remaining important findings.

Image `20261015T185424Z-e664cb9647e7`, profile `rpi5-camera-hailo`, built successfully
(7,884 tasks; 7,800 reused). Actual compressed WIC verification passed for 398
files, including the executable, web bundle and all 21 changed source/test files
in the optional development checkout. The executable was also matched to its
packaged output and compiled source. All 460 package names/versions match the
previous image; the expected executable/web/development-source changes are the
only differences in the protected comparison set. Kernel, camera boot configuration,
DTB/overlay and protected shared libraries remain unchanged. Sensitive runtime
configuration/authentication files remain absent from the image, and checked
privileged file ownership/modes are preserved.

Build/verification evidence is archived under
`artifacts/20261015T185424Z-e664cb9647e7/rpi5-camera-hailo/security/camera-capture-health-2026-10-15/`.

The new image is now installed on the operating Pi. Installed-file verification
and all 70 independent runtime tests passed on this image; the production service
remained active and the temporary test executable was removed. Three controlled
Wi-Fi reboots passed with increasing actual capture counters and zero capture
errors; the user confirmed final video and Hailo inference/detections. Hardware
acceptance is PASS, with measurements and scope recorded in the separate
[deployment record](camera-capture-health-deployment-validation-2026-10-15.md).
Do not infer hardware acceptance from the build-stage checks. No QEMU build or
test was run.
