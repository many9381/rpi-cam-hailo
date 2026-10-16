# Camera capture health deployment validation — 2026-10-15

Image **`20261015T185424Z-e664cb9647e7`**, profile `rpi5-camera-hailo`: **PASS**.
Three controlled Wi-Fi reboots passed with actual capture progress and zero
capture errors. After the final reboot, the user confirmed web video,
`hailo / ready`, increasing inference frames, and object labels/confidence values.

This records deployment of [capture liveness and bounded recovery](camera-capture-health-2026-10-15.md).
The build-time verification remains a separate historical record; its
`hardware_acceptance: NOT_RUN` describes the build stage.

## Installed image and independent runtime tests

- The installation receipt, board/build/profile and USB root identity match.
  WIC SHA-256 is
  `b708ce80e2da797bcfa14ec94f45126ffa6256f062492f87d3899e5142a61af3`.
- **396 readable installed files** match the actual WIC, including the changed
  executable, served web bundle and optional development source files.
  **16 privileged ownership/mode records** match. Execute-only sudo and the
  root-only security sudoers rule have image/metadata/behavior evidence; no
  device-side byte hash is claimed for those two unreadable files.
- **70 runtime, capture-liveness and boot tests** passed again as an independent
  AArch64 executable on this new image. They cover first-frame/stall boundaries,
  the three-attempt retry limit, failed attempts, healthy-budget reset, explicit
  stop/settings changes and protected manual recovery. The production service
  retained its boot ID and PID; the temporary test executable was removed.
- Initial actual capture progress passed the common
  `scripts/test-camera-runtime.sh` check. It requires stable identity and process,
  increasing CFE/ISP counters and zero current-process capture errors.

These independent tests inject failures into test dependencies; they do not
disconnect the physical sensor or inject faults into the running production
graph. Normal device operation validates deployment and capture continuity.
Hardware interrupt increments do not establish exact FPS or authenticated AI
results.

## Reboot and final functional acceptance

Recovery time measures Wi-Fi SSH, healthy service and pinned HTTPS availability.
Camera service start is monotonic time after kernel boot, not first-frame latency.
Each cycle includes twenty seconds of stability and a five-second capture check.

| Cycle | Wi-Fi/web recovery | Camera service start | CFE / ISP increments over 5 s | Capture errors / app restarts |
|---|---:|---:|---:|---:|
| 1 | 43.033 s | 6.229 s | 1069 / 529 | 0 / 0 |
| 2 | 42.749 s | 6.181 s | 1070 / 530 | 0 / 0 |
| 3 | 53.935 s | 6.189 s | 1065 / 529 | 0 / 0 |

Four distinct boot IDs were observed. The common capture gate passed initially,
on each reboot and in the final check. The final CFE/ISP increments were
1065/530 over five seconds. Each boot retained its process during observation,
with automatic IMX708 NV12 1920×1080 configuration, completed setup, the same
root UUID and fixed SSH/TLS identities. No selected capture, TLS-identity,
kernel panic/oops/BUG, module ABI or sensor-probe error was observed.

The final user response confirms video, Hailo readiness, increasing inference
frames and object labels/confidence. This authenticated functional confirmation
is recorded separately from the hardware-counter measurements.

## Final system checks

- Kernel **6.18.55-v8-16k**, 16 KiB page size, **27 installed module hashes**,
  required loaded-module version magic and **four boot-file hashes** match.
  Wi-Fi provides the default route; disconnected Ethernet does not hold up boot.
- HAILO8 firmware **4.24.0**, Codex **0.162.1** with restored ChatGPT login and
  bundled ripgrep **15.2.0** pass. Only login status was checked; no authentication
  file was read and no Codex model request was sent.
- NTP is synchronized and device time is within the host request window plus
  five seconds. The optional development checkout has the expected base commit,
  installed changes and `rpiadmin` ownership.
- Final hardware observation: **59.5 °C**, fan state **2/4**, **5,431 RPM**.
  Initial observation was state **1/4**, **3,337 RPM**. These are normal operating
  observations, not a thermal stress test.
- HTTPS pages and assets return 200; unauthenticated AI access returns 401.
  Key-only SSH and root-login restrictions, installed firewall/sysctl policy and
  policy-before-networkd ordering pass. SSH policy verification initially used a
  case-sensitive filter against capitalized OpenSSH fields; normalizing field
  names fixed the verifier, without changing device policy.
- Root and boot mounts remain active/read-write. Unprivileged `findmnt --verify`
  cannot resolve the stock `/dev/root` alias or inspect raw block devices; this
  limitation is retained rather than presented as an on-disk filesystem pass.

The production service, accounts and settings were not replaced during testing.
No deliberate physical fault, long-duration endurance or authenticated RTSPS
media test was performed in this deployment check. The bounded recovery behavior
is supported by the independent injected-failure tests, not by a physical cable
disconnect experiment.

## Evidence and scope

Working evidence: `.state/camera-health-deployment-2026-10-15/`.
Curated evidence archive with verified SHA-256 checksums:
`artifacts/20261015T185424Z-e664cb9647e7/rpi5-camera-hailo/security/camera-capture-health-deployment-2026-10-15/`.

Privileged logs are reduced to operational counts on the Pi before transfer.
Credentials, cookies, private keys, signed application configuration and raw
system journals are not collected. The SSH/TLS pins and device identifiers stay
in ignored local state. No QEMU build/test or image rebuild is part of this
deployment check. Vulnerability findings are not reclassified by these tests.
