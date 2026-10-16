# Quality-gate image deployment validation — 2026-10-16

Image **`20261015T204138Z-e664cb9647e7`**, profile `rpi5-camera-hailo`: **PASS**.
The user completed the new image's administrator setup and confirmed normal
video before the three reboot cycles. After the final cycle, the user confirmed
normal video, `hailo / ready`, increasing inference frames, and visible object
labels/confidence values in the authenticated web dashboard. These observations
are recorded separately from the automated SSH checks.

This is the deployment follow-up to
[image build verification](quality-gate-image-2026-10-15.md) and
[source quality verification](static-analysis-2026-10-15.md).

## Installation and identity

- The installation receipt records successful writing to the registered USB
  SSD on October 16 at 10:26:33 UTC, with Codex login restoration and camera
  provisioning. Its WIC SHA-256 matches the verified image:
  `797551e2ca38f5ecdf778a29c9b7a4fb5df79d926f2db3ed033c01c9c821ed2e`.
- After the user confirmed the newly installed Pi's Wi-Fi address, a separate
  SSH pin was created. Strict SSH verified the expected build, registered
  board, kernel and USB root. The public TLS certificate was obtained over
  that pinned channel; HTTPS checks then verified its exact certificate hash.
  Previous device pins and acceptance records were preserved.
- **400 readable installed files** match the actual WIC, including the corrected
  executable, served web assets and changed development sources. Two additional
  files do not have device-side byte-hash claims: execute-only sudo and the
  root-only security-status sudoers rule. Their image/metadata/operation checks
  remain separate. All **16 privileged ownership/mode records** match.
- The effective SSH policy allows only the `rpiadmin` public-key login, with
  password, keyboard-interactive and root login disabled. Root and boot mounts
  are active and writable. The ordinary fstab query passes; raw on-disk probing
  by the unprivileged account retains the documented `/dev/root` and block-read
  limitations without relaxing device permissions.

## Startup, capture and reboots

The uninitialized device exposed the setup surface and denied the AI route
with HTTP 403, matching `SecurityRequestGate`'s default-state policy. The first
private verification attempt expected the operational 401 too early; the
validation now distinguishes those states. Product code and access policies
were not changed. After administrator setup, unauthenticated AI requests return
401 and web resources return the expected bytes. Setup remains complete after
every reboot.

Recovery measures Wi-Fi SSH, healthy service and pinned HTTPS availability.
Service start is measured from kernel boot, not camera first-frame latency.
Each cycle includes twenty seconds of stability and a five-second capture check.

| Cycle | Wi-Fi/web recovery | Service start | CFE / ISP increases over 5 s | Capture errors / service restarts |
|---|---:|---:|---:|---:|
| 1 | 41.962 s | 6.233 s | 1076 / 529 | 0 / 0 |
| 2 | 43.027 s | 6.213 s | 1076 / 528 | 0 / 0 |
| 3 | 42.960 s | 6.213 s | 1068 / 530 | 0 / 0 |

Four distinct boot IDs were observed. The shared capture gate passed initially,
after each reboot and in the final check. The final CFE/ISP increases were
1069/530 over five seconds. Each observation retained a stable process, with
automatic IMX708 NV12 1920×1080 startup and zero selected capture, TLS-identity,
sensor-probe, module-ABI, unknown-symbol or kernel panic/oops/BUG errors.
Interrupt counts establish capture progress, not exact FPS or inference results.

## Other checks and scope

- Camera, autofocus, CFE/ISP, Hailo, Wi-Fi and PWM fan modules match the running
  16 KiB-page kernel. Hailo identifies as HAILO8 with firmware 4.24.0.
- Fan cooling control is active; the final state was 1 of 4, with 3309 RPM.
  The earlier cool idle state was 0; this is not a forced-full-speed condition.
- Codex CLI 0.162.1 reports an existing ChatGPT login and bundled ripgrep 15.2.0
  runs. No authentication-file content or model request was collected.
- Four boot-file hashes match the WIC. NTP is synchronized and the device clock
  is within the host request window with five seconds tolerance. This is a
  post-boot clock check, not a repeated clock-jump experiment.
- Security-policy activation, effective nftables/IPv6/core settings, normal
  root/boot mounts and development-checkout revision/ownership pass.

This pass verifies the installed image and real hardware. The earlier complete
source-quality suite is linked above and was not rerun as part of deployment.
No QEMU/image build, physical camera fault injection, long endurance run,
security-advisory reclassification or wired/minimal release acceptance is
claimed. Operating credentials, app configuration and TLS identities were not
modified by these checks.

Evidence is stored under
`artifacts/20261015T204138Z-e664cb9647e7/rpi5-camera-hailo/security/quality-gate-deployment-2026-10-16/`.
Operational logs are reduced to counts on the Pi; raw privileged journals,
credentials, cookies, private keys and signed application configuration are
not transferred. SSH/TLS pins remain in ignored local state.
