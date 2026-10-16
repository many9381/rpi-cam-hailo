# Static-warning image deployment validation — 2026-10-16

Image **`20261016T111625Z-e664cb9647e7`**, profile `rpi5-camera-hailo`: **PASS**.
Installed files match the verified image, three Wi-Fi reboot cycles pass, and
the user confirms normal authenticated video, `hailo / ready`, increasing
inference frames and visible object labels/confidence after the final reboot.

This records deployment of the [verified image](static-warning-image-2026-10-16.md)
containing the [selective warning improvements](static-warning-review-2026-10-16.md).
The preceding source tests and image-build checks remain separate evidence.

## Installation and image identity

- The registered USB SSD installation receipt is dated **2026-10-16 12:49:14 UTC**,
  with camera provisioning and Codex login restoration recorded. Its WIC hash
  matches the verified build:
  `49417cfdc898f1cb0ab9aae7a2f78de92d19f45666a0e4c0a5f2d4276f7a9c12`.
- The previous SSH pin rejected the newly installed device's changed key.
  After the user confirmed its Wi-Fi address, a separate strict pin verified
  the expected board, build, kernel and USB root. The public TLS certificate
  was obtained through that pinned SSH connection and its exact hash was used
  for HTTPS verification. Previous pins and acceptance records were preserved.
- **415 readable installed files** match the WIC, including the executable,
  web assets, changed development-source files and Codex package. Execute-only
  sudo and the root-only security-status sudoers rule have no device-side byte
  hash claim; their existing image/metadata/operation evidence is separate.
  All **16 privileged ownership/mode records** match.
- SSH remains restricted to `rpiadmin` public-key authentication. Password,
  keyboard-interactive and root logins are disabled. The development checkout
  retains its pinned upstream commit and `rpiadmin` ownership.

## Startup and repeated reboots

Setup was already complete when first inspected; no new administrator-setup
interaction was requested during validation. Served HTML/JS/CSS match the
installed bytes, and unauthenticated AI requests return HTTP 401. Setup remains
complete after all reboots.

Recovery measures Wi-Fi SSH, healthy application service and pinned HTTPS
availability. Service start is monotonic time after kernel boot, not first-frame
latency. Each cycle includes twenty seconds of process stability and a
five-second actual capture check.

| Cycle | Wi-Fi/web recovery | Service start | CFE / ISP increases over 5 s | Capture errors / service restarts |
|---|---:|---:|---:|---:|
| 1 | 26.763 s | 6.173 s | 1060 / 531 | 0 / 0 |
| 2 | 40.800 s | 6.230 s | 1060 / 530 | 0 / 0 |
| 3 | 32.760 s | 5.657 s | 1059 / 528 | 0 / 0 |

Four distinct boot IDs were observed. The shared capture check passed initially,
after each reboot and at the final check. The final CFE/ISP increases were
1073/537 over five seconds. IMX708 NV12 1920×1080 startup was observed, with
zero selected capture, TLS-identity, sensor-probe, unknown-symbol, module-ABI
or kernel panic/oops/BUG errors. Interrupt counts show capture progress, not
exact FPS or authenticated inference results; the latter were confirmed by
the user in the dashboard.

## Codex and system checks

- Codex CLI **0.163.0** reports an existing ChatGPT login before and after the
  reboot checks. Bundled ripgrep **15.2.0** executes successfully.
- A first `codex app-server daemon version` query failed because no control
  socket existed before daemon startup. The normal `start` command created
  its per-user managed package/control state and succeeded. The subsequent
  query reported CLI, managed package and running server version **0.163.0**.
  The test-started daemon was then stopped successfully before reboot testing.
  This was an initially unstarted daemon, not a missing-package defect; no
  firmware or Codex recipe correction was needed.
- No model request, login/logout operation, auth-file content collection or
  session-cookie transfer was performed. Normal CLI startup created its runtime
  state; application accounts, signed camera configuration and TLS identity
  were not edited by validation.
- Camera, autofocus, CFE/ISP, Hailo, Wi-Fi and fan modules match the running
  `6.18.55-v8-16k` kernel with 16 KiB pages. Hailo identifies as HAILO8 with
  firmware 4.24.0. PWM fan control is active: final state 2 of 4, 5732 RPM.
- Four boot-file hashes match the WIC. NTP is synchronized and the device clock
  falls within the host request window with five seconds tolerance. This is
  a normal post-boot check, not a clock-jump experiment.
- Security-policy activation, effective nftables/IPv6/core settings and normal
  root/boot mounts pass. The unprivileged raw-disk/fstab probe retains its
  documented `/dev/root` and permission limitations; no block-read permissions
  were relaxed.

## Scope and evidence

This pass covers the installed image and observed hardware operation. The
361 selected source regression tests and static analysis were not rerun for
deployment. No QEMU/image build, physical sensor fault injection, endurance
run, new security-advisory assessment or wired/minimal release acceptance is
claimed.

Private evidence is archived under
`artifacts/20261016T111625Z-e664cb9647e7/rpi5-camera-hailo/security/static-warning-deployment-2026-10-16/`,
including installed hashes, reboot/capture measurements, Codex lifecycle
results, separate operator confirmation and a SHA-256 manifest. Raw privileged
journals are reduced to counts on the Pi. Credentials, cookies, private keys,
signed configuration and SSH/TLS pin files are not included in that archive;
pins remain in Git-ignored local state.
