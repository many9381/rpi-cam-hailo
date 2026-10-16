# Kernel follow-up image deployment validation — 2026-10-13

Image: `20261013T124642Z-e664cb9647e7` / `rpi5-camera-hailo`.

## Outcome and scope

Installed-image verification, three controlled Wi-Fi reboots and final hardware/service checks: **PASS**. After the third reboot, the user separately confirmed normal web video, `hailo / ready`, increasing inference frames, and object labels with confidence values.

This accepts deployment of the [kernel follow-up image](kernel-followup-2026-10-13.md), containing thirteen additional reviewed kernel corrections. The user installed and booted the image before this run. Verification did not rebuild or write an image, replace packages, change accounts/application settings, or adjust the clock. It records integrated Wi-Fi operation, not the separate wired/minimal-image release gate.

## Installed image and kernel

- The SSD installation record matches the completed image's compressed SHA-256. Running build/profile and registered board identity match; the root filesystem is on its USB SSD. The root UUID remained fixed across all three reboots.
- After the user confirmed the reinstalled Pi's address, its new SSH host key was pinned in a separate evidence directory. The public TLS certificate was obtained from the loopback HTTPS service through that pinned SSH connection. Both pins remained fixed throughout verification; old evidence was preserved.
- **75 installed root-filesystem files** match the actual WIC evidence, including all **25 installed kernel modules**, camera/web/Codex executables, protected shared libraries and development source files.
- The complete module directory contains exactly the expected `6.18.55-v8-16k` release and 25 modules. Every module hash and version magic matches the image. `modules.builtin`, `modules.builtin.modinfo` and `modules.dep` hashes also match. The V3D module is not installed, builtin or loaded; its source-level finding is not reclassified as fixed.
- **Three boot files** match: the Pi 5 kernel, `config.txt`, and IMX708 overlay. The boot kernel SHA-256 is `5db06314fc343ed828b9e95243468440ac5bcda27ff03e5f838871ff6b8fc93a`. These checks ran before and after the reboot sequence.
- All **16 privileged-file ownership/mode checks** pass. `/usr/bin/sudo` is deliberately execute-only (`04111`); the SSH account verified metadata and permitted operations, without claiming a device-side byte hash for that file.
- Served web assets match the image before and after reboots. The editable development repository retains its expected revision and development-user ownership. Normal BusyBox shell/AWK operations pass.

## Three controlled reboots

Recovery is elapsed host time from requesting reboot until Wi-Fi SSH, healthy services and pinned HTTPS return. App start is monotonic time since kernel boot. Each cycle includes another 20 seconds of stable operation.

| Cycle | Host-observed recovery | App start after kernel boot | App restarts | Result |
|---|---:|---:|---:|---|
| 1 | 83.714 s | 5.754 s | 0 | PASS |
| 2 | 51.301 s | 6.410 s | 0 | PASS |
| 3 | 40.995 s | 6.246 s | 0 | PASS |

All four boot IDs are distinct. The enabled camera service starts its IMX708 NV12 1920×1080 pipeline automatically after every reboot. The wired wait-online service remains inactive, with Wi-Fi supplying the default route and Ethernet disconnected. Public setup status remains complete; account creation and session-expiry regression were not repeated.

Each reboot's selected kernel panic, oops/BUG, unresolved-symbol, symbol/version mismatch and sensor-probe error counts are zero. No application TLS-identity error was found. Raw journals were inspected in memory and not retained.

## Hardware, time and access

- Kernel `6.18.55-v8-16k`, 16 KiB pages. Hailo, IMX708, autofocus, CFE, PiSP, PWM fan and Wi-Fi modules are loaded with matching version magic. Hailo identifies as HAILO8 with firmware 4.24.0.
- Final fan state is **1/4**, approximately **2,967 RPM**, at **52.9 °C**. This verifies fan control at the observed operating point, not a thermal-ramp or endurance test.
- Final NTP synchronization is active; device UTC is within five seconds of the host request window. No clock was changed by this run.
- Codex CLI 0.162.1 starts and reports the restored ChatGPT login; bundled ripgrep 15.2.0 runs. No model/API request was sent, and no authentication-file contents were collected.
- SSH retains key-only policy; root/non-key login attempts are rejected. A 128 KiB SFTP round trip matches its checksum and remote temporary files were removed.
- HTTPS pages return 200 and unauthenticated AI requests return 401. **16 TLS/unauthenticated RTSPS cases and five OPTIONS selector cases** pass both before and after reboots without app PID changes or restarts. No authenticated RTSP media test or credential collection was performed.

## Evidence and limits

Git-excluded working evidence: `.state/kernel-deployment-2026-10-13/`.
Curated archive with per-file `SHA256SUMS`:
`artifacts/20261013T124642Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-deployment-2026-10-13/`.

The archive contains result records, verification helpers, installation metadata, actual-image baselines and the user's observation record. Authentication files, passwords, cookies, signed application configuration, raw journals, transfer payloads and key/certificate files are excluded. Device addresses and identifiers remain in ignored evidence rather than this report. The original build-only report/archive remains a historical record.

This validates observed deployment operation, not a target exploit-regression suite, new vulnerability scan, long-duration stability test or QEMU acceptance. Kernel assessments remain **55 fixed, 285 specifically excluded, 45 open and 18 inconclusive**. Successful camera/Hailo operation does not close those unresolved findings or validate optional modules absent from this image.
