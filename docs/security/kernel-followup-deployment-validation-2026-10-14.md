# Kernel follow-up image deployment validation — 2026-10-14

Image: `20261014T064455Z-e664cb9647e7` / `rpi5-camera-hailo`.

## Outcome and scope

Installed-image verification, three controlled Wi-Fi reboots and final hardware/service checks: **PASS**. After the third reboot, the user separately confirmed normal web video, `hailo / ready`, increasing inference frames, and object labels with confidence values.

This accepts deployment of the [kernel follow-up image](kernel-followup-2026-10-14.md), containing twenty additional reviewed kernel patches covering 22 advisory associations. The user installed and booted the image before this run. Verification did not rebuild or write an image, replace packages, change accounts/application settings, or adjust the clock. It records integrated Wi-Fi operation, not the separate wired/minimal-image release gate.

## Installed image and kernel

- The SSD installation record matches the completed image's compressed SHA-256. Running build/profile and registered board identity match; the root filesystem is on its USB SSD. The root UUID remained fixed across all three reboots.
- After the user confirmed the reinstalled Pi's address, its new SSH host key was pinned in a separate evidence directory. The public TLS certificate was obtained from the loopback HTTPS service through that pinned SSH connection. Both pins remained fixed throughout verification; old evidence was preserved.
- **249 installed root-filesystem files** match the actual WIC evidence, including all **25 installed kernel modules**, all **182 protected shared libraries**, camera/web/Codex executables and development source files.
- The complete module directory contains exactly the expected `6.18.55-v8-16k` release and 25 modules. Every module hash and version magic matches the image. `modules.builtin`, `modules.builtin.modinfo` and `modules.dep` hashes also match. The V3D module is not installed, builtin or loaded; its source-level finding is not reclassified as fixed.
- **Four boot files** match: the Pi 5 kernel, `config.txt`, IMX708 overlay and board DTB. The boot kernel SHA-256 is `3ffe67b1265777f8b69b125a84002e336cedcfe00dd1a8b48302d0cec400dad3`. These checks ran before and after the reboot sequence.
- All **16 privileged-file ownership/mode checks** pass. `/usr/bin/sudo` is deliberately execute-only (`04111`); the SSH account verified metadata and permitted operations, without claiming a device-side byte hash for that file.
- Served web assets match the image before and after reboots. The editable development repository retains its expected revision and development-user ownership. Normal BusyBox shell/AWK operations pass.

## Three controlled reboots

Recovery is elapsed host time from requesting reboot until Wi-Fi SSH, healthy services and pinned HTTPS return. App start is monotonic time since kernel boot. Each cycle includes another 20 seconds of stable operation.

| Cycle | Host-observed recovery | App start after kernel boot | App restarts | Result |
|---|---:|---:|---:|---|
| 1 | 33.830 s | 6.014 s | 0 | PASS |
| 2 | 63.067 s | 6.282 s | 0 | PASS |
| 3 | 29.805 s | 6.354 s | 0 | PASS |

All four boot IDs are distinct. The enabled camera service starts its IMX708 NV12 1920×1080 pipeline automatically after every reboot. The wired wait-online service remains inactive, with Wi-Fi supplying the default route and Ethernet disconnected. Public setup status remains complete; account creation and session-expiry regression were not repeated.

Each reboot's selected kernel panic, oops/BUG, unresolved-symbol, symbol/version mismatch and sensor-probe error counts are zero. No application TLS-identity error was found. Raw journals were inspected in memory and not retained.

## Hardware, time and access

- Kernel `6.18.55-v8-16k`, 16 KiB pages. Hailo, IMX708, autofocus, CFE, PiSP, PWM fan and Wi-Fi modules are loaded with matching version magic. Hailo identifies as HAILO8 with firmware 4.24.0.
- All four current CPUs report ARM implementer `0x41`, part `0xd0b` (Cortex-A76), with no SVE feature. The running device tree exposes `arm,gic-400` and no GICv5 bindings; the board DTB hash matches the exact image. This supports the two existing board-specific exclusions, while preserving their source-open status for other hardware.
- Final fan state is **2/4**, approximately **5,155 RPM**, at **57.9 °C**. This verifies fan control at the observed operating point, not a thermal-ramp or endurance test.
- Final NTP synchronization is active; device UTC is within five seconds of the host request window. No clock was changed by this run.
- Codex CLI 0.162.1 starts and reports the restored ChatGPT login; bundled ripgrep 15.2.0 runs. No model/API request was sent, and no authentication-file contents were collected.
- SSH retains key-only policy; root/non-key login attempts are rejected. A 128 KiB SFTP round trip matches its checksum and remote temporary files were removed.
- HTTPS pages return 200 and unauthenticated AI requests return 401. **16 TLS/unauthenticated RTSPS cases and five OPTIONS selector cases** pass both before and after reboots without app PID changes or restarts. No authenticated RTSP media test or credential collection was performed.

## Evidence and limits

Git-excluded working evidence: `.state/kernel-followup-deployment-2026-10-14/`.
Curated archive with per-file `SHA256SUMS`:
`artifacts/20261014T064455Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-followup-deployment-2026-10-14/`.

The archive contains result records, verification helpers, installation metadata, actual-image baselines and the user's observation record. Authentication files, passwords, cookies, signed application configuration, raw journals, transfer payloads and key/certificate files are excluded. Device addresses and identifiers remain in ignored evidence rather than this report. The original build-only report/archive remains a historical record. An initial host-key fingerprint comparison included sentence punctuation; the comparison was corrected against the first observed key before SSH login. This affected only the private verification helper and did not change the target.

This validates observed deployment operation, not a target exploit-regression suite, new vulnerability scan, long-duration stability test or QEMU acceptance. Kernel assessments remain **102 fixed, 292 specifically excluded, 8 open and 1 inconclusive**. The whole-image ledger remains **191 fixed, 328 specifically excluded, 17 open, 2 partially mitigated/open and 1 inconclusive** out of 539 original associations. The assessment retains the 2026-10-11 scanner database. Successful camera/Hailo operation does not close unresolved findings or validate optional modules absent from this image.
