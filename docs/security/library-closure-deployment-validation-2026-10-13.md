# Library follow-up image deployment validation — 2026-10-13

Image: `20261012T172633Z-e664cb9647e7` / `rpi5-camera-hailo`.

## Outcome and scope

Installed-image verification, three controlled Wi-Fi reboots and final service
health checks: **PASS**. After the third reboot, the user separately confirmed
normal web video, `hailo / ready`, increasing inference frames, and object
labels with confidence values.

This accepts deployment of the [library follow-up image](library-closure-2026-10-12.md).
The device was already installed and booted by the user. This run did not rebuild
or write an image, replace packages, reset accounts, change application settings
or adjust the clock. It records integrated Wi-Fi acceptance, not the separate
wired/minimal-image release gate.

## Installation and file verification

- The SSD installation record matches the completed image's compressed-file
  SHA-256. The running build ID and Hailo profile match that image, and the root
  filesystem is on the registered board's USB SSD. Its UUID stayed unchanged
  through all three reboots.
- After the user confirmed the reinstalled device's address, its new SSH host
  key was pinned. The public TLS certificate was obtained through that pinned
  SSH connection. Both identity pins stayed fixed throughout verification.
- **57 installed root-filesystem files** match the actual WIC evidence. These
  include the changed ALSA, GnuTLS, libevent, libcamera and librpicam_app
  libraries; both BusyBox binaries; libc/loader; the application, web assets,
  development sources, the SSH server and seven kernel modules.
- **Two boot files**, the Pi 5 kernel and `config.txt`, also match the image.
  **16 privileged-file ownership/mode checks** pass. `/usr/bin/sudo` is
  deliberately execute-only (`04111`), so its installed bytes could not be
  hashed by the SSH account. Its metadata and permitted operations were
  verified; its byte identity is not asserted by this device check.
- The three served web assets match the image before and after the reboot
  sequence. The editable development repository has the expected upstream
  revision and development-user ownership; reviewed source files match the
  image. Ordinary BusyBox shell and AWK operations pass.
- The public setup-status endpoint reports setup complete before and after
  every reboot. This run did not repeat account creation or force initial-session
  expiry. Those regression checks remain in the linked setup-recovery evidence.

## Three reboots

Recovery measures elapsed host time from requesting reboot until Wi-Fi SSH,
healthy services and pinned HTTPS are available. App start uses monotonic time
since kernel boot. Every cycle includes another 20 seconds of stable service.

| Cycle | Host-observed recovery | App start after kernel boot | App restarts | Result |
|---|---:|---:|---:|---|
| 1 | 76.462 s | 6.246 s | 0 | PASS |
| 2 | 51.248 s | 6.382 s | 0 | PASS |
| 3 | 40.585 s | 6.294 s | 0 | PASS |

All four boot IDs are distinct. The camera service remained enabled and started
its IMX708 NV12 1920×1080 pipeline after every reboot. Board and media identity
were preserved. The wired wait-online service stayed inactive, and Wi-Fi
provided the default route with Ethernet disconnected.

## Hardware, time and access checks

- Kernel `6.18.55-v8-16k`, 16 KiB pages. Hailo, IMX708, autofocus, CFE, PiSP,
  PWM fan and Wi-Fi modules are loaded with matching version magic.
- Selected kernel panic/oops, unresolved-symbol, module-version mismatch and
  sensor-probe error counts are zero. No application TLS-identity error was
  found in the initial or three reboot journals. Raw journals were not saved.
- Hailo8 identifies with firmware 4.24.0. Final fan state is **2/4**, about
  **5,169 RPM**, with **58.4 °C** measured temperature. This confirms fan control
  at the observed operating point, not a thermal-ramp or endurance test.
- Final NTP synchronization is active. Device UTC is within five seconds of
  the host request window without any clock change by this validation.
- Codex CLI 0.162.1 starts and reports the restored ChatGPT login; bundled
  ripgrep 15.2.0 runs. No model/API request was sent and no authentication-file
  contents were collected or archived by this run.
- SSH enforces the expected key-only policy. Root and non-key login attempts
  are rejected. A 128 KiB SFTP round trip matches its checksum and the remote
  temporary files were removed.
- HTTPS pages return 200; unauthenticated AI requests return 401. **16
  TLS/unauthenticated RTSPS cases and five OPTIONS selector cases** pass before
  and after the three reboots. The app retains the same PID with zero restarts
  during each set of protocol checks. No authenticated RTSP media test or
  credential collection was performed in this run.

## Evidence and remaining work

Private working evidence: `.state/library-closure-deployment-2026-10-13/`.
Curated archive with `SHA256SUMS`:
`artifacts/20261012T172633Z-e664cb9647e7/rpi5-camera-hailo/security/library-closure-deployment-2026-10-13/`.

The archive contains selected result records, verification helpers, installation
metadata, the user's observation record and the actual-image hash baseline.
Authentication files, passwords, cookies, signed application configuration,
raw journals, transfer payloads and key/certificate files are excluded. Device
addresses and identifiers remain in ignored evidence rather than this report.
The original build-only archive is preserved as a historical record.

This is acceptance of the installed image's observed operation. It is not a new
vulnerability scan, a target exploit-regression suite, physical audio testing,
long-duration stability testing, or QEMU acceptance. The library assessment
remains **eight open and two partial**, with the other whole-image findings and
assessment limits unchanged. Successful camera/Hailo operation does not close
those security findings.
