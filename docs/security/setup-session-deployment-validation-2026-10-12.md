# Setup recovery image deployment validation — 2026-10-12

> Privacy: Device/client addresses in this report are documentation-only
> examples. Original local measurements are retained outside Git.

Image: `20261012T162756Z-e664cb9647e7` / `rpi5-camera-hailo`.
Recorded: 2026-10-12T17:02:14.647752+00:00.

## Outcome and scope

Installed-file checks, three controlled Wi-Fi reboots and final health checks:
**PASS**. The user separately confirmed **error-free initial setup** and, after
the third reboot, **normal video, Hailo ready status, increasing inference frames,
and object labels/confidence**.

This verifies deployment of the [setup session recovery change](setup-session-recovery-2026-10-12.md)
on Wi-Fi `198.51.100.60`. No account reset, production configuration change,
clock adjustment, package replacement, image build or SSD write was performed
during this acceptance run.

## Installed image and setup behavior

- The local SSD installation record matches this image's SHA-256 and identifies
  the registered GIGABYTE SSD, serial `003987654321`.
- The running board serial is `5090bb4b8a34a361`, with USB root `/dev/sda2`
  and UUID `111e1410-5824-4436-a207-eb33315f0115`. The new SSH host key was pinned after
  the user confirmed the reinstalled Pi's address; the public HTTPS certificate
  was obtained through that pinned SSH connection.
- **15 installed files match the actual-image evidence**, including the
  three web assets, nine changed development-source files, build identity,
  application executable and service unit. Served web asset hashes also match
  before and after all three reboots.
- `setup/status` reports setup complete. The user confirms initial-account login
  and administrator creation finished without errors in this image.
- The camera application starts automatically; the 1080p IMX708 capture pipeline
  appears in the current process's log after every reboot. Setup stays complete.
- Live initial-session expiry was **not forced** on the already initialized
  device. Expiry/401 recovery, safe messages and forward-clock behavior have the
  automated regression evidence linked in the change record. Normal first-boot
  success is user-observed; it does not by itself exercise the expiry branch.

## Three reboots

Recovery is measured from the host's reboot request until Wi-Fi SSH, service
health and pinned HTTPS are available. It includes shutdown, firmware and network
recovery. App start is measured from monotonic kernel-boot time. Each cycle then
observes another 20 seconds of stable service.

| Cycle | Host-observed recovery | App start after kernel boot | App restarts | Result |
|---|---:|---:|---:|---|
| 1 | 85.621 s | 5.794 s | 0 | PASS |
| 2 | 40.111 s | 6.406 s | 0 | PASS |
| 3 | 39.979 s | 6.306 s | 0 | PASS |

All four boot IDs are distinct. Board, USB root UUID, SSH key and TLS certificate
remained unchanged. The wired wait-online service remained inactive. Final NTP
synchronization is confirmed without modifying the device clock.

## Hardware and access checks

- Kernel `6.18.55-v8-16k`, 16 KiB pages; Hailo, IMX708, autofocus, CFE, PiSP,
  PWM fan and Wi-Fi modules are loaded with matching version magic.
- No selected kernel panic/oops, unresolved-symbol, module-version mismatch,
  sensor-probe failure or application TLS-identity errors were found.
- Hailo8 identifies with firmware 4.24.0. Final fan state is
  `2/4`, approximately
  5130 RPM; final measured temperature is
  57.9 °C. This confirms active control, not a
  temperature-ramp characterization.
- Codex CLI 0.162.1 starts and reports the restored ChatGPT login; bundled
  ripgrep 15.2.0 runs. No model/API request was sent.
- SSH effective policy permits the expected key-only user. Root and non-key
  login attempts are rejected. A 128 KiB SFTP round trip matches its checksum;
  its temporary remote directory was removed.
- HTTPS resources return 200 and unauthenticated AI requests return 401.
  Sixteen TLS/unauthenticated RTSPS cases and five OPTIONS selector cases pass
  both before and after the reboot sequence. No authorized RTSP media credentials
  were collected for this run.

## Evidence and limits

Private working evidence: `.state/setup-session-deployment-2026-10-12/`.
Curated archive with its own `SHA256SUMS`:
`artifacts/20261012T162756Z-e664cb9647e7/rpi5-camera-hailo/security/setup-session-deployment-2026-10-12/`.

The archive contains explicit sanitized results, verification scripts, public
identity pins, installation metadata and user observation records. Passwords,
session cookies, Codex authentication files, signed application configuration
and raw journals are excluded.

This is Wi-Fi acceptance for this installed image. It does not assert wired,
minimal-image or QEMU acceptance, long-duration stability, or a new vulnerability
assessment. The previously documented remaining library/kernel findings are
unchanged.
