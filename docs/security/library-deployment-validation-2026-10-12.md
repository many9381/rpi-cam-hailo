# Library image deployment validation — 2026-10-12

Image: `20261012T140609Z-e664cb9647e7` / `rpi5-camera-hailo`.
Recorded: 2026-10-12T16:10:03.994206+00:00.

## Scope and outcome

Automated installed-image checks and three controlled Wi-Fi reboots: **PASS**.
Authenticated browser confirmation: **PASS**.
This record covers the Raspberry Pi 5 booted from the installed USB SSD, using
Wi-Fi `198.51.100.60`. It does not claim wired/minimal/QEMU acceptance, long-duration
stability, full-library test-suite coverage, or that all security findings are fixed.
No image build, SSD write, package replacement, account change, or production
configuration change was performed during this acceptance run.

## Installed identity and checks

- Board serial `5090bb4b8a34a361`; `/dev/sda2`, USB root UUID
  `0ba292b1-3dd9-413c-8b58-9fb7f0210b9a`. The installer record identifies SSD
  `003987654321`; the running USB bridge reports the expected GIGABYTE model/size
  but does not expose a serial in `lsblk`, so serial comparison is installer evidence.
- **204 installed files matched** the image/rootfs evidence, including all 182
  shared-library files recorded by the build comparison, the application, camera
  IPA modules/signatures, selected security libraries, kernel and seven drivers.
  The library comparison is symbol/export compatibility, not proof of every ABI behavior.
- Kernel `6.18.55-v8-16k`, 16 KiB pages; Hailo, IMX708, autofocus, CFE, PiSP,
  PWM fan and Wi-Fi modules loaded with matching version magic. Selected kernel
  panic, oops, unresolved-symbol, version-mismatch and sensor-probe error counts: zero.
- SSH public-key policy verified; root and password login rejected. A 128 KiB
  SFTP round trip matched its checksum; temporary device files removed.
- Installed FFmpeg 7.1.5 passed bounded H.264 encode/decode, JPEG encode/decode,
  VobSub and four-frame alternating-size filter checks. Synthetic inputs only;
  production camera process and restart count remained unchanged.
- Hailo8 identified with firmware 4.24.0. Codex CLI 0.162.1 reports an existing
  ChatGPT login; bundled ripgrep 15.2.0 runs. No model/API request was sent.
- HTTPS resources returned 200; setup remained complete; unauthenticated AI
  requests returned 401. Sixteen TLS/unauthenticated RTSPS cases and five OPTIONS
  selector cases passed before and after reboot testing. No authorized media
  credentials were collected for this run.
- Final fan state `2/4`,
  `5132` RPM; final temperature
  58.4 °C. Fan control is active;
  this is not a temperature-ramp characterization.

## Three reboots

Recovery is measured from the host’s reboot request until Wi-Fi SSH, service
health and pinned HTTPS are available; it includes shutdown/firmware/network time.
App start uses the device’s monotonic kernel-boot time. Each cycle then observes
20 seconds of stable service and confirms the 1080p capture pipeline in the log.

| Cycle | Host-observed recovery | App start after kernel boot | App restart count | Result |
|---|---:|---:|---:|---|
| 1 | 56.838 s | 6.258 s | 0 | PASS |
| 2 | 39.771 s | 6.318 s | 0 | PASS |
| 3 | 53.018 s | 6.442 s | 0 | PASS |

All four boot IDs are distinct. Board, root UUID, SSH key and TLS certificate
remained unchanged. Initial setup stayed complete and no wired wait-online unit
ran. Final NTP synchronization: **PASS** (checked separately after the last boot).

## Browser observation

PASS — user confirmed live video, `hailo / ready`, increasing processed frames, and object labels/confidence after the third reboot.

## Initial setup incident and remaining follow-up

Before this acceptance run, the user reported a generic initialization/credential
error. The submitted username is permitted by the username policy. The first failed HTTP
response was not captured. A later retry returned 200 and started the 1080p
pipeline at 15:58:16 UTC, with `setup/status.required=false` afterward.

The first boot seeded time at 15:24:59 UTC and started the app at logged 15:25:03;
NTP first synchronized to 15:44:25.634849 UTC. Monotonic uptime supports an
approximately 19-minute forward correction. Sessions expire after 600 seconds
using wall-clock deadlines, so a session created before that correction could
expire immediately. **This is a plausible trigger, not a confirmed cause of the
reported failure**: no failed response code or user-session audit was obtained.

Two UI behaviors are confirmed by source inspection: setup failures all use a
generic credential message, and the setup failure reconciliation does not
restore the initial login view when that session expires. These remain open;
they were not changed or regression-tested in this deployment validation.
Successful configured-device reboots do not close first-boot setup reliability.

Subsequent work is tracked in
[initial setup session recovery](setup-session-recovery-2026-10-12.md). That
separate change fixes and regression-tests the UI behavior; this historical
deployment record does not validate installation of the later image.

The prior security assessment also remains unchanged: 14 open and two partially
mitigated associations in the remaining-library review. No new CVE scan was run.
See [library remediation](library-residual-remediation-2026-10-12.md).

## Evidence

Private working evidence: `.state/library-deployment-2026-10-12/`.
Curated archive: `artifacts/20261012T140609Z-e664cb9647e7/rpi5-camera-hailo/security/library-deployment-2026-10-12/`.
The archive contains explicit sanitized results, scripts, public identity pins,
installer/build verification records, and checksums. Passwords, session cookies,
Codex authentication files, signed application configuration and raw journals
are excluded. User browser confirmation, when present, is identified as such.
