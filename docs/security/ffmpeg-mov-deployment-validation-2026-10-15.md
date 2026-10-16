# FFmpeg MOV image deployment validation — 2026-10-15

Image **`20261015T121728Z-e664cb9647e7`**, profile `rpi5-camera-hailo`: **PASS after recovery**.
Fresh capture-progress checks and three new Wi-Fi reboots passed. After the
last reboot the user confirmed web video, `hailo / ready`, increasing inference
frames, and object labels with confidence values.

This is the hardware acceptance record for the
[MOV append follow-up](ffmpeg-mov-append-2026-10-15.md). The
[initial capture failure](camera-capture-failure-2026-10-15.md) remains recorded.

## Initial failure and recovery

The first three reboot checks verified active services but missed a camera
frontend timeout one second after startup. Both CSI/ISP interrupt counters were
zero, and two independent raw-YUV capture modes also failed. The user rejected
functional acceptance. Those original observations and the failed UI record
are preserved; they are not counted as successful video/AI reboot acceptance.

Following normal shutdown, the user reported another boot and a suspected
loose camera connection. Capture progress resumed without any image, package,
application, account or configuration change. This supports a connection/device
state cause. Cable inspection and power cycling were not isolated interventions,
so this record does not prove which action alone restored capture.

The new checks require live CSI/ISP counter growth and zero capture-timeout or
requeue-error messages for the current application PID. Journal filtering/counting
occurs on the Pi before transfer. A startup log alone cannot pass this gate.
These counters establish hardware progress, not exact frame counts or FPS;
final authenticated video and Hailo confirmation remains a separate requirement.

## Installed software and bounded FFmpeg tests

The same installed image was already checked before the connection issue was
reported. The retained evidence is reused explicitly, not presented as tests
run again after recovery:

- WIC SHA-256: `bc72d65e53f7fdeabb3de4f063d239b0f24541cfe30af95354737e43e57a32ab`; installation receipt, registered board,
  build/profile and USB root identity match.
- **376 readable files**, including **187 shared libraries** and **27 modules**,
  match actual WIC evidence. Changed libavutil and libavformat match exactly.
  **16 privileged ownership/mode records** pass. Execute-only sudo and the
  root-only security sudoers rule have WIC/behavior evidence, without a
  privileged device-side byte-hash claim.
- **20 installed-system FFmpeg tests** pass: ten prior cleanup/allocation/unit
  cases, one new append-API invocation and nine real MOV demuxer invocations.
  These include 20,000 API appends, 32,768 continuous PSSH records, two streams,
  parameter copies and discovery followed by additional fragments (17 records
  after discovery, all 26 at EOF with four media packets).
- Five cross-compiled executables dynamically import the system libraries;
  loader/library/test-file hashes bind them to this image. No implementation
  replacement was installed. Tests used bounded CPU/stack/address-space and
  wall-clock limits with core dumps disabled; all target payloads were removed.
  Static allocation counters, insertion-failure injection and sanitizers were
  native build evidence, not target measurements.

Kernel, all 27 installed modules and four boot files were checked again after
recovery. Module version magic is correct; no extra kernel tree is present.
The previous and recovered installation retain the same SSH/TLS pins and root
UUID. No image rebuild, SSD write or QEMU work was needed.

## Fresh recovery reboot verification

Recovery time measures Wi-Fi SSH, healthy service and pinned HTTPS availability.
Camera service start is monotonic time after kernel boot, not the first frame
latency. Each cycle includes twenty seconds of stability followed by a
five-second hardware-progress measurement.

| Cycle | Wi-Fi/web recovery | Camera service start | CSI / ISP increments over 5 s | Capture errors / app restarts |
|---|---:|---:|---:|---:|
| 1 | 37.012 s | 6.225 s | 1051 / 520 | 0 |
| 2 | 52.135 s | 6.173 s | 1047 / 521 | 0 |
| 3 | 45.001 s | 6.223 s | 1052 / 520 | 0 |

Four distinct boot IDs were observed, with automatic IMX708 NV12 1920×1080
configuration and increasing hardware counters on all four boots. Setup remains
complete, Wi-Fi provides the default route, and disconnected Ethernet does not
hold up boot. Selected kernel panic/oops/BUG, module mismatch and sensor-probe
errors are absent; no application TLS-identity error was observed.

After reboot three, HAILO8 firmware **4.24.0**, Codex **0.162.1** with restored
ChatGPT login, ripgrep **15.2.0**, synchronized NTP and basic BusyBox operations
pass. Final temperature is **55.6 °C**, fan state
**1/4**, **3,214 RPM**; this is an
operating-point observation, not a thermal stress test. No credentials were read
and no Codex model request was sent.

SSH key-only/root restrictions, served web assets, unauthenticated AI rejection,
16 TLS/unauthenticated RTSPS cases and five OPTIONS-selector cases pass.
Firewall, IPv6-interface and core-discard policy persists; policy setup finishes
before networkd. Root/boot are active read/write. The initial unprivileged
on-disk `findmnt --verify` limitation remains; recovery checks do not claim a
raw-filesystem or privileged mount-race test. Authenticated RTSPS media and
long-duration endurance tests are not repeated here.

## Security scope and evidence

CVE-2026-107678 remains **partially mitigated/open** because many separate MOV
parsing passes can still cause cumulative copying/growth. Hardware acceptance
does not close this remaining source issue. The 546-association ledger remains
200 fixed, 331 not affected, 11 open, three partial and one unassessed. No new
vulnerability scan or advisory reclassification was performed.

Fresh evidence: `.state/ffmpeg-mov-recovery-2026-10-15/`.
Earlier bounded-software checks: `.state/ffmpeg-mov-deployment-2026-10-15/`.
Failure diagnosis: `.state/video-ai-stall-2026-10-15/`.
Curated archive with verified checksums:
`artifacts/20261015T121728Z-e664cb9647e7/rpi5-camera-hailo/security/ffmpeg-mov-recovery-2026-10-15/`.
Keys, certificates, credentials, cookies, signed configuration, raw journals,
executable/media payloads and SFTP payloads are excluded. Device identifiers
remain in ignored evidence. Original build and failed hardware observations
are preserved; this report records later successful recovery acceptance.
