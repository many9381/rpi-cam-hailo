# CoDel/libmount image deployment validation — 2026-10-15

Image: `20261014T170636Z-e664cb9647e7` / `rpi5-camera-hailo`.

## Outcome

Installed-image checks and three controlled Wi-Fi reboots: **PASS**. After the
third reboot, the user confirmed normal web video, `hailo / ready`, increasing
inference frames, and object labels with confidence values.

This is the hardware acceptance record for the
[CoDel/libmount remediation](codel-mount-remediation-2026-10-14.md). The user
installed and booted the image before this run. No image was rebuilt or flashed;
no packages, credentials, application settings, network policy, permissions or
clock were changed. This is Wi-Fi integration evidence, not the separate
wired/minimal-image release gate or a long-duration endurance test.

## Installed image

- The installation receipt matches WIC SHA-256
  `29f43e854fa7d9c1200c8c8bee464e2e2e6a97fb50850ee5e318548c16fa14fd`.
  The running build/profile, registered board and USB root identity match;
  root UUID remains unchanged through all reboots.
- The user confirmed the current Pi address after its SSH host key changed.
  A separate new pin preserves previous evidence. The public TLS certificate
  was obtained through pinned SSH from the loopback service. SSH/TLS pins
  stay fixed throughout this run.
- **376 readable installed files** match the verified WIC, covering all
  **119 util-linux package files**, **187 shared-library files** and **27 kernel
  modules**, together with selected application, camera, Codex and policy files.
  The corrected `sch_fq_codel` and libmount files match the reviewed build.
- All 27 modules, module metadata and **four boot files** match before and
  after the reboot sequence. Module version magic is correct; no extra kernel
  release tree is present. The six rebuilt shared-library changes, including
  the camera public-key/signature regeneration, are covered by the linked
  build-stage evidence and exact installed-file matches.
- **16 privileged ownership/mode checks** pass, including mount/umount root
  ownership and mode `04755`. `/usr/bin/sudo` is execute-only: its byte hash
  cannot be read by this account. The root-only policy sudoers rule also cannot
  be read. Those two files retain WIC evidence; installed metadata where readable
  and permitted/denied helper behavior were checked without relaxing access.

## Three controlled reboots

Recovery measures host elapsed time until Wi-Fi SSH, healthy services and pinned
HTTPS return. Camera start is monotonic time after kernel boot. Each cycle
includes at least 20 seconds of stable operation.

| Cycle | Wi-Fi/web recovery | Camera service start | App restarts | Result |
|---|---:|---:|---:|---|
| 1 | 49.944 s | 6.233 s | 0 | PASS |
| 2 | 38.755 s | 6.173 s | 0 | PASS |
| 3 | 49.910 s | 6.181 s | 0 | PASS |

Four distinct boot IDs were observed. Each reboot automatically starts the
IMX708 NV12 1920×1080 pipeline. Wi-Fi supplies the default route; Ethernet
remains disconnected and wired wait-online remains inactive. Setup stays
complete. Selected panic, oops/BUG, symbol/version mismatch and sensor-probe
error counts are zero; no application TLS-identity error was observed.

## Mount, hardware and service checks

- Root `/` (ext4) and `/boot` (vfat) remain read-write, with both mount units
  active/mounted/successful on all four boots. util-linux/libmount 2.41.3 normal
  query and fstab parsing work. No restricted `user`, `users` or `X-mount.*`
  entries are present.
- An additional unprivileged `findmnt --verify` probe is **LIMITED**, not PASS:
  it reports zero parse errors, one error and two warnings. The stock root
  fstab entry uses `/dev/root`, which has no device node, and this account cannot
  read the raw boot block device. Actual mounted sources are `/dev/sda2` and
  `/dev/sda1`. No on-disk filesystem health or privileged mount/race test is
  claimed, and device permissions were not changed.
- Linux 6.18.55-v8-16k uses 16 KiB pages. Camera, autofocus, CFE, PiSP, Hailo,
  fan and Wi-Fi modules load normally; Hailo reports HAILO8 firmware 4.24.0.
  Final temperature is **57.3 °C**, fan state
  **1/4**, approximately **3,310 RPM**.
  This is a normal operating-point observation, not a thermal stress test.
- Codex 0.162.1 starts with the restored ChatGPT login; its bundled ripgrep
  15.2.0 runs. No model request or authentication-file read was performed.
- NTP is synchronized; UTC falls within five seconds of the host request
  window. Development repository ownership/revision and normal BusyBox
  shell/AWK checks pass.
- SSH remains key-only; root and non-key login attempts fail. A 128 KiB SFTP
  round trip matches its checksum and temporary target files are removed.
- HTTPS web assets return 200; unauthenticated AI access returns 401.
  **16 TLS/unauthenticated RTSPS cases and five OPTIONS selector cases** pass
  both before and after reboots. No authenticated RTSPS credentials or media
  capture were collected in this run.
- The existing policy service completes before networkd on every boot; its
  exact nftables rules, all/default/current-interface IPv6 settings and core
  discard settings persist. Restricted status-helper calls behave correctly.
  Packet-injection, core-dump and interface-hotplug tests were not repeated.

## Security scope and evidence

The three selected CoDel/libmount source fixes retain their build-stage
assessment. This run proves installed identity and ordinary integration; it
does not repeat live CoDel stress, privileged mount races or setuid transitions.
The October 14 database and **546-association** assessment remain unchanged:
**200 fixed, 331 not affected, 12 open, two partially mitigated/open and one
unassessed**. The separately tracked BusyBox `cp` finding remains outside that
denominator. No new vulnerability scan or whole-image security clearance is
claimed. Existing policy mitigations do not close their source-open findings.

Working evidence: `.state/codel-mount-deployment-2026-10-15/`.
Curated archive with checked `SHA256SUMS`:
`artifacts/20261014T170636Z-e664cb9647e7/rpi5-camera-hailo/security/codel-mount-deployment-2026-10-15/`.

The archive excludes keys, certificates, credentials, cookies, signed app
configuration, raw journals and transfer payloads. Device identifiers remain
in ignored evidence. No QEMU work was performed.
