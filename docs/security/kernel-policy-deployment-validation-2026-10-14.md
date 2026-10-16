# Kernel policy image deployment validation — 2026-10-14

Image: `20261014T152325Z-e664cb9647e7` / `rpi5-camera-hailo`.

## Outcome and scope

Installed-image, network-policy and three controlled Wi-Fi reboot checks: **PASS**.
After the third reboot, the user confirmed normal web video, `hailo / ready`,
increasing inference frames, and object labels with confidence values.

This is the deployment record for [the kernel policy image](kernel-policy-2026-10-14.md).
The user installed and booted the image before verification. This run did not
rebuild or flash an image, replace packages, change credentials, rules, sysctls,
application settings or the clock. It records Wi-Fi integration, not a separate
wired/minimal-image release gate.

## Image and service identity

- The SSD receipt matches WIC SHA-256
  `60c48862a4df7a085961907128d33050ad9f5a35fcd71646d49bb5b4d68774b6`.
  Running build/profile, registered board and USB root device match. Root UUID
  remains unchanged across all three reboots.
- The user confirmed the reinstalled Pi address before the new SSH key was
  pinned. Its public TLS certificate was obtained from loopback HTTPS through
  that pinned SSH connection. Both pins remain fixed; prior evidence is preserved.
- **262 readable installed files** match the verified WIC, including **27 kernel
  modules**, the protected **182 library comparisons**, policy content and
  camera/web/Codex files. All **four boot files**, module metadata and module
  version magic match before and after reboots. No extra module release tree exists.
- **16 existing privileged-file metadata checks** pass. `/usr/bin/sudo` is
  execute-only; its target-side byte hash is not claimed. The root-only policy
  sudoers rule also cannot be read by this SSH account: its bytes/0440/root
  ownership were checked in the WIC, and its permitted/denied behavior was
  verified on the device. Readable policy metadata, including the 0750 sudoers
  directory, matches the image. No permissions were relaxed.
- The no-argument status helper succeeds; extra arguments are rejected both by
  sudo and directly by the helper. The status operation does not change rules.

## Actual policy behavior

Before the reboot sequence and again after it, three ordinary IPv4 echo requests
receive three replies; three timestamp requests receive **zero** replies while
the Pi's input-drop counter increases by **three**. Requests originate from a
temporary unprivileged container on a dedicated NAT bridge on the build PC.
The counter establishes packet arrival and rule matching rather than inferring
blocking from silence alone. The app PID and restart count remain unchanged.

The installed table has exactly two accept-policy chains at priority -10, with
the expected inbound timestamp-request and outbound timestamp-reply drop rules.
The enabled policy service completes successfully **before networkd** on every
observed boot; networkd requires it. IPv6 `drop_unicast_in_l2_multicast=1` is
effective for `all`, `default`, `lo`, `eth0` and `wlan0` across all four boots.
Core settings remain `core_pattern=|/bin/false`, `core_pipe_limit=1`,
`suid_dumpable=0`; the discard executable exists and is executable.

No timestamp reply was injected from the Pi, no IPv6 L2 malformed-frame/hotplug
test was performed on the Pi, and no process core dump was triggered. The
previous isolated native packet tests remain a separate evidence scope.

## Three controlled reboots

Recovery is host elapsed time until Wi-Fi SSH, healthy services and pinned HTTPS
return. Start times are monotonic seconds after kernel boot. Each cycle also
includes at least 20 seconds of stable operation.

| Cycle | Recovery | Camera service start | Policy active | App restarts | Result |
|---|---:|---:|---:|---:|---|
| 1 | 34.816 s | 6.261 s | 4.528 s | 0 | PASS |
| 2 | 50.753 s | 6.213 s | 4.504 s | 0 | PASS |
| 3 | 70.115 s | 6.293 s | 4.488 s | 0 | PASS |

Four distinct boot IDs are recorded. The camera service automatically starts the
IMX708 NV12 1920×1080 pipeline after each reboot. Wi-Fi supplies the default route;
Ethernet remains disconnected and wired wait-online inactive. Setup stays complete.
Selected panic, oops/BUG, unresolved-symbol, version/CRC mismatch and sensor-probe
error counts remain zero. No application TLS-identity error is observed.

## Hardware and access

- Linux 6.18.55-v8-16k with 16 KiB pages; camera, autofocus, CFE, PiSP, Hailo,
  fan and Wi-Fi modules load normally. Hailo reports HAILO8 firmware 4.24.0.
- Final observed temperature is **56.8 °C**;
  fan state **2/4**, approximately
  **5,285 RPM**. This is an operating-point observation.
- Codex 0.162.1 starts with the restored ChatGPT login; bundled ripgrep 15.2.0
  runs. No model/API request or authentication-file read was performed.
- NTP is synchronized and device UTC falls within five seconds of the host
  request window. The development repository and normal BusyBox shell/AWK checks pass.
- SSH remains key-only; root and non-key login attempts fail. The 128 KiB SFTP
  round trip matches its checksum and temporary target files are removed.
- HTTPS web assets return 200 and unauthenticated AI access returns 401.
  **16 TLS/unauthenticated RTSPS cases and five OPTIONS selector cases** pass
  before and after reboots. No authenticated RTSPS media credentials were collected.
- The existing board-specific observations remain Cortex-A76 without SVE and
  `arm,gic-400` without GICv5; they do not broaden source-level exclusions.

## Security boundaries and evidence

The three policy associations retain source-open status. IPv6's separate
multicast-destination/error variant remains open. The nftables ownership fix
retains its build-stage source-fixed assessment; installed module identity and
normal loading are verified here, not exploit resistance or concurrency stress.

Kernel counts remain **108 fixed, 291 specifically excluded, 3 open, 1 unassessed**.
The original whole-image ledger remains **197 fixed, 327 specifically excluded,
12 open, 2 partially mitigated/open, 1 unassessed** out of 539 associations.
This is not a new vulnerability scan; the historical database snapshot remains
2026-10-11, with selected primary-record review on 2026-10-14. Newly added
userspace packages remain outside that old denominator as documented at build time.

Working evidence: `.state/kernel-policy-deployment-2026-10-14/`.
Curated archive with `SHA256SUMS`:
`artifacts/20261014T152325Z-e664cb9647e7/rpi5-camera-hailo/security/kernel-policy-deployment-2026-10-14/`.

The temporary ICMP container, image, bridge, storage pool and local binary/archive
were removed after testing. The evidence archive excludes keys, certificates,
credentials, cookies, signed app configuration, raw journals and transfer payloads.
Device addresses/identifiers remain in ignored evidence rather than this report.
No QEMU build or long-duration endurance test was performed.
