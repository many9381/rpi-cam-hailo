# Default image deployment validation — 2026-10-17

Image **`20261017T051814Z-63b1d2587b1b`**, profile `rpi5-camera-hailo`:
**PASS — automated checks and authenticated video/Hailo operator confirmation**.
The three-reboot and capture checks below are fresh measurements of this image.
After the final reboot, the user confirmed normal video, `hailo / ready`,
increasing inference frames and detected object names/confidence in response
to the dashboard verification request. This is fresh operator evidence for
this deployment.

## Image and installation identity

This image separates target GCC/development tools into the optional
`packagegroup-rpi5-buildtools`, default off. Codex is selected explicitly by
the camera image instead of the firmware package group's runtime dependencies.
The shared firmware package epoch is now `1`, so the privacy-cleaned Git
revision sorts after packages from the former history. Existing application
patches and the sanitized source pin remain selected.

- Compressed WIC SHA-256:
  `660aab46d09ed60d75723737b24bf3ce8cafd6e8e1b58b8963ac0136d2342949`.
- The SSD installation receipt is dated **2026-10-17 07:04:36 UTC** and matches
  this image. It records camera provisioning and Codex login restoration.
- The user confirmed the reinstalled device address after the old SSH pin
  rejected its changed key. A separate strict pin verified the expected board,
  build, kernel and USB root. The HTTPS certificate was obtained through that
  pinned SSH connection and checked by exact certificate hash.
- **393 selected files** were verified inside the actual WIC; **391 readable
  installed files** matched those bytes on the Pi. Execute-only sudo and the
  root-only security-status sudoers file have no device-side byte-hash claim.
  All **16 privileged ownership/mode records** matched.
- Four boot files and all **27 packaged kernel module files** matched.
  The device runs `6.18.55-v8-16k` with 16 KiB kernel pages.
- The source checkout belongs to `rpiadmin` and uses sanitized base
  `a6364ff4c8161334fdf89b54b8d2eeb4ec55a32c` with the layer's existing patches.

## Development-tool separation

The package manifest contains **368 packages**, 92 fewer than the preceding
accepted image. GCC/G++, cpp, binutils, CMake, make, Ninja, pkgconf, development
headers and the compiler package groups are absent. The WIC and live device
also lack the checked compiler/build-tool command paths and C/C++ headers.
Required `libgcc` and `libstdc++` runtime libraries remain present.

The first hardware probe used `getconf`, which was removed with the development
dependencies. The private verification helper now reads `KernelPageSize`
from `/proc/self/smaps`; it confirmed 16 KiB pages. This was a verifier
dependency, and required no image change or package installation on the Pi.
The opted-in development image is not validated by this default-image run.

## Startup and repeated reboots

Initial setup was already complete when inspected and stayed complete after
all three reboots. HTTPS HTML/JS/CSS matched the installed assets, and the AI
endpoint rejected unauthenticated requests with HTTP 401. SSH retained
public-key-only access for `rpiadmin`, with root/password/keyboard-interactive
authentication disabled.

Recovery measures Wi-Fi SSH, healthy application service and pinned HTTPS.
Each cycle then checks twenty seconds of process stability and five seconds
of actual capture progress.

| Cycle | Wi-Fi/web recovery | Service start after boot | CFE / ISP increases over 5 s | Capture errors / service restarts |
|---|---:|---:|---:|---:|
| 1 | 49.800 s | 6.333 s | 1063 / 528 | 0 / 0 |
| 2 | 32.717 s | 6.209 s | 1077 / 528 | 0 / 0 |
| 3 | 32.765 s | 6.257 s | 1071 / 529 | 0 / 0 |

Four distinct boot IDs were observed. Initial, each-reboot and final common
capture checks passed. The final CFE/ISP increases were **1066/530** over five
seconds, with IMX708 NV12 1920×1080 startup recorded. Selected capture/TLS,
sensor-probe, unknown-symbol, module-ABI and kernel panic/oops/BUG error counts
were zero. These counters establish capture progress. The user's subsequent
dashboard confirmation establishes normal authenticated video, Hailo readiness,
increasing inference frames and detected labels/confidence as operator
observations, separate from the automated capture measurements.

## Hailo, Codex and system checks

- Hailo identifies as **HAILO8**, firmware **4.24.0**, with its matching driver
  loaded. Camera, autofocus, CFE/ISP, Wi-Fi and PWM-fan modules are loaded with
  the expected kernel version.
- Codex **0.163.0** reports an existing ChatGPT login before and after reboot
  testing. Its bundled ripgrep **15.2.0** runs. The local daemon starts and
  reports matching CLI, managed-package and server versions; the daemon
  started by the test was stopped before reboot checks. No model request,
  package update, login/logout or credential-content collection was performed.
- Final fan control is **1/4**, approximately **3,675 RPM**, at **57.85 °C**.
- NTP is synchronized, with device time within five seconds of the host
  request window. Security-policy activation and effective nftables, IPv6
  and core-dump settings pass. Root and boot mounts are active/read-write.
  The unprivileged raw-disk/fstab probe retains its documented `/dev/root`
  and block-read permission limitations; those permissions were not changed.

## Scope and evidence

This run did not rebuild the image or rerun source regression suites. It does
not claim new vulnerability classifications, RTSPS interoperability tests,
wired/minimal release acceptance, QEMU validation, physical camera fault
injection or endurance testing. Existing exclusions remain unchanged.

Private evidence is stored under
`artifacts/20261017T051814Z-63b1d2587b1b/rpi5-camera-hailo/security/buildtools-deployment-2026-10-17/`,
with its own SHA-256 manifest. Credentials, cookies, SSH/TLS pins and signed
device configuration are excluded from that archive. Public documentation
contains no device address, serial number or login material.
