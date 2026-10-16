# rpi-cam-hailo — camera firmware for Raspberry Pi 5 + Hailo

A single-binary C++20 camera firmware for the Raspberry Pi 5 with the IMX708
camera module and an optional Hailo-8 AI accelerator, plus the React web
application it serves. It captures 1080p50 from libcamera, encodes with x264,
serves fragmented MP4 over HTTPS and SRTP over RTSPS, runs object detection on
the Hailo device, burns an on-screen display into every output, and is built
to the hardening requirements of a certified network camera: authenticated
HTTPS API and web UI, audit log, integrity self-protection with a signed
manifest, and a source/dependency security gate in the repository.

## Features

- **Video**: libcamera (PiSP) capture at 1920x1080 NV12 up to 50 fps, x264
  encode on a dedicated thread, an on-demand software-downscaled sub stream.
- **Streaming**: `live.mp4` fragmented MP4 over HTTPS with per-client
  back-pressure, JPEG snapshots, and an RTSPS control channel with SDES/MIKEY
  keyed SRTP media (`/imx708/main`, `/imx708/sub`) that stock GStreamer plays.
- **AI**: HailoRT object detection on a low-resolution ISP output (no software
  colour conversion), detections as JSON and as a server-sent-event stream,
  multi-model configuration.
- **OSD**: up to 8 items (timestamp, camera id, custom text) laid out from the
  same ratios in the web preview and the firmware compositor, rendered from an
  embedded Korean-capable font.
- **Web UI / API**: setup wizard, dashboard with live preview, camera / sub
  stream / OSD settings, users and access, optional management IP restrictions, audit
  records, system protection; Korean and English.
- **Security**: HTTPS with device TLS material, session cookies, password
  hashing, per-IP login rate limit, role-based access (administrator /
  viewer), RTSP digest authentication, SQLite security store, bounded audit
  log with rotation.
- **Integrity**: a signed manifest over the firmware binary, its configuration
  and the kernel image, verified at start and on a schedule; the device runs
  restricted when verification fails.
- **Runtime settings**: camera, sub-stream and OSD settings editable from the
  web with validation shared between backend and frontend, durable apply /
  rollback markers, and restart-safe storage.

## Platform

The current deployed target is the companion Yocto project's
`rpi5-camera-hailo` image. Image `20261016T111625Z-e664cb9647e7` passed
[installation and device validation on 2026-10-16](docs/security/static-warning-deployment-validation-2026-10-16.md).
Runtime versions below describe that image; build requirements come from the
current source configuration.

| Item | Validated Yocto image |
|---|---|
| Board | Raspberry Pi 5, Camera Module 3 Wide (IMX708), Hailo-8 (`/dev/hailo0`) |
| OS | Yocto 6.0 (`wrynose`), AArch64, kernel `6.18.55-v8-16k` |
| Capture | Raspberry Pi libcamera `0.6.0+rpt20251202`, matching the downstream CFE/ISP drivers |
| AI runtime | HailoRT 4.24.0 and matching 4.24.0 PCIe driver built for the image kernel |
| C++ toolchain | Yocto GCC 15.3.0; project requires C++20 and CMake 3.25+ |
| Web build | Node.js `^20.19.0` or `>=22.12.0` + npm, as declared in `web/package.json`; no Node.js runtime needed by the served UI |
| Lint | clang-format / clang-tidy 18.1.3 in the latest source-quality run |

The companion project also offers a camera profile without Hailo. Earlier
Raspberry Pi OS / Debian 13 development used a different kernel and libcamera
0.7; its [dependency inventory](docs/security/dependency-inventory.md) is
historical evidence. Use the actual image package manifest and SPDX for Yocto,
as described in the [security evidence index](docs/security/README.md#current-yocto-image-evidence).

## Repository layout

| Path | Contents |
|---|---|
| `apps/camera-firmware/` | the firmware executable (`main.cpp`, live MP4 byte stream) |
| `apps/camera-firmware-integrity/` | CLI that creates and signs the integrity manifest |
| `apps/rtsp-digest-credential/` | CLI that provisions RTSP digest credentials |
| `src/`, `include/camera_firmware/` | library modules: `ai`, `boot`, `common`, `config`, `crypto`, `integrity`, `media`, `rtsp`, `runtime`, `security`, `service`, `settings` |
| `plugins/gst-secure-srtp/` | GStreamer element that applies SRTP with firmware-owned keys |
| `web/` | React 18 + TypeScript application (Vite, Vitest, Playwright e2e) |
| `config/` | sample YAML configurations for the Pi 5 (`app-rpi5-dev.yaml`, AI variants) |
| `cmake/` | dependency handling, including the vendored Drogon/Trantor copy and patches |
| `patches/` | the patches applied to Drogon 1.9.0 and Trantor 1.5.20 |
| `vendor/` | `stb_truetype`, the embedded NanumGothic Bold font (OFL) |
| `tests/` | GoogleTest unit and integration suites (`tests/unit/<module>`, `tests/integration`) |
| `tools/ci/` | quality gate script, pre-commit hook, hook installer |
| `tools/security/` | SBOM generator and Debian security-tracker scanner |
| `docs/security/` | dependency inventory, SBOMs, vulnerability scan and static-analysis records |

## Building

### Yocto image

When this checkout is `rpi-cam-hailo/` inside the companion
`yocto-rpi5-cam-firmware` workspace, run these commands from that workspace's
root after preparing the local inputs in the
[firmware integration runbook](../docs/runbooks/camera-firmware.md):

```bash
BUILD_ID="$(./scripts/new-build-id.sh)"
./scripts/build.sh --build-id "$BUILD_ID" rpi5-camera-hailo build
./scripts/install-ssd.sh --check
# With the registered target SSD attached, install the latest completed image:
./scripts/install-ssd.sh
```

The application, static web UI and optional development checkout are separate
packages. Recipes use a pinned upstream commit plus reviewed layer patches;
uncommitted edits here are not automatically included in an image. The web
recipe builds offline with native Node.js. Routine Hailo image builds and
installation do not require QEMU. See the runbook for source updates, private
Hailo/Wi-Fi inputs, SSD selection and per-device provisioning.

### Standalone source build

Install the development packages for the libraries the firmware links:
libcamera, GStreamer core / app / rtsp / rtsp-server, libsrtp2 (2.7+), x264,
libavutil, libswscale, OpenSSL, SQLite3, yaml-cpp, jsoncpp, libjpeg, GLib/GIO,
and HailoRT with its headers. Use a libcamera build compatible with the target
kernel's camera drivers. The historical Debian package list is a reference for
that earlier environment, not a package-installation list for Yocto.

The HTTP server is Drogon 1.9.0 on Trantor 1.5.20. Both are copied from local
source checkouts at configure time and patched (`patches/`), so the checkouts
must be passed to CMake:

```bash
cmake -S . -B build \
  -DCAMERA_FIRMWARE_DROGON_SOURCE_DIR=/path/to/drogon-1.9.0 \
  -DCAMERA_FIRMWARE_TRANTOR_SOURCE_DIR=/path/to/trantor-1.5.20 \
  -DBUILD_TESTING=ON
cmake --build build --target camera-firmware -j4
```

The `camera-firmware` target also runs `npm ci` and `npm run build` in `web/`;
the result is served from the `http.web_root` directory in the configuration.
The default build type is RelWithDebInfo with `-DNDEBUG` stripped, so
optimisation is on and assertions stay active. `compile_commands.json` is
always written.

## Configuration

One YAML file, validated on start (`camera-firmware --validate-config
<file>`). Sections, with `config/app-rpi5-dev.yaml` as the reference:

| Section | Purpose |
|---|---|
| `platform` | target board |
| `camera` | capture source and format, x264 encoder settings, AI model attachment, sub stream, OSD |
| `http` | bind address and port, TLS material, `web_root`, optional explicit `public_base_url`, snapshot and live-stream limits |
| `security` | security store on/off, state directory, audit log bounds |
| `self_protection` | manifest and signature paths, check interval |
| `ai` | Hailo backend, models (`hef_path`, input format, labels, thresholds) |
| `secure_rtsp` | RTSPS/SRTP server: port, mount, keying mode, digest client authentication |

Settings that are editable from the web (camera, sub stream, OSD) are stored
under the security state directory and applied on top of the file.

Direct HTTPS browser requests are checked against the server socket's actual
IP address, port and TLS state. `http.public_base_url` can be empty for DHCP;
when set, it permits an additional explicit HTTPS origin. `Host` and forwarded
headers do not authorize arbitrary origins. No future Pi IP needs to be
registered in the setup wizard. Certificate trust/name validation is separate
from this origin check; see [first-boot setup](#first-boot-setup-on-yocto).

When `self_protection` is enabled the firmware refuses to run unrestricted
unless the manifest covers the binary, the configuration and the kernel image
and its signature verifies against the embedded public key:

```bash
camera-firmware-integrity create \
  --entry configuration:app-config:/abs/path/app.yaml \
  --entry firmware:camera-firmware:/abs/path/camera-firmware \
  --entry kernel:kernel-image:/boot/firmware/kernel_2712.img \
  --output /var/lib/camera-firmware/integrity/manifest.yaml
camera-firmware-integrity sign \
  --manifest /var/lib/camera-firmware/integrity/manifest.yaml \
  --private-key /path/to/signing.private.pem \
  --output /var/lib/camera-firmware/integrity/manifest.sig
```

That example uses a Raspberry Pi OS kernel path. The Yocto image uses
`/boot/kernel_2712.img`; `install-ssd.sh` signs the actual installed files with
the build PC's private signing key. Re-create and re-sign the manifest after
changing a covered binary, base YAML or kernel. App-managed mutable settings
do not require manually editing or re-signing the base YAML.

## Running

### First-boot setup on Yocto

Normal SSD installation provisions the signed configuration and device TLS/SRTP
material. `camera-firmware.service` starts automatically on boot and becomes
reachable when Ethernet or Wi-Fi receives an address. A raw WIC written without
provisioning has no active app configuration and does not start the service.

1. Open `https://<current-Pi-IP>:8443/`. The installer defaults to
   `public_host: null`, so the address need not be known at image-build time.
   Its self-signed bootstrap certificate identifies `camera.local`; direct IP
   access can show trust and name warnings. This does not configure DNS/mDNS.
   Strict TLS validation requires a resolvable stable name and a matching
   trusted certificate, as described in the provisioning runbook.
2. Sign in with the initial account displayed by the app, then create the
   permanent administrator in the wizard. New web setup defaults management IP
   restrictions **off**. Account/password authentication remains required.
3. The IP shown during setup is the connecting **client PC's address**, used
   to validate the setup session and saved for optional access restrictions.
   It is not the Pi's future server address. If restrictions are needed, manage
   them in **Users → Access IPs**. Enabling them requires the current
   administrator's address in the allowed list; policy changes require recent
   authentication and end existing sessions.
4. Check live video and, on the Hailo profile, `hailo / ready`, increasing
   inference frames and object labels/confidence. Service startup alone is not
   proof that capture or inference is working.

Reboots preserve setup. A full SSD reflash replaces accounts and app state and
requires setup again. An app update that preserves the existing security DB
preserves its accounts and existing enabled IP restrictions. Sessions remain
bound to the login client's IP even when restrictions are off; a client IP
change requires a fresh login. If setup reports session expiry, sign in again
and re-enter the administrator details instead of repeatedly submitting the
expired wizard.

### Standalone executable

```bash
./build/apps/camera-firmware/camera-firmware config/app-rpi5-dev.yaml
```

- Web UI and API: `https://<device>:8443/` (or `http://` when `http.tls` is
  off in a development configuration). With security enabled, use the setup
  wizard to create the first administrator and choose the IP restriction policy.
- RTSP: `rtsps://<device>:8555/imx708/main` and `/imx708/sub` (when the sub
  stream is enabled), digest-authenticated when `secure_rtsp.client_auth` is on;
  initial administrator setup creates its RTSP Digest credential. The
  `rtsp-digest-credential` CLI is available for explicit manual provisioning.

### HTTP API (all under `/api/v1`)

| Group | Endpoints |
|---|---|
| Health / setup | `health`, `setup/status`, `setup/initialize`, `setup/runtime` |
| Authentication | `auth/login`, `auth/logout`, `auth/me`, `auth/password`, `auth/reauthenticate` |
| Cameras | `cameras`, `cameras/{id}/live.mp4`, `cameras/{id}/snapshot.jpg`, `monitoring/cameras`, `stream` |
| AI | `ai/detections`, `ai/detections/stream` (SSE), `ai/restart` |
| Runtime settings | `settings/runtime`, `settings/runtime/apply`, `settings/runtime/discard`, `runtime/restart` |
| Users and access | `security/users…`, `security/management-ips…` |
| Audit and protection | `audit/events`, `audit/status`, `system/protection`, `system/integrity-checks`, `system/self-tests` |

## Tests and quality gate

```bash
ctest --test-dir build --output-on-failure -j2   # C++ suites + the web suite as one case
cd web && npx vitest run                          # web unit tests
tools/ci/check.sh                                 # format, clang-tidy, build, all tests, web build
tools/ci/install-hooks.sh                         # once per clone: pre-commit format gate, blame config
```

`tools/ci/check.sh` is the gate CI runs (`.github/workflows/ci.yml`, a
self-hosted ARM64 runner): clang-format dry run, clang-tidy over the product
translation units with bugprone / CERT / analyzer / concurrency findings as
errors, the C++ build with tests, `ctest`, then the web tests and build.
`--lint` and `--format` run the first stages only. On a Pi 5 the clang-tidy
stage takes about half an hour.

## Security documentation

`docs/security/` holds the evidence for the known-vulnerability and
source-weakness work. The [security evidence index](docs/security/README.md)
separates current Yocto image SPDX/package manifests, web lockfile/SBOM,
historical Debian inventory, vulnerability assessments and source-quality
results. Device acceptance and source tests are tied to their recorded build
and inputs; they do not imply that all remaining security findings are closed.

## Third-party components

Drogon and Trantor (vendored from source with the patches in `patches/`),
GStreamer and its RTSP server, libcamera, HailoRT, x264, libsrtp2, FFmpeg's
libavutil/libswscale, OpenSSL, SQLite, yaml-cpp, jsoncpp, libjpeg, GLib;
`stb_truetype` and the NanumGothic Bold font (SIL Open Font License) under
`vendor/`; React, react-router and Vite for the web application. Current image
versions are in its package manifest/SPDX; web versions are pinned in
`web/package-lock.json`. See the [security evidence index](docs/security/README.md#current-yocto-image-evidence)
for the artifact paths and historical-inventory boundary.

## License

No license file is included yet.
