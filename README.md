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
  stream / OSD settings, users and access, management IP allow-list, audit
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

| Item | Requirement |
|---|---|
| Board | Raspberry Pi 5, IMX708 camera module, Hailo-8 (optional, `/dev/hailo0`) |
| OS | Raspberry Pi OS / Debian 13 (trixie) 64-bit, kernel 6.x |
| Capture | libcamera 0.7 (Raspberry Pi fork) |
| AI runtime | HailoRT 4.24 with the PCIe driver module for the running kernel |
| Toolchain | CMake 3.25+, GCC 14 (C++20), Node.js 20 + npm for the web build |
| Lint | clang-format 18, clang-tidy 18 (`tools/ci/check.sh`) |

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

Install the development packages for the libraries the firmware links:
libcamera, GStreamer core / app / rtsp / rtsp-server, libsrtp2 (2.7+), x264,
libavutil, libswscale, OpenSSL, SQLite3, yaml-cpp, jsoncpp, libjpeg, GLib/GIO,
and HailoRT with its headers. The runtime package list with versions is in
`docs/security/dependency-inventory.md`.

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
| `http` | bind address and port, TLS material, `web_root`, `public_base_url` (the single allowed browser origin), snapshot and live-stream limits |
| `security` | security store on/off, state directory, audit log bounds |
| `self_protection` | manifest and signature paths, check interval |
| `ai` | Hailo backend, models (`hef_path`, input format, labels, thresholds) |
| `secure_rtsp` | RTSPS/SRTP server: port, mount, keying mode, digest client authentication |

Settings that are editable from the web (camera, sub stream, OSD) are stored
under the security state directory and applied on top of the file.

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

Re-create and re-sign the manifest after every firmware rebuild, configuration
change, or kernel update.

## Running

```bash
./build/apps/camera-firmware/camera-firmware config/app-rpi5-dev.yaml
```

- Web UI and API: `https://<device>:8443/` (or `http://` when `http.tls` is
  off). A device in default state is initialised through the setup wizard,
  which creates the first administrator and the management IP allow-list.
- RTSP: `rtsps://<device>:8555/imx708/main` and `/imx708/sub` (when the sub
  stream is enabled), digest-authenticated when `secure_rtsp.client_auth` is on;
  credentials are provisioned with `rtsp-digest-credential`.

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
source-weakness work: the dependency inventory, CycloneDX SBOMs for the
firmware and the web bundle, the vulnerability scan record with every CVE and
its verdict, and the static-analysis record. `docs/security/README.md`
explains how to regenerate the SBOMs and re-run the scans with
`tools/security/`.

## Third-party components

Drogon and Trantor (vendored from source with the patches in `patches/`),
GStreamer and its RTSP server, libcamera, HailoRT, x264, libsrtp2, FFmpeg's
libavutil/libswscale, OpenSSL, SQLite, yaml-cpp, jsoncpp, libjpeg, GLib;
`stb_truetype` and the NanumGothic Bold font (SIL Open Font License) under
`vendor/`; React, react-router and Vite for the web application. Versions are
listed in `docs/security/dependency-inventory.md`.

## License

No license file is included yet.
