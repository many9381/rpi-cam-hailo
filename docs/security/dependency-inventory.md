# Dependency inventory

**Historical Debian inventory — generated 2026-09-10.** The tables below
describe the development Raspberry Pi 5 running Debian 13 "trixie" arm64 plus
the Raspberry Pi archive. They are preserved as that environment's record and
do not describe the current Yocto image.

For the accepted Yocto image's package manifest, SPDX and deployment record,
see [current Yocto image evidence](README.md#current-yocto-image-evidence).
`sbom/firmware.cdx.json` is the historical Debian machine-readable inventory
(CycloneDX 1.5, produced by `tools/security/generate_sbom.py`). The separate
`sbom/web.cdx.json` was regenerated on 2026-10-10 from the updated web lockfile;
the web table below remains the September 10 snapshot, not that newer SBOM.

## 1. Firmware binary — runtime shared libraries

63 Debian/Raspberry Pi packages own the shared libraries the firmware binary loads (`ldd` of `camera-firmware` resolved through `dpkg -S`). "Origin" is Debian unless the version carries the Raspberry Pi suffix or the package only exists in the Raspberry Pi archive.

| Package | Version | Source package | Origin | Role in the firmware |
|---|---|---|---|---|
| hailort | 4.24.0 | hailort | Raspberry Pi archive | Hailo AI runtime |
| libatomic1 | 14.2.0-19 | gcc-14 | Debian trixie | runtime dependency (transitive) |
| libavutil59 | 8:7.1.5-0+deb13u1+rpt2 | ffmpeg | Raspberry Pi archive | swscale support |
| libblkid1 | 2.41.5-0+deb13u1 | util-linux | Debian trixie | runtime dependency (transitive) |
| libboost-filesystem1.83.0 | 1.83.0-4.2 | boost1.83 | Debian trixie | runtime dependency (transitive) |
| libboost-log1.83.0 | 1.83.0-4.2 | boost1.83 | Debian trixie | runtime dependency (transitive) |
| libboost-thread1.83.0 | 1.83.0-4.2 | boost1.83 | Debian trixie | runtime dependency (transitive) |
| libbz2-1.0 | 1.0.8-6 | bzip2 | Debian trixie | runtime dependency (transitive) |
| libc6 | 2.41-12+rpt1+deb13u3 | glibc | Raspberry Pi archive | C runtime |
| libcamera0.7 | 0.7.2+rpt20260817-1 | libcamera | Raspberry Pi archive | camera capture (PiSP) |
| libcap2 | 1:2.75-10+deb13u1+b1 | libcap2 | Debian trixie | runtime dependency (transitive) |
| libdrm2 | 2.4.134-3~bpo13+1+rpt1 | libdrm | Raspberry Pi archive | runtime dependency (transitive) |
| libdw1t64 | 0.192-4 | elfutils | Debian trixie | runtime dependency (transitive) |
| libelf1t64 | 0.192-4 | elfutils | Debian trixie | runtime dependency (transitive) |
| libffi8 | 3.4.8-2 | libffi | Debian trixie | runtime dependency (transitive) |
| libgcc-s1 | 14.2.0-19 | gcc-14 | Debian trixie | runtime dependency (transitive) |
| libglib2.0-0t64 | 2.84.4-3~deb13u3 | glib2.0 | Debian trixie | GStreamer runtime |
| libgmp10 | 2:6.3.0+dfsg-3 | gmp | Debian trixie | runtime dependency (transitive) |
| libgnutls30t64 | 3.8.9-3+deb13u4 | gnutls28 | Debian trixie | GStreamer/glib-networking TLS (not used by the firmware TLS paths) |
| libgstreamer-plugins-base1.0-0 | 1.26.2-1+rpt3+deb13u1 | gst-plugins-base1.0 | Raspberry Pi archive | RTP payloading / app src |
| libgstreamer1.0-0 | 1.26.2-2 | gstreamer1.0 | Debian trixie | RTSP media pipeline |
| libgstrtspserver-1.0-0 | 1.26.2-1 | gst-rtsp-server1.0 | Debian trixie | RTSPS server |
| libhogweed6t64 | 3.10.1-1 | nettle | Debian trixie | runtime dependency (transitive) |
| libidn2-0 | 2.3.8-2 | libidn2 | Debian trixie | runtime dependency (transitive) |
| libjpeg62-turbo | 1:2.1.5-4 | libjpeg-turbo | Debian trixie | JPEG snapshot |
| libjsoncpp26 | 1.9.6-3 | libjsoncpp | Debian trixie | JSON (runtime settings API, Drogon) |
| liblttng-ust-common1t64 | 2.13.9-1 | ust | Debian trixie | runtime dependency (transitive) |
| liblttng-ust1t64 | 2.13.9-1 | ust | Debian trixie | tracing (drogon/trantor build option) |
| liblzma5 | 5.8.1-1+deb13u1 | xz-utils | Debian trixie | runtime dependency (transitive) |
| libmount1 | 2.41.5-0+deb13u1 | util-linux | Debian trixie | runtime dependency (transitive) |
| libnettle8t64 | 3.10.1-1 | nettle | Debian trixie | runtime dependency (transitive) |
| libnuma1 | 2.0.19-1 | numactl | Debian trixie | runtime dependency (transitive) |
| liborc-0.4-0t64 | 1:0.4.41-1 | orc | Debian trixie | runtime dependency (transitive) |
| libp11-kit0 | 0.25.5-3 | p11-kit | Debian trixie | runtime dependency (transitive) |
| libpcre2-8-0 | 10.46-1~deb13u1 | pcre2 | Debian trixie | runtime dependency (transitive) |
| libpisp1 | 1.7.0-1 | libpisp | Raspberry Pi archive | PiSP ISP backend |
| libselinux1 | 3.8.1-1 | libselinux | Debian trixie | runtime dependency (transitive) |
| libsqlite3-0 | 3.46.1-7+deb13u1 | sqlite3 | Debian trixie | security store (users, sessions, audit) |
| libssl3t64 | 3.5.7-1~deb13u2 | openssl | Debian trixie | TLS (HTTPS, RTSPS), crypto self-test |
| libstdc++6 | 14.2.0-19 | gcc-14 | Debian trixie | C++ runtime |
| libswscale8 | 8:7.1.5-0+deb13u1+rpt2 | ffmpeg | Raspberry Pi archive | NV12 downscale (sub stream) |
| libtasn1-6 | 4.20.0-2+deb13u1 | libtasn1-6 | Debian trixie | runtime dependency (transitive) |
| libudev1 | 257.13-1~deb13u1 | systemd | Debian trixie | runtime dependency (transitive) |
| libunistring5 | 1.3-2 | libunistring | Debian trixie | runtime dependency (transitive) |
| libuuid1 | 2.41.5-0+deb13u1 | util-linux | Debian trixie | runtime dependency (transitive) |
| libva-drm2 | 2.22.0-3 | libva | Debian trixie | runtime dependency (transitive) |
| libva-x11-2 | 2.22.0-3 | libva | Debian trixie | runtime dependency (transitive) |
| libva2 | 2.22.0-3 | libva | Debian trixie | runtime dependency (transitive) |
| libvdpau1 | 1.5-3+b1 | libvdpau | Debian trixie | runtime dependency (transitive) |
| libx11-6 | 2:1.8.12-1 | libx11 | Debian trixie | runtime dependency (transitive) |
| libx11-xcb1 | 2:1.8.12-1 | libx11 | Debian trixie | runtime dependency (transitive) |
| libx264-164 | 2:0.164.3108+git31e19f9-2+b1 | x264 | Debian trixie | H.264 encode (main + sub stream) |
| libxau6 | 1:1.0.11-1 | libxau | Debian trixie | runtime dependency (transitive) |
| libxcb-dri3-0 | 1.17.0-2+b1 | libxcb | Debian trixie | runtime dependency (transitive) |
| libxcb1 | 1.17.0-2+b1 | libxcb | Debian trixie | runtime dependency (transitive) |
| libxdmcp6 | 1:1.1.5-1 | libxdmcp | Debian trixie | runtime dependency (transitive) |
| libxext6 | 2:1.3.4-1+b3 | libxext | Debian trixie | runtime dependency (transitive) |
| libxfixes3 | 1:6.0.0-2+b4 | libxfixes | Debian trixie | runtime dependency (transitive) |
| libyaml-0-2 | 0.2.5-2 | libyaml | Debian trixie | runtime dependency (transitive) |
| libyaml-cpp0.8 | 0.8.0+dfsg-7 | yaml-cpp | Debian trixie | YAML config loader |
| libzstd1 | 1.5.7+dfsg-1 | libzstd | Debian trixie | runtime dependency (transitive) |
| ocl-icd-libopencl1 | 2.3.3-1 | ocl-icd | Debian trixie | runtime dependency (transitive) |
| zlib1g | 1:1.3.dfsg+really1.3.1-1+b1 | zlib | Debian trixie | runtime dependency (transitive) |

## 2. Vendored / embedded sources (compiled into the binary)

| Component | Version | Pinned identity | Local patches | Role |
|---|---|---|---|---|
| Drogon | 1.9.0 | commit `f215cb15a0f53abd0ca7ee8b95ed8c9c3b40d262` (tree verified by `cmake/Dependencies.cmake`) | drogon-1.9.0-async-stream-response.patch, drogon-1.9.0-preserve-raw-cookie-headers.patch | HTTP/HTTPS server framework |
| Trantor | 1.5.20 | commit `79e1ffc59aa1b9c8226c2988fe2e1185e97cd795` | trantor-1.5.20-bounded-async-stream.patch | event loop / TLS transport used by Drogon |
| stb_truetype.h | 1.26 (upstream `master` copy, 2026-09-05) | SHA-256 in `sbom/firmware.cdx.json` | none | glyph rasterization for the OSD burn-in; parses only the embedded font |
| NanumGothicBold.ttf | fonts-nanum 20200506-1 (OFL-1.1) | SHA-256 in `sbom/firmware.cdx.json` | none | embedded OSD font (data, not code) |

## 3. Platform

| Component | Version | Notes |
|---|---|---|
| Linux kernel | 6.18.39+rpt-rpi-2712 | Raspberry Pi vendor kernel; image is covered by the integrity manifest |
| HailoRT | 4.24.0 | Hailo runtime + `/dev/hailo0` driver (kernel module built from `/usr/src/hailort-pcie-driver`) |
| libcamera | 0.7.2+rpt20260817-1 | Raspberry Pi fork |
| OpenSSL | 3.5.7-1~deb13u2 | Debian |

## 4. Web UI (web/)

Direct dependencies (versions as resolved in `package-lock.json`, 174 packages in total including transitive):

| Package | Version | Kind |
|---|---|---|
| @types/react | 18.3.3 | runtime |
| @types/react-dom | 18.3.0 | runtime |
| lucide-react | 0.468.0 | runtime |
| react | 18.3.1 | runtime |
| react-dom | 18.3.1 | runtime |
| react-router-dom | 7.18.3 | runtime |
| @playwright/test | 1.61.1 | dev |
| @testing-library/jest-dom | 7.0.1 | dev |
| @testing-library/react | 16.0.0 | dev |
| @testing-library/user-event | 14.5.2 | dev |
| @vitejs/plugin-react | 6.0.3 | dev |
| jsdom | 25.0.0 | dev |
| typescript | 5.5.4 | dev |
| vite | 8.1.4 | dev |
| vitest | 5.0.0 | dev |

## 5. Build toolchain

| Tool | Version |
|---|---|
| gcc | 14.2.0 |
| cmake | 3.31.6 |
| node | v20.19.2 |
| npm | 9.2.0 |
| clang-tidy / clang-format | 18 (static analysis, see TTA 10.1 record) |
