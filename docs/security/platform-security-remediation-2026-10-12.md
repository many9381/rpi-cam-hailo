# Platform security follow-up — 2026-10-12

This record covers curl, the Raspberry Pi kernel and Raspberry Pi FFmpeg in
`meta-rpi5-cam`. Build and device evidence below are separate: testing a library
in an isolated directory does not validate booting a newly built kernel.
The preceding installed image remains described by
[OpenSSH deployment validation](openssh-deployment-validation-2026-10-12.md).

## Layer changes

| Component | Previous source | New source |
| --- | --- | --- |
| curl / libcurl | 8.19.0 | 8.22.0, official signed release |
| Raspberry Pi FFmpeg | actual 7.1.3, incorrectly labelled 7.1.13 | 7.1.5 with Pi patch 29 and 21 upstream security backports |
| Raspberry Pi kernel | 6.18.33 | Pi 6.18.55 with one additional stable IPv4 lifetime fix |

curl's tarball SHA256 is
`f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7`.
Its detached signature passed verification with the
[published release key](https://curl.se/docs/verify.html), fingerprint
`27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2`. The inherited CVE-2026-6276,
CVE-2026-5773 and mbedTLS backports are already in the new source and were
removed. The target ptest timeout remains 600 seconds. The removed librtmp
configure option caused a real build failure and was removed from PACKAGECONFIG;
QA checks were retained. The final image installs libcurl, while the isolated
tests also use the CLI produced by the same recipe.

The FFmpeg source pin is
`2fe08f3bd52c6e795df8353d29deb89596b5099d` on `pios/trixie`.
`PV` and `CVE_VERSION` are both 7.1.5; package epoch 1 ensures that this correction
is an upgrade from the erroneous 7.1.13 package label. Keep the epoch in future
updates. All library ABI majors remain unchanged. The Pi patch's original body
SHA256 is `4178f3c4e1983c38215da8bd85134e1b7ea3e34807718481f927dfebeaa438dd`;
the local copy adds only a provenance/Upstream-Status header. Existing OE
configuration and OMX patches still apply. The LGPL 2.1 checksum change was
verified byte-for-byte as removal of nine form-feed characters only; license
text and the other three checked license files are unchanged. [Pi source](https://github.com/RPi-Distro/ffmpeg/commit/2fe08f3bd52c6e795df8353d29deb89596b5099d),
[upstream release history](https://ffmpeg.org/download.html).

The following exact upstream fixes are applied after the Pi/OE patches:

| CVE | Upstream fix |
| --- | --- |
| CVE-2026-64830 | [dbd495f066a8](https://github.com/FFmpeg/FFmpeg/commit/dbd495f066a85ba96b17433f4306582aa37c3951) |
| CVE-2026-64835 | [1836ef968469](https://github.com/FFmpeg/FFmpeg/commit/1836ef96846937a6cc2443698a693104f5c0b21e) |
| CVE-2026-65703 | [fd3ee52fab34](https://github.com/FFmpeg/FFmpeg/commit/fd3ee52fab34d98a95b787d0b5ff45685766200c) |
| CVE-2026-65704 | [de771bd52774](https://github.com/FFmpeg/FFmpeg/commit/de771bd52774a52d45b0e2c82e56995a1ef40df7) |
| CVE-2026-66039 | [aafb5c655edc](https://github.com/FFmpeg/FFmpeg/commit/aafb5c655edc76a753275c383ebb139feb032718) |
| CVE-2026-70628 | [93f2a525ec6c](https://github.com/FFmpeg/FFmpeg/commit/93f2a525ec6c7b467bae68322720d10188fc6e30) |
| CVE-2026-70632 | [db05df9d135f](https://github.com/FFmpeg/FFmpeg/commit/db05df9d135fb56a4babb836d5e9f5c1d984e087) |
| CVE-2026-75141 | [acf5d7cdc1f9](https://github.com/FFmpeg/FFmpeg/commit/acf5d7cdc1f9ae8752c23e1ea8d7f355ed780781) |
| CVE-2026-75142 | [9d786e4b5e9b](https://github.com/FFmpeg/FFmpeg/commit/9d786e4b5e9b8482651928574de33772aeee7be1) |
| CVE-2026-75144 | [1cdeb3c4e7f1](https://github.com/FFmpeg/FFmpeg/commit/1cdeb3c4e7f1f8566d846b9b451e01c376398818) |
| CVE-2026-65706 | [a7e38b617b32](https://github.com/FFmpeg/FFmpeg/commit/a7e38b617b32f996beaa371bbf04b39907d7a527) |
| CVE-2026-107676 | [2c2f6e96e317](https://github.com/FFmpeg/FFmpeg/commit/2c2f6e96e31795ae95a8f8323a493ffbc493111f) |
| CVE-2026-107695 | [a4ddaba8bb78](https://github.com/FFmpeg/FFmpeg/commit/a4ddaba8bb7811b1a3afaad59fe6555e720d4754) |
| CVE-2026-107697 | [23602df9cd1b](https://github.com/FFmpeg/FFmpeg/commit/23602df9cd1b485c45ba6f533d3b85569de3f323) |
| CVE-2026-64833 | [6f80e2765492](https://github.com/FFmpeg/FFmpeg/commit/6f80e2765492700622596af720534cef33dd31b4) |
| CVE-2026-64834 | [11d5f475be95](https://github.com/FFmpeg/FFmpeg/commit/11d5f475be95d22d5f0692220cc772b116abc632) |
| CVE-2026-66037 | [86708357d126](https://github.com/FFmpeg/FFmpeg/commit/86708357d126af84c16f80d9c57335d1e8c845c5) |
| CVE-2026-66038 | [e7cbfd1c507b](https://github.com/FFmpeg/FFmpeg/commit/e7cbfd1c507b57a806a5825b87d609963e862c8c) |
| CVE-2026-70629 | [cd1f545cf27b](https://github.com/FFmpeg/FFmpeg/commit/cd1f545cf27ba08f6f5b31b1e92665d7874d4fd7) |
| CVE-2026-70630 | [705890061467](https://github.com/FFmpeg/FFmpeg/commit/705890061467ad550ecc1dad5eea07f28ccfb43e) |
| CVE-2026-70631 | [2f234ea34c81](https://github.com/FFmpeg/FFmpeg/commit/2f234ea34c81288e3840fca632dd16481d8de39f) |

Independent review also found a new double-close on the Pi patch's DRM device
creation failure path. A separate local patch leaves descriptor ownership with
the already registered cleanup callback. It is not assigned a CVE. The bounded
regression executes the exact create/free function bodies with real descriptors
and forced ioctl failure. Before the fix, two closes invalidate a reused
canary descriptor; after the fix, cleanup closes once and preserves it. This is
an isolated error-path test, not a full DRM driver test.

The additional review found a detached-segment leak in 7.1's HLS reload
failure path reached by the new master-tag rejection. A second local patch
moves old-segment cleanup to the common exit. A regression executes the exact
production ownership blocks with real allocations: rejected reload leaked
seven allocations before the fix; normal reload, both rejected tags, failure
before detachment and empty reload pass after it. This fixture models parser
control flow and does not claim full malformed-playlist coverage.

The kernel pin is `4103a989a46196239b830bd07693277e42b8f992` on `rpi-6.18.y`.
The original `yocto-6.18` kernel metadata pin is retained. This Pi branch pin is
newer than the observed `stable_20260911` tag; source ancestry does not substitute
for hardware validation. The complete upstream stable release was 6.18.56 on
2026-10-11. Its narrow IPv4 fix
[`a47406c769f7`](https://github.com/gregkh/linux/commit/a47406c769f72c070386985488f1c4d057df86b2)
is backported because the Pi source still frees shared IP options before the
RCU grace period. The resulting kernel remains labelled 6.18.55: it is not all
of 6.18.56. [Pinned Pi source](https://github.com/raspberrypi/linux/commit/4103a989a46196239b830bd07693277e42b8f992),
[6.18.56 changelog](https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18.56).

The integrated rebuild exposed an existing Codex packaging omission: the
bundled `rg` is dynamically linked against glibc/libgcc, while only the Codex
CLI and its other bundled helpers are static musl binaries. The real
`do_package_qa` rejected thirteen unprovided library requirements. Explicit
`glibc libgcc` runtime dependencies were added without suppressing file-rdeps
QA or changing the upstream binaries. The failed image attempt
`20261012T023656Z-e664cb9647e7` is retained as evidence; the corrected recipe
requires a fresh final-image input snapshot.

## Assessment boundaries

The baseline scan's 4,635 kernel, 58 FFmpeg and 33 curl associations are version
matches, not demonstrated exploit counts. Raw reports are retained unchanged.
The repeat image scan uses the same pinned 2026-10-11 NVD/CVEList snapshots for
comparison; upstream release/advisory/source checks were performed on
2026-10-12. This is not a claim that the entire CVE database was refreshed today.

All 33 original curl candidates have official advisories identifying fixed
versions at or before 8.22.0. The runtime regression covers
[CVE-2026-80255](https://curl.se/docs/CVE-2026-80255.html): a TAB preceding Secure
must not cause a cookie to be sent on plaintext HTTP. This targeted regression
is separate from the other 32 source/version assessments.

Of the original 58 FFmpeg candidates, 17 are source-fixed by the existing code
or 7.1.5, six concern absent implementations, seven concern disabled optional
components, two concern the uninstalled zmqsend developer tool, twenty-one receive
the listed patches, and five remain unresolved. Configuration exclusions
must be rechecked against the final build and are not blanket distro-wide
CVE_STATUS suppressions. The corrected version also exposes an old false
negative: CVE-2026-107698 was labelled fixed by a 7.1.13 comparison even though
the 7.1.3 source lacked the RTSP protocol check; 7.1.5 includes that fix.

Kernel source checks confirm new fixes for CVE-2026-74705, CVE-2026-72421,
CVE-2026-74612, CVE-2026-74475, CVE-2026-63795 and CVE-2026-93207. Two old raw
candidates, CVE-2023-1073 and CVE-2022-3636, were already fixed in the original
source. Disabled subsystem examples and same-series CNA fixed-version matches
help prioritize the rest, but do not clear every kernel finding or establish
that every compiled module is installed, loaded or externally reachable.

## Remaining FFmpeg source work

These five original candidates are not cleared by this change:

| Candidate | Remaining work |
| --- | --- |
| CVE-2026-107678 | MOV encryption-initialization recursion: upstream PR 24593 was still open when checked; no merged fix claimed |
| CVE-2026-107696 | RTSP redirect-count limit: merged fix requires a reviewed 7.1 context backport |
| CVE-2026-58049 | RASC decoder bounds: primary record does not identify an exact fixing commit |
| CVE-2026-65705 | Floodfill dynamic size: assess the allocation fix and prerequisite series; cited tip alone is insufficient |
| CVE-2026-66036 | hqdn3d dynamic size: assess the parameter-change and filter-core prerequisite series |

This list reconciles the original candidates. It is not a promise that a future
scan or newly disclosed issue cannot add findings.

## Validation

The host suite passed all 365 tests. Exact-function DRM cleanup and exact-block
HLS ownership regressions failed before their respective fixes and passed after
them. These small fixtures do not replace full FFmpeg FATE/fuzz coverage.

The old curl package reproduced the Secure-cookie error; the isolated 8.22.0
package passed. Control cases verify both cookies arrive over HTTPS and that
untrusted certificates and the wrong hostname fail with curl exit code 60.
The one libcurl ABI comparison found no removed exported symbols. The test CLI
and library versions were both checked. This did not replace the running Pi's
system libcurl, restart the app or reboot the device.

The final FFmpeg source passes reverse application checks for all 21 upstream
backports and both cleanup fixtures. Eight shared-library comparisons found no
removed exported symbols. On the Pi, the isolated 7.1.5 package passed:

- Ten synthetic H.264 frames through MP4 encoding/decoding, plus JPEG output
  and decoding, without taking control of the camera sensor.
- A bounded VobSub fixture reuses two stream IDs rather than creating three
  streams as the old package did.
- An HLS master tag in a media playlist is rejected after two HTTP requests;
  the old package continued until the fixture's ninth request returned 404.
- The real `av_hwdevice_ctx_create()` DRM failure path closes once and preserves
  the descriptor reused by the test canary.

These tests ran on the existing image `20261011T190155Z-e664cb9647e7` with
isolated binaries and libraries. The private target directory was removed;
boot ID, app PID and restart count were unchanged, and pinned HTTPS and setup
state remained healthy. No full FFmpeg FATE or curl ptest execution is claimed.

The built Hailo PCIe module reports `6.18.55-v8-16k` vermagic matching the new
kernel. Twelve critical kernel configuration checks passed. Neither establishes
that the new kernel has booted or that the driver has loaded on hardware.

Final image **`20261012T031641Z-e664cb9647e7`**, profile
`rpi5-camera-hailo`, completed all 7,786 tasks; 7,236 reused existing results.
The corrected Codex package passed the actual file-rdeps QA. Build input
provenance covers all 30 changed layer files, including that dependency fix.
The compressed WIC SHA256 is
`a0246039daaa88cc80c2f3c671fac01b6c69fda706f3378667a28b031e8732b6`.
No QEMU/minimal image was built or booted.

All checksums and source provenance passed. The actual WIC contains the tested
libcurl and eight FFmpeg libraries, the expected FFmpeg tools, and the new
kernel. Seven camera/fan/Wi-Fi/Hailo modules match its `6.18.55-v8-16k` vermagic
and match the rootfs byte-for-byte. OpenSSH binaries still match the previous
tested packages; RTSP source/patch identity and tested GStreamer library build
ID are preserved. Camera/Wi-Fi configuration, clock/service ordering, Codex
package layout, absence of baked credentials/TLS keys and the development
checkout checks all pass. The image has 453 installed packages.

A stale libcamera packagedata cache reported a version rollback; the real
packagedata task succeeded without relaxing QA. The installed manifest still
reports `0.6.0+rpt20251202`, and both libcamera shared libraries in the final WIC
match the functioning Pi byte-for-byte. An initial verification-harness
expectation incorrectly used the source-suffixed intermediate pkgdata version;
it was corrected to the installed manifest version while retaining binary
identity checks. Those logs are preserved.

The host suite passed all 365 tests again after the build (92.650 seconds).
One intermediate run under build load exceeded a test's five-second wall-clock
limit: `test_launcher_reports_immediate_qemu_exit_without_guest_timeout` took
7.448 seconds. Its unchanged standalone retry passed in 1.153 seconds and the
final full suite passed. This is a host fixture with a fake launcher, not a
QEMU image build or guest run; the failure and retry are retained.

## Final scan and remaining work

The final SPDX adapter and exact installed-package selection checks pass.
Raw unresolved associations changed as follows using the same database snapshots:

| Scope | Previous image | Final image |
| --- | ---: | ---: |
| All installed recipes | 4,825 | 539 |
| Kernel | 4,635 | 403 |
| Non-kernel | 190 | 136 |
| curl | 33 | 0 |
| FFmpeg | 58 | 37 |

The 37 raw FFmpeg rows reconcile to 17 already/source-fixed candidates, six
absent implementations, seven disabled components, two uninstalled-tool issues
and the five unresolved candidates listed above. The 21 applied backports are
no longer raw unresolved findings. The raw CSV is unchanged by this assessment;
configuration exclusions are verified against the final generated headers.
Kernel's 403 and other recipes' remaining raw associations still require
source/configuration review. **This is not a whole-image security PASS.**

Evidence is under
`artifacts/20261012T031641Z-e664cb9647e7/rpi5-camera-hailo/security/`:
`host-image-verification.json`, `cve-scan/`, `scanner-evidence/`,
`configuration-evidence/` and the curated
`platform-security-2026-10-12/` directory with `SHA256SUMS`. Evidence excludes
private test keys, user credentials, full source trees and copied test binaries.

At build completion the operating Pi was still on its previous validated image.
The later [2026-10-12 deployment validation](platform-deployment-validation-2026-10-12.md)
confirms installation of this image, the running 6.18.55-v8-16k kernel and seven
loaded matching modules, 34 installed file identities, system FFmpeg media
checks, three Wi-Fi reboots, fan/Codex health and user-confirmed camera/Hailo
inference. This closes that deployment acceptance; the remaining security
findings above and long-duration validation are separate work.
