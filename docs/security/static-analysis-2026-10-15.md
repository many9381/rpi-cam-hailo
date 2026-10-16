# Firmware quality gate — 2026-10-15

The current working sources passed formatting, product-source static analysis,
the complete CMake test suite (with the explicit hardware exclusions below),
and web tests/build. This updates the source-quality evidence; it is not a new
vulnerability scan or acceptance of a newly built SSD image.

Subsequent image build and verification are recorded in
[quality-gate-image-2026-10-15.md](quality-gate-image-2026-10-15.md). Statements
below about the next build describe the boundary at source-gate completion.

## Results

| Check | Result |
|---|---|
| clang-format 18.1.3 | 257 existing tracked/non-ignored new C++ files; PASS |
| Gate regression tests | 8 PASS, using the real formatter and temporary Git repositories |
| clang-tidy 18.1.3 | All 79 product translation units; 0 errors, 208 unique warnings |
| C++ build | Complete original CMake project, all targets, Yocto AArch64 compiler/sysroot; PASS |
| CTest | 1,366 discovered: 1,356 PASS, 10 explicitly skipped, 0 failures |
| Web | 56 files / 770 tests PASS; TypeScript and Vite production build PASS |
| Yocto host suite | 372 PASS; 10 affected packaging/development-repository tests rerun after recipe changes, PASS |
| Layer patch application | Complete registered series applied to the pinned source for all three recipes; all six changed files match the tested working sources |

The ten skipped tests are one system-protection hardware test, two Hailo
hardware tests and seven camera hardware tests. They are opt-in tests that
would compete with the operating camera. They are not counted as passes.
Existing installed-image hardware acceptance remains documented in
[the capture-health deployment record](camera-capture-health-deployment-validation-2026-10-15.md).

## Corrections

`tools/ci/check.sh` previously selected only tracked files. It now includes
non-ignored new sources and excludes removed files, preserving filenames with
spaces or newlines using NUL separators. The default and lint modes run the
new gate regression suite. The format-only hook remains format-only.

The regressions exercise tracked and untracked formatting failures, ignored
generated files, deleted tracked files, unusual filenames, missing formatter
failure, and relative tool paths. The tests fail on the original selection
logic. Missing tools produce a failure rather than a skipped success. Two
existing C++ files needed formatting; those edits have no behavioral effect.

The first complete target test run exposed an actual bootstrap validation
failure: the target GLib accepts `fe80::1%eth0`, then serializes it without the
interface suffix. Comparing that result with `fe80::1` accepted input that
the existing plain-address contract intended to reject. `NormalizePeerIp`
now rejects `%` before parsing either peer. The existing test was extended to
cover scoped actual peers, both peers scoped, and an empty suffix. The failure
was reproduced with the old implementation and the extended test, then passed
with the correction. Plain IPv4/IPv6 normalization, optional management-IP
policy, accounts and database format are unchanged by this correction.

Two other initial failures were test-environment issues: a source snapshot
without Git metadata, and a host OpenSSL executable loading incompatible
private host libraries. An empty Git repository in the temporary target copy
and an explicit host OpenSSL selection corrected these. The final complete
suite was rerun, not just the initially failing tests.

## Static-analysis boundary and remaining warnings

The existing `.clang-tidy` checks, exclusions and error families were retained:
`bugprone-*`, `cert-*`, `clang-analyzer-*` and `concurrency-*` fail the gate.
An intentional assignment-in-condition negative control confirmed that an
error-family finding still fails. No new suppression was added.

| Warning check | Unique findings |
|---|---:|
| performance-unnecessary-value-param | 90 |
| performance-move-const-arg | 70 |
| cppcoreguidelines-init-variables | 30 |
| performance-unnecessary-copy-initialization | 6 |
| performance-no-automatic-move | 5 |
| readability-braces-around-statements | 5 |
| misc-redundant-expression | 2 |

These 208 findings remain warnings, not resolved findings. Counts are
deduplicated by source location and check. Tests are format-checked, compiled
and run, but are outside the product clang-tidy scope. Vendored/system code is
also outside that scope. This result does not establish absence of defects.

The analysis database was derived from the existing Hailo Yocto recipe, with
current working source paths, the AArch64 target, GCC 15.3 C++ include paths,
and Clang 18 resource headers. The GCC-only `-fcanon-prefix-map` flag was
removed for Clang, and sysroot includes were marked as system includes. An
initial incompatible include setup was discarded. All 79 units completed
with the corrected setup; BootstrapService was checked again after its fix.

## Execution and layer integration

The full application and test targets were built from a separate source copy
using the existing Yocto sysroot, GTest 1.13.0 and the pinned Drogon/Trantor
sources. The Hailo implementation was compiled against the actual HailoRT
library (`CF_HAVE_HAILORT=1`). Test builds used `-O1 -g0`; these are not the
production image binaries. CTest used a pinned SSH runner for AArch64 tests
on the Pi and host execution for the CMake/web tests. No QEMU or image build
was run. All build/test/web input hashes matched the working sources.

Layer patch `0009-quality-gate-and-plain-bootstrap-peers.patch` is registered
for `camera-firmware`, `camera-firmware-web` and `rpi-cam-hailo-devrepo`.
The firmware recipe now also applies existing patch `0007` before `0008` and
`0009`, so its source includes the same idle/clock-step login regression that
`0009` formats. That existing patch changes test/web files only; firmware
still uses `CF_BUILD_WEB=OFF`. The development repository applies its patches
at installation time, retaining the upstream commit/history.

Each complete patch series was checked against pinned revision
`ba503a1fbc4ed68c1fd29aace7214a5c330d7021`. This checks application and source
identity, not a fresh BitBake image build. **The bootstrap correction is ready
for the next image build; it has not been installed into the production Pi.**

The Pi remained on image `20261015T185424Z-e664cb9647e7`, with the same boot,
production service PID 307, zero service restarts, and an HTTPS 200 response
after testing. The isolated target test tree was removed. No operating
account, TLS certificate or app configuration was changed. Independent review
found no remaining critical or important issue in the changes or layer series.

## Evidence

Public results and hashes are in
[`scan-2026-10-15-quality-gate/verification.json`](scan-2026-10-15-quality-gate/verification.json),
with the full warning list in
[`static-analysis.json`](scan-2026-10-15-quality-gate/static-analysis.json),
per-unit analysis results in
[`translation-units.json`](scan-2026-10-15-quality-gate/translation-units.json),
and tested input hashes in
[`source-sha256.json`](scan-2026-10-15-quality-gate/source-sha256.json).

Raw build/test logs, the initial failing runs, final CTest XML, tool package
hashes, cross-execution scripts and private device checks remain in the parent
workspace's Git-ignored `.state/quality-gate-2026-10-15/`. The public verification
record lists the relevant log hashes. It contains no credentials or session
files. The single-machine gate remains `tools/ci/check.sh`; this cross-host
validation ran its stages explicitly to use the existing Yocto sysroot and Pi.
