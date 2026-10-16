# Selective static-warning review — 2026-10-16

Ten of the 208 warnings in the [October 15 source gate](static-analysis-2026-10-15.md)
were removed by reducing intermediate copies while preserving ownership and
error handling. The final working sources have **0 clang-tidy errors and 198
warnings**. This is a bounded source-quality change, not a vulnerability scan
or a measured frame-rate improvement.

Layer patch `0010-avoid-intermediate-metadata-and-error-copies.patch` is
registered for `camera-firmware` and `rpi-cam-hailo-devrepo`. At source-review
completion, no new image had been built or installed. The subsequent
[image build and verification](static-warning-image-2026-10-16.md) completed
for `20261016T111625Z-e664cb9647e7`. Its subsequent installation and hardware
acceptance also passed; see the
[deployment report](static-warning-deployment-validation-2026-10-16.md).
The source-review checks below ran before those build/deployment stages, while
the Pi was still on `20261015T204138Z-e664cb9647e7`.

## Changes and retained ownership

| Change | Removed warnings | Lifetime/behavior boundary |
|---|---:|---|
| AI frame metadata local reference | 1 | The asynchronous completion lambda still owns its metadata snapshot by value; the input frame lease retains ownership during preprocessing |
| Camera requeue weak pointer by const reference | 1 | The callback retains its weak pointer; the synchronous helper immediately locks it into shared ownership |
| Owned validation/build errors borrowed locally | 3 | Password validation and normalized runtime factory errors are owned by their local Results; returned diagnostics still own their values |
| Return local Results without `const` | 5 | Enables implicit move on return in runtime validation, fMP4 startup and settings validation; validation order and error values are preserved |

Initial review rejected two further copy removals in runtime startup and
durable-promotion failure handling. These callbacks can return
`ErrFromStaticLifetime`, which promises static storage duration, not immutable
error contents. Cleanup or restarting the previous runtime may update that
storage. The original value copies preserve the failed operation's diagnostic
across those callbacks and are deliberately retained, with explanatory comments.

Two new regressions exercise the real runtime replacement orchestration with
injected device dependencies. Both failed with the proposed references: the
returned original error was replaced by the recovery diagnostic. Both pass
with the retained snapshots. This caught an issue in the proposed optimization;
it does not identify a bug in the previously installed code. Independent review
also checked the asynchronous capture and remaining reference lifetimes.

## Remaining warnings

| Check | Before | After | Disposition |
|---|---:|---:|---|
| `performance-unnecessary-value-param` | 90 | 89 | One synchronous weak-pointer copy removed; other ownership/callback boundaries or cold helpers deferred |
| `performance-move-const-arg` | 70 | 70 | No-op moves into const-reference/trivial-value APIs; no runtime benefit established from deleting them |
| `cppcoreguidelines-init-variables` | 30 | 30 | Reviewed paths assign before reads: syscall retry loops, SQLite loop conditions and locked state snapshots |
| `performance-unnecessary-copy-initialization` | 6 | 2 | Four intermediate copies removed; two rollback error snapshots required |
| `performance-no-automatic-move` | 5 | 0 | Local Result returns corrected |
| `readability-braces-around-statements` | 5 | 5 | Style-only follow-up deferred |
| `misc-redundant-expression` | 2 | 2 | Both SQLite binds are required: `parameter++` advances to separate cursor placeholders |
| **Total** | **208** | **198** | No warning suppressions or check-policy changes |

The remaining entries are not counted as resolved. The per-finding decisions
use the original baseline locations; final diagnostics use the updated locations.
Changes across ownership boundaries require their own behavior and lifetime
review rather than a blanket automatic fix.

## Verification

| Check | Result |
|---|---|
| clang-format 18.1.3 | Repository C++ format gate PASS |
| clang-tidy 18.1.3 | All 79 product translation units; 0 errors / 198 unique warnings |
| Yocto AArch64 cross-build | Seven changed production units and selected tests compile/link using the existing target sysroot and production libraries |
| Before-change selected target suite | 359 PASS |
| Rejected-reference negative control | Two new error-snapshot tests fail for the expected changed diagnostic |
| Final selected target suite | 361 PASS, 0 failures, including both new regressions |
| Host firmware packaging tests | 25 PASS |
| Recipe patch application | Both complete registered series apply to the pinned source; all eight changed source/test files match the tested working tree |

The target suite covers AI processing/buffers, frame leases, camera config,
fMP4, runtime replacement/recovery, settings, user management, security storage
and TLS management. One selected test that initializes the actual Hailo device
is explicitly excluded to avoid competing with operating inference. Tests use
injected camera/AI dependencies where appropriate; this is not new hardware
capture or Hailo acceptance. The previous full CTest/web results are historical
evidence and were not rerun or counted as fresh passes here.

The harness links newly compiled objects for all seven changed production
units with the existing Yocto static libraries and target shared libraries.
It enables the actual Hailo build path (`CF_HAVE_HAILORT=1`) and uses GTest
1.13.0. Tests run from a private temporary directory on the Pi via pinned SSH.
No QEMU, complete image build, service restart or configuration migration was
performed. The production boot and service PID stayed unchanged. Temporary
target tests and this task's local compiled harness were removed after recording
their results and hashes.

The existing `.clang-tidy` policy remains unchanged: `bugprone-*`, `cert-*`,
`clang-analyzer-*` and `concurrency-*` fail the gate. All 79 units were scanned;
after retaining the two error snapshots, that changed unit was rescanned and
all recorded source hashes were checked against the final working tree.

The layer uses pinned source `ba503a1fbc4ed68c1fd29aace7214a5c330d7021`.
Both firmware and development-checkout patch sequences include the regressions.
No web recipe change is needed for this C++ delta. Accounts, authentication
policy, database schema, TLS settings and MOV parsing are outside this change.

## Evidence

Public evidence is in [`scan-2026-10-16-static-warning-review/verification.json`](scan-2026-10-16-static-warning-review/verification.json),
with [final diagnostics](scan-2026-10-16-static-warning-review/static-analysis.json),
[baseline warning dispositions](scan-2026-10-16-static-warning-review/triage.json),
[translation-unit results](scan-2026-10-16-static-warning-review/translation-units.json),
[source hashes](scan-2026-10-16-static-warning-review/source-sha256.json) and
[patch-chain verification](scan-2026-10-16-static-warning-review/patch-validation.json).

Raw logs, test XML, the rejected-change negative control and the cross-build
harness remain in Git-ignored `.state/static-warning-review-2026-10-16/` in the
parent workspace. Public evidence contains no credentials or session files.
