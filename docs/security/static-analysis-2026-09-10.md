# Source-weakness removal record (TTA 10.1) — 2026-09-10

Static analysis of the firmware's own C++ sources with clang-tidy 18 and a
pinned clang-format style, the findings, and what was done about each family.
The gate that keeps the tree in this state is `tools/ci/check.sh` (also run by
the pre-commit hook for formatting and by `.github/workflows/ci.yml`).

## Scope and tooling

| Item | Value |
|---|---|
| Analyzer | clang-tidy 18.1.8 (Debian `clang-tidy-18` 1:18.1.8-18+b1), configuration `.clang-tidy` |
| Formatter | clang-format 18.1.8, configuration `.clang-format` (Google, C++20, 80 columns) |
| Compile database | `compile_commands.json` from the RelWithDebInfo build (`CMAKE_EXPORT_COMPILE_COMMANDS` is now on for every build directory) |
| Analysed | the 79 product translation units under `src/`, `apps/`, `plugins/` (42,533 lines) plus every project header they include (`HeaderFilterRegex`) |
| Formatted | all 255 tracked C++ sources: `src/`, `include/`, `apps/`, `plugins/`, `tests/` |
| Not analysed | `tests/` (compiled and run, format-checked, not clang-tidy'd — the product code is the certification object), vendored sources (`vendor/`, the copied Drogon/Trantor tree), system headers |
| Baseline run | 2026-09-10, commit `a7200dc` (before this work), 33 min wall on the Pi 5 (`ServiceApp.cpp` alone 14 min) |

Check families and what they mean for the gate:

| Family | Role |
|---|---|
| `bugprone-*`, `cert-*`, `clang-analyzer-*`, `concurrency-*` | **errors** — a finding fails `tools/ci/check.sh` |
| `performance-*`, `portability-*`, `misc-*`, selected `cppcoreguidelines-*` / `modernize-*` / `readability-*` | warnings — reported, tracked here, do not fail the gate |

Two checks are disabled in `.clang-tidy`, with the reason recorded there:
`clang-analyzer-optin.core.EnumCastOutOfRange` (GLib/GStreamer flag enums are
combined with `|` and cast back — the check has no flag-enum notion) and
`performance-enum-size` (enum storage width is not a weakness and changes the
ABI of serialized types). `bugprone-empty-catch` is kept but accepts an empty
catch only when its body carries a `swallowed: <reason>` comment
(`IgnoreCatchWithKeywords`), so every deliberately ignored exception is
documented at the site.

## Baseline (before)

436 unique findings (file:line:column deduplicated across translation units),
192 of them in the error families. No compile errors.

| Check | Count | Family |
|---|---:|---|
| performance-unnecessary-value-param | 88 | warning |
| bugprone-unchecked-optional-access | 86 | error |
| performance-move-const-arg | 66 | warning |
| bugprone-empty-catch | 45 | error |
| performance-enum-size | 37 | warning (now disabled) |
| cppcoreguidelines-init-variables | 30 | warning |
| bugprone-implicit-widening-of-multiplication-result | 21 | error |
| clang-analyzer-optin.core.EnumCastOutOfRange | 8 | error (now disabled) |
| performance-unnecessary-copy-initialization | 6 | warning |
| cert-err33-c | 6 | error |
| performance-no-automatic-move | 5 | warning |
| concurrency-mt-unsafe | 5 | error |
| misc-unused-parameters | 4 | warning |
| bugprone-reserved-identifier (+ cert-dcl37-c, cert-dcl51-cpp) | 4 | error |
| bugprone-exception-escape | 4 | error |
| bugprone-suspicious-missing-comma | 3 | error |
| modernize-use-equals-delete | 2 | warning |
| misc-unused-using-decls | 2 | warning |
| misc-redundant-expression | 2 | warning |
| clang-analyzer-cplusplus.Move | 2 | error |
| cert-err52-cpp | 2 | error |
| bugprone-branch-clone | 2 | error |
| modernize-use-equals-default | 1 | warning |
| modernize-deprecated-headers | 1 | warning |
| clang-analyzer-deadcode.DeadStores | 1 | error |
| clang-analyzer-core.uninitialized.Assign | 1 | error |
| bugprone-use-after-move | 1 | error |
| bugprone-optional-value-conversion | 1 | error |

Raw baseline output: `scan-2026-09-10/clang-tidy-baseline.txt`.

## What was done (commit `0a7b00b`)

Every error-family finding was resolved in code; six sites carry a `NOLINT`
with the reason on the line, and one check was disabled (above). Nothing was
silenced by lowering the check level.

| Finding | Sites | Resolution |
|---|---:|---|
| bugprone-unchecked-optional-access | 86 | The pattern was `Result<std::optional<T>>` read through repeated `.value()` calls, which the analyzer treats as distinct optionals. Each function now binds the optional once and derives a pointer (`AuthService::Login/Verify/Logout/Reauthenticate`, 68 sites) or a reference (`RuntimeSettingsStore::Open`, `LiveMp4ByteStream`, `FragmentRing`, `AiFrameTap`, `SecuritySelfTest`, the protection worker). `FragmentedMp4Hub` / `SecureRtspServer` keep the PTS base as a plain value because `seen_keyframe` already gates it. `SystemProtectionHttp` uses `value_or` for names validated earlier. The credential CLI tests the optional itself instead of a mirror flag. |
| bugprone-empty-catch | 45 | Each block now states why the exception is swallowed (`// swallowed: ...`): noexcept teardown and destructors, GStreamer callbacks that cannot unwind, `promise::set_value` on an already-satisfied promise, external observer/callback code, best-effort cancellation. |
| bugprone-implicit-widening-of-multiplication-result | 21 | Size and time constants multiply in the target type (`std::size_t{16} * 1024U`, `std::int64_t{5} * 60`); the OSD chroma row offset is computed in `std::ptrdiff_t`. |
| clang-analyzer-optin.core.EnumCastOutOfRange | 8 | Check disabled: seven sites combine GLib/GStreamer flag enums, one casts a deliberately invalid `UserRole` in a test hook. |
| cert-err33-c | 6 | `std::signal` failures are reported; `fclose` on a read-only stream and the CLI's diagnostic `fprintf`/`fputs` are cast to `void` explicitly. |
| concurrency-mt-unsafe | 5 | The three `getenv` reads (test hooks) go through one helper with a single documented `NOLINT` — the firmware never calls `setenv`/`putenv`, which is the only unsafe combination. The two `readdir` calls carry `NOLINTNEXTLINE`: private `DIR` stream, glibc is per-stream safe, `readdir_r` is deprecated. |
| bugprone-reserved-identifier | 4 | `struct _GstCfRtspDigestAuth` etc. renamed; the `using` aliases were redundant (`G_DEFINE_FINAL_TYPE` only needs the typedef name). |
| bugprone-exception-escape | 4 | `main()` in `camera-firmware` and `camera-firmware-integrity` catch, print `E_UNHANDLED_EXCEPTION` and return failure (unwinding also runs the secret-cleansing destructors); `Result<T>::error()` reads the variant with `std::get_if`; the firmware-log outbox worker runs each poll under a catch and keeps the thread alive. |
| bugprone-suspicious-missing-comma | 3 | The three split `INSERT INTO device_state ...` migration statements became raw strings like their neighbours (the store tests capture executed statements at runtime, not literal text). |
| clang-analyzer-cplusplus.Move + bugprone-use-after-move | 3 | `AiRuntime::SubmitFrame` moved the frame inside a ternary in the loop; the last runner now receives it after the loop. |
| cert-err52-cpp | 2 | libjpeg's error model is `setjmp`/`longjmp`; both sites carry `NOLINTNEXTLINE` with that reason. |
| bugprone-branch-clone | 2 | The UTF-8 validators' two `length = 3` ranges merged into one condition (both files). |
| clang-analyzer-deadcode.DeadStores | 1 | `allocation_size` moved into the self-test `#ifdef` that uses it. |
| clang-analyzer-core.uninitialized.Assign | 1 | Analyzer artefact: it cannot see through `Result<T>::value() &&` (a `std::variant` move) and reports the default-initialised `Principal::user_id` as garbage; `NOLINT` with that note. |
| bugprone-optional-value-conversion | 1 | `PublishApplyCompletion` receives the optional itself. |

Warning-family findings fixed on the way: unused `using` declarations (2),
unused GStreamer callback parameters (4, left unnamed), deleted copy operations
made public (2), a trivial copy constructor defaulted (1), `<setjmp.h>` →
`<csetjmp>` (1).

## After

Final run on the reformatted tree (commit `a0e68e1`,
`tools/ci/check.sh`, all stages): **0** error-family findings,
197 warnings.

| Check | Count |
|---|---:|
| performance-unnecessary-value-param | 88 |
| performance-move-const-arg | 66 |
| cppcoreguidelines-init-variables | 30 |
| performance-unnecessary-copy-initialization | 6 |
| performance-no-automatic-move | 5 |
| misc-redundant-expression | 2 |

The remaining warnings are style/performance advice (by-value parameters that
could be references, `std::move` on trivially copyable values, uninitialised
declarations that are assigned before use, one intentional double bind of a
cursor value). They stay visible in every `check.sh` run and are candidates for
the next pass; none is a memory-safety, lifetime, or concurrency weakness.

Suppressions in the tree after this work: 6 `NOLINT` markers,
each with its reason on the same or the preceding line.

## Formatting

`clang-format --dry-run --Werror` reported 219 of 255 files off the pinned
style before the reformat (9,387 replacements; ~19,600 lines touched, all
line-wrapping and initializer-list layout — the code base was already 80-column
Google style). The one-time reformat is commit `bb7c43f`, listed in
`.git-blame-ignore-revs`; `tools/ci/install-hooks.sh` sets
`blame.ignoreRevsFile` so `git blame` skips it.

## Verification

- `tools/ci/check.sh` on the final tree: format ok, clang-tidy ok (0 error-family
  findings), C++ build, `ctest` 1331/1331 passed, web suite (vitest 739/739 passed) and
  `npm run build`.
- Three things the gate run surfaced that were not visible before it existed, all
  fixed on the branch: vitest 5 had silently broken the jest-dom matcher types
  (`npm run build` and therefore the firmware target failed; jest-dom 7.0.1); the
  web suite's 1 s Testing Library default timed out once under `ctest -j2` load
  next to the C++ tests (raised to 5 s in `web/vitest.setup.ts`, assertions
  unchanged); and `AppConfigTest`'s inline-config helper named its temp file from
  a per-process counter, so concurrently running test processes clobbered each
  other's `/tmp/cf-app-config-0.yaml` (4 failures in 60 rounds at `-j4`; the pid
  is now part of the name, 0 in 100 rounds).
- The same gate was re-run with the apt-installed `clang-format-18` /
  `clang-tidy-18` 1:18.1.8-18+b1 after the tool installation: identical result.

## Re-running

```bash
sudo apt install clang-format-18 clang-tidy-18
tools/ci/install-hooks.sh          # once per clone: pre-commit format gate
tools/ci/check.sh --lint           # format + clang-tidy (≈35 min on the Pi 5)
tools/ci/check.sh                  # + C++ build/tests + web tests/build
```

Set `CF_CI_BUILD_DIR` to reuse an existing build directory instead of
`build-ci/`; `CAMERA_FIRMWARE_DROGON_SOURCE_DIR` / `..._TRANTOR_SOURCE_DIR`
must point at the pinned checkouts when the directory is configured for the
first time.
