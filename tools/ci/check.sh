#!/usr/bin/env bash
# Repository quality gate (TTA 10.1). The same checks run locally, in the
# pre-commit hook (format only) and in CI:
#
#   tools/ci/check.sh            format + clang-tidy + C++ build/tests + web tests/build
#   tools/ci/check.sh --lint     format + clang-tidy only
#   tools/ci/check.sh --format   format only
#
# Requirements: clang-format and clang-tidy 18 or newer (Debian: apt install
# clang-format-18 clang-tidy-18), the firmware build dependencies, and
# node/npm for the web. Tool binaries come from CLANG_FORMAT / CLANG_TIDY when
# set, else clang-format-18 / clang-tidy-18, else the unsuffixed name when it
# is version 18 or newer.
#
# The C++ steps use build-ci/ (configured on first run with tests; the root
# CMakeLists always writes compile_commands.json). The vendored Drogon/Trantor
# sources are pinned by cmake/Dependencies.cmake, so
# CAMERA_FIRMWARE_DROGON_SOURCE_DIR and CAMERA_FIRMWARE_TRANTOR_SOURCE_DIR must
# point at the exact checkouts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
MODE="${1:-all}"
BUILD_DIR="${CF_CI_BUILD_DIR:-$ROOT/build-ci}"
JOBS="${JOBS:-$(nproc)}"

# Every enabled clang-tidy check fails the gate: the tree carries zero
# findings since the 2026-09-10 warning pass, so any new one is a regression.
TIDY_ERRORS='*'

resolve_tool() {  # resolve_tool <name> <override>
  local name="$1" override="$2" candidate major
  if [ -n "$override" ]; then
    echo "$override"
    return
  fi
  for candidate in "$name-18" "$name"; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    major=$("$candidate" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
    if [ "${major:-0}" -ge 18 ]; then
      echo "$candidate"
      return
    fi
  done
  echo "$name 18 or newer not found (apt install $name-18)" >&2
  exit 1
}
CLANG_FORMAT="$(resolve_tool clang-format "${CLANG_FORMAT:-}")"
CLANG_TIDY="$(resolve_tool clang-tidy "${CLANG_TIDY:-}")"

# Tracked C++ sources. A git pathspec '*' matches across directory levels.
sources() {
  git ls-files -- 'src/*.cpp' 'src/*.hpp' 'include/*.hpp' 'apps/*.cpp' 'apps/*.hpp' \
    'plugins/*.cpp' 'plugins/*.hpp' 'tests/*.cpp' 'tests/*.hpp'
}
# clang-tidy analyses the product translation units. Tests are format-checked
# and compiled but not analysed (docs/security/static-analysis-2026-09-10.md).
tidy_sources() { sources | grep -E '^(src|apps|plugins)/.*\.cpp$'; }

step() { printf '\n== %s ==\n' "$1"; }

step "clang-format ($CLANG_FORMAT, dry run, deviations are errors)"
sources | xargs -r "$CLANG_FORMAT" --dry-run --Werror
echo "format: ok"
[ "$MODE" = "--format" ] && exit 0

step "configure $BUILD_DIR"
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  cmake -S "$ROOT" -B "$BUILD_DIR" -DBUILD_TESTING=ON \
    ${CAMERA_FIRMWARE_DROGON_SOURCE_DIR:+-DCAMERA_FIRMWARE_DROGON_SOURCE_DIR="$CAMERA_FIRMWARE_DROGON_SOURCE_DIR"} \
    ${CAMERA_FIRMWARE_TRANTOR_SOURCE_DIR:+-DCAMERA_FIRMWARE_TRANTOR_SOURCE_DIR="$CAMERA_FIRMWARE_TRANTOR_SOURCE_DIR"}
fi
[ -f "$BUILD_DIR/compile_commands.json" ] || { echo "no compile_commands.json in $BUILD_DIR" >&2; exit 1; }

step "clang-tidy ($CLANG_TIDY, -j$JOBS; errors: $TIDY_ERRORS)"
# Generated headers are needed for a complete analysis: build the libraries first.
cmake --build "$BUILD_DIR" -j"$JOBS" --target camera_firmware_common camera_firmware_config \
  camera_firmware_settings camera_firmware_security camera_firmware_media camera_firmware_rtsp \
  camera_firmware_ai camera_firmware_service >/dev/null
TIDY_OUT="$(mktemp -d)"
trap 'rm -rf "$TIDY_OUT"' EXIT
# One clang-tidy process per file, JOBS at a time. Each file's output goes to
# its own log so the report is not interleaved; a non-zero exit (an error-level
# finding or a compile error) records the file in "failed".
tidy_sources | xargs -r -P "$JOBS" -I{} sh -c \
  '"$1" -p "$2" --quiet --warnings-as-errors="$3" "$4" > "$5/$(echo "$4" | tr / _).log" 2>&1 || echo "$4" >> "$5/failed"' \
  _ "$CLANG_TIDY" "$BUILD_DIR" "$TIDY_ERRORS" {} "$TIDY_OUT"
cat "$TIDY_OUT"/*.log 2>/dev/null \
  | grep -vE '^[0-9]+ (warnings?|errors?)( and [0-9]+ (warnings?|errors?))? generated\.$|^Suppressed [0-9]+ warnings|^Use -header-filter=|^Use -system-headers' \
  || true
if [ -s "$TIDY_OUT/failed" ]; then
  echo "clang-tidy: errors in $(wc -l < "$TIDY_OUT/failed") file(s):" >&2
  sort "$TIDY_OUT/failed" >&2
  exit 1
fi
echo "clang-tidy: ok"
[ "$MODE" = "--lint" ] && exit 0

step "C++ build + tests"
cmake --build "$BUILD_DIR" -j"$JOBS"
ctest --test-dir "$BUILD_DIR" --output-on-failure -j2

step "web tests + build"
( cd "$ROOT/web" && npm ci --no-audit --no-fund && npx vitest run && npm run build )

echo
echo "all checks passed"
