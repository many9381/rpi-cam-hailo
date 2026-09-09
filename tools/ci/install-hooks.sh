#!/usr/bin/env bash
# Point git at the repository's hooks (format gate on commit) and hide the
# whole-tree reformat commit from git blame.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath tools/ci/hooks
git config blame.ignoreRevsFile .git-blame-ignore-revs
echo "core.hooksPath -> tools/ci/hooks"
echo "blame.ignoreRevsFile -> .git-blame-ignore-revs"
