#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Install reviewed dependencies and trusted local source; never resolve at install time.
set -euo pipefail
python=${1:?usage: install_locked.sh PYTHON PROFILE [SOURCE]}
profile=${2:?runtime, ci, oldest or docs}
source_dir=${3:-$(cd "$(dirname "$0")/.." && pwd)}
case "$profile" in runtime|ci|docs|oldest) ;; *) echo "Unknown lock profile: $profile" >&2; exit 2 ;; esac
"$python" -m pip install --require-hashes --no-deps --only-binary=:all: -r "$source_dir/requirements/tools.txt"
"$python" -m pip install --require-hashes --no-deps --no-build-isolation -r "$source_dir/requirements/$profile.txt"
if [ "$profile" != docs ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    "$python" -m build --no-isolation --wheel --outdir "$work" "$source_dir"
    "$python" -m installer "$work"/*.whl
fi
"$python" -m pip check
