#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Build TTP's Python distributions in the exact, hash-pinned build environment.
#
#   packaging/build_python.sh <outdir> [python -m build arguments, e.g. --wheel]
#
# Creates a throwaway venv, installs packaging/build-requirements.txt into it with
# --require-hashes (every package at one version, every file checked against its
# SHA-256), and runs `python -m build --no-isolation` from it. Every released
# artifact that contains the wheel - the wheel and sdist themselves, the .deb and
# the .rpm - is built through here, so they all come from the same backend.
#
# Not PIP_CONSTRAINT with hashes: pip before 26.2 switches a constraints file with
# hashes into hash-checking mode for the build requirements too, and then refuses
# pyproject.toml's `hatchling>=1.27` for not being pinned with ==. A hash-pinned
# requirements file behaves the same on every pip.

set -euo pipefail

out="${1:?usage: $0 <outdir> [build arguments]}"
shift
out="$(mkdir -p "$out" && cd "$out" && pwd)"
cd "$(dirname "$0")/.."

env_dir="$(mktemp -d)"
trap 'rm -rf "$env_dir"' EXIT
python3 -m venv "$env_dir"
"$env_dir/bin/python" -m pip install --quiet --disable-pip-version-check \
    --require-hashes --no-deps -r packaging/build-requirements.txt
"$env_dir/bin/python" -m build --no-isolation --outdir "$out" "$@"
