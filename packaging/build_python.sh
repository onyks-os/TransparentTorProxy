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
# By default this runs inside a Python image pinned by digest. The same files in
# the same order still compress to different bytes under a different zlib - and
# Fedora ships zlib-ng - so a wheel or sdist built on the host is reproducible on
# that host only. In the pinned image it is reproducible on any machine with
# podman or docker, which is what lets someone else check a release.
# TTP_PY_NATIVE=1 builds on the host instead: the .rpm does, inside its own
# pinned Fedora image, and the .deb does, because it unpacks the wheel anyway.
#
# Not PIP_CONSTRAINT with hashes: pip before 26.2 switches a constraints file with
# hashes into hash-checking mode for the build requirements too, and then refuses
# pyproject.toml's `hatchling>=1.27` for not being pinned with ==. A hash-pinned
# requirements file behaves the same on every pip.

set -euo pipefail

PYTHON_BUILD_IMAGE="${PYTHON_BUILD_IMAGE:-docker.io/library/python@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b}"

out="${1:?usage: $0 <outdir> [build arguments]}"
shift
out="$(mkdir -p "$out" && cd "$out" && pwd)"
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Build from a copy of exactly what the distributions are made of, with
# normalised permissions. An sdist is a tar and records each file's mode as it
# is on disk, so a checkout made under umask 027 (files 0640) built a different
# sdist from one made under 022 - the same commit, different bytes, depending
# only on who cloned it. The copy also keeps the build venv out of the tree.
mkdir -p "$work/src/packaging" "$work/out"
cp -r ttp assets README.md LICENSE pyproject.toml "$work/src/"
cp packaging/build_python.sh packaging/build-requirements.txt "$work/src/packaging/"
find "$work/src" -name __pycache__ -prune -exec rm -rf {} +
chmod -R u=rwX,go=rX "$work/src"

if [ "${TTP_PY_NATIVE:-0}" != 1 ]; then
    engine="$(command -v podman || command -v docker || true)"
    if [ -z "$engine" ]; then
        echo "Error: building in $PYTHON_BUILD_IMAGE needs podman or docker (TTP_PY_NATIVE=1 builds on the host, reproducibly only there)." >&2
        exit 1
    fi
    # shellcheck disable=SC2016 # expanded by the container's shell, not this one
    "$engine" run --rm -v "$work:/work:z" -e TTP_PY_NATIVE=1 \
        -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}" "$PYTHON_BUILD_IMAGE" sh -c '
            set -eu
            [ -n "$SOURCE_DATE_EPOCH" ] || unset SOURCE_DATE_EPOCH
            /work/src/packaging/build_python.sh /work/out "$@" > /dev/null
            chown -R "$(stat -c %u:%g /work)" /work/out' sh "$@"
    cp "$work"/out/* "$out/"
    exit 0
fi

python3 -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --quiet --disable-pip-version-check \
    --require-hashes --no-deps -r packaging/build-requirements.txt
(cd "$work/src" && "$work/venv/bin/python" -m build --no-isolation --outdir "$out" "$@")
