#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Build every release artifact twice, from two independent copies of the tree,
# and fail unless both builds are identical byte for byte.
#
#   scripts/check-reproducible.sh [output-dir]
#
# Why this matters: a Sigstore signature proves an artifact came from the release
# workflow; it cannot prove the workflow built what the source says. If the same
# commit always builds to the same bytes, anyone can rebuild a release and compare
# - and a build machine that injected something would be caught by the first
# person who did. This script is the precondition: it proves the build *is*
# deterministic before anyone relies on that.
#
# Both builds use the commit's timestamp (SOURCE_DATE_EPOCH) and the same pinned
# toolchain (packaging/build-requirements.txt, the rpm's digest-pinned container),
# in different directories and at different times. Uses the tracked files of the
# working tree, so uncommitted edits to tracked files are included; new files
# must be `git add`ed first. Needs what packaging/release.sh needs.

set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$(mktemp -d)}"
# Created, and made absolute before the cd below: CI passes a directory that
# does not exist yet, and a relative one would otherwise resolve against $repo.
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd "$repo"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
echo "==> SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($(date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ))"

artifacts=('*.deb' '*.rpm' '*.whl' '*.tar.gz' '*.cdx.json' 'SHA256SUMS.txt')

for run in 1 2; do
    tree="$(mktemp -d)"
    echo "==> Build $run in $tree"
    git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$tree"
    # Different paths, and a pause so that anything still reading the clock shows.
    [ "$run" = 2 ] && sleep 2
    (cd "$tree" && packaging/release.sh > "$out/build-$run.log" 2>&1) || {
        tail -30 "$out/build-$run.log" >&2
        exit 1
    }
    mkdir -p "$out/$run"
    for pattern in "${artifacts[@]}"; do
        # shellcheck disable=SC2086 # the pattern is meant to glob
        cp "$tree"/packaging/$pattern "$out/$run/"
    done
    rm -rf "$tree"
done

echo "==> Comparing"
status=0
for f in "$out"/1/*; do
    name="$(basename "$f")"
    if [ ! -f "$out/2/$name" ]; then
        echo "DIFFERENT  $name (missing from build 2)"
        status=1
    elif cmp -s "$f" "$out/2/$name"; then
        echo "identical  $name  $(sha256sum "$f" | cut -c1-16)"
    else
        echo "DIFFERENT  $name"
        status=1
        if command -v diffoscope >/dev/null; then
            diffoscope --text "$out/$name.diff.txt" "$f" "$out/2/$name" > /dev/null || true
            echo "           see $out/$name.diff.txt"
        fi
    fi
done

if [ "$status" = 0 ]; then
    echo "==> Reproducible: both builds are identical ($out)"
else
    echo "==> NOT reproducible ($out)" >&2
fi
exit "$status"
