#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Install a native package in a clean container and check that what it installed
# can actually run.
#
# Nothing did this before. The release rehearsal built the .deb and the .rpm and
# checked they existed; no job installed one. So three defects shipped unseen:
# the .deb did not depend on `transitions`, which the watchdog needs and which
# `ttp stop` imported outside any `try`; the .rpm required python(abi) = 3.12,
# because it was built on Ubuntu, and a `transitions` and a `rich` no Fedora
# provides, so it could not be installed at all; and the PKGBUILD was rejected by
# makepkg before building anything.
#
# Usage:
#   packaging/smoke_test.sh <package.deb> [image]   default image: debian:13
#   packaging/smoke_test.sh <package.rpm> [image]   default image: fedora:44
#   packaging/smoke_test.sh arch [image]            builds packaging/PKGBUILD from
#                                                   this checkout, then installs it
# Needs podman or docker. Runs no systemd and touches no firewall: it checks the
# install and the imports, not a session.

set -euo pipefail

target="${1:?usage: $0 <package.deb|package.rpm|arch> [image]}"
engine="$(command -v podman || command -v docker || true)"
[ -n "$engine" ] || { echo "podman or docker is required" >&2; exit 2; }

# What must hold on an installed host. Each line fails the run on its own.
checks='
ttp --help > /dev/null
echo "ok: ttp --help"
# The watchdog state machine must be buildable: this is what needs transitions,
# from the distribution or from the copy the package bundles.
python3 -c "from ttp.watchdog.fsm import WatchdogFSM; WatchdogFSM()"
echo "ok: WatchdogFSM() builds"
python3 -c "import sys; from ttp.watchdog.fsm import load_machine; m = load_machine(); print(\"    transitions from\", sys.modules[m.__module__].__file__)"
# And everything ttp stop imports must import even so.
python3 -c "import ttp.commands.lifecycle, ttp.commands.stop_restart, ttp.watchdog"
echo "ok: teardown modules import"
'

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

case "$target" in
    *.deb|*.rpm)
        [ -f "$target" ] || { echo "no such package: $target" >&2; exit 2; }
        cp "$target" "$stage/package.${target##*.}"
        if [ "${target##*.}" = deb ]; then
            image="${2:-docker.io/library/debian:13}"
            install='apt-get update -qq && apt-get install -y -qq /stage/package.deb'
        else
            image="${2:-registry.fedoraproject.org/fedora:44}"
            install='dnf install -y -q /stage/package.rpm'
        fi
        label="$(basename "$target")"
        ;;
    arch)
        image="${2:-docker.io/library/archlinux:latest}"
        # The PKGBUILD builds the checkout it sits in; give it only what the
        # build reads, so a local venv or cache is never mounted.
        repo="$(cd "$(dirname "$0")/.." && pwd)"
        mkdir "$stage/src"
        (cd "$repo" && cp -r ttp assets packaging pyproject.toml README.md LICENSE "$stage/src/")
        rm -f "$stage"/src/packaging/*.deb "$stage"/src/packaging/*.rpm "$stage"/src/packaging/*.pkg.tar.*
        install='
            pacman -Syu --noconfirm --needed base-devel python-build python-installer python-wheel python-hatchling
            useradd -m builder
            cp -r /stage/src /home/builder/ttp && chown -R builder /home/builder/ttp
            su builder -c "cd /home/builder/ttp/packaging && makepkg --noconfirm --nodeps --force"
            pacman -U --noconfirm /home/builder/ttp/packaging/transparent-tor-proxy-*.pkg.tar.zst'
        label="packaging/PKGBUILD"
        ;;
    *)
        echo "not a .deb, an .rpm or 'arch': $target" >&2
        exit 2
        ;;
esac

echo "==> Installing $label in $image"
"$engine" run --rm -v "$stage:/stage:z" "$image" sh -c \
    "set -eu; ( $install ) > /tmp/install.log 2>&1 || { tail -40 /tmp/install.log; exit 1; }; $checks"
echo "==> $label: installed and runnable in $image"
