#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

# TTP - RPM Package Builder
#
# This script builds a native .rpm package for Fedora/RHEL/CentOS
# distributions. It is the RPM equivalent of build_deb.sh.
#
# How RPM packaging works (simplified):
#   1. rpmbuild expects a very specific directory layout (BUILD, RPMS,
#      SOURCES, SPECS, SRPMS) inside a "build root" directory.
#   2. A source tarball containing the project code is placed in SOURCES/.
#   3. A .spec file (the recipe) is placed in SPECS/. This file tells
#      rpmbuild how to unpack, build, and install the software.
#   4. rpmbuild reads the .spec, executes its phases (%prep, %build,
#      %install, etc.), and produces the final .rpm in RPMS/.
#
# This script automates all of the above, using /tmp as a scratch space
# so we don't pollute the user's home directory (which is the rpmbuild
# default behavior).
#
# Usage:
#   ./packaging/build_rpm.sh
#
# Prerequisites:
#   sudo dnf install rpm-build

# Strict mode: exit on error, undefined variables, and pipe failures.
set -euo pipefail

# Keep packaged file modes independent of the operator's umask (see build_deb.sh).
umask 022

# Navigate to the project root.
# $(dirname "$0") resolves to packaging/, so /.. takes us to the root.
cd "$(dirname "$0")/.."

# The Python ABI the rpm requires and the site-packages directory it installs
# into both come from the Python it is built with. The release job runs on
# Ubuntu, so 0.4.8's .rpm required python(abi) = 3.12 and installed into
# /usr/lib/python3.12/site-packages: no supported Fedora could install it. Build
# it on the Fedora it targets instead - in a container, unless this already is
# that Fedora.
RPM_TARGET_IMAGE="${RPM_TARGET_IMAGE:-registry.fedoraproject.org/fedora:44}"
target_version="${RPM_TARGET_IMAGE##*:}"
# shellcheck disable=SC1091 # the host's own file, read at run time
host_id="$(. /etc/os-release 2>/dev/null && echo "${ID:-}:${VERSION_ID:-}")"
if [ "${TTP_RPM_NATIVE:-0}" != 1 ] && [ "$host_id" != "fedora:$target_version" ]; then
    engine="$(command -v podman || command -v docker || true)"
    if [ -z "$engine" ]; then
        echo "Error: building the .rpm for $RPM_TARGET_IMAGE needs podman or docker on a non-matching host ($host_id)." >&2
        exit 1
    fi
    echo "==> Host is $host_id; building the .rpm inside $RPM_TARGET_IMAGE..."
    # Only what the build reads is mounted - the same set the source tarball
    # below is made of - so a local venv or cache never has to be relabelled
    # or read by the container.
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' EXIT
    cp -r ttp assets packaging pyproject.toml README.md LICENSE "$stage/"
    rm -f "$stage"/packaging/*.rpm
    # shellcheck disable=SC2016 # expanded by the container's shell, not this one
    "$engine" run --rm -v "$stage:/src:z" -w /src -e TTP_RPM_NATIVE=1 "$RPM_TARGET_IMAGE" sh -c '
        set -eu
        dnf install -y -q rpm-build python3-devel python3-build python3-pip unzip curl \
            checkpolicy policycoreutils > /dev/null
        packaging/build_rpm.sh
        chown "$(stat -c %u:%g /src)" packaging/*.rpm'
    cp "$stage"/packaging/*.rpm packaging/
    echo "==> Done! RPM is ready: $(ls packaging/transparent-tor-proxy-*.rpm)"
    exit 0
fi

# Extract the version string from pyproject.toml (single source of truth).
# Example: version = "x.y.z" → VERSION="x.y.z"
VERSION=$(grep -m 1 '^version =' pyproject.toml | cut -d '"' -f 2)

# rpmbuild requires the source directory to be named exactly
# %{name}-%{version} (e.g., "ttp-x.y.z"). This variable is used
# for the tarball and the temporary source directory.
PKG_NAME="transparent-tor-proxy-${VERSION}"

echo "==> Building native RPM for transparent-tor-proxy version $VERSION..."

# Verify that rpmbuild is installed. It ships in the 'rpm-build' package
# on Fedora/RHEL but is not installed by default.
if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "Error: 'rpmbuild' is not installed."
    echo "Install it with: sudo dnf install rpm-build"
    exit 1
fi

# Create an isolated rpmbuild workspace in /tmp.
# By default, rpmbuild uses ~/rpmbuild, which is messy and can cause
# permission issues. Using --define "_topdir ..." later tells rpmbuild
# to use our temporary directory instead.
RPM_DIR="/tmp/transparent-tor-proxy-rpmbuild"
rm -rf "$RPM_DIR"
mkdir -p "$RPM_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Prepare the source tarball
# rpmbuild's %prep phase expects to unpack a tarball that contains a
# single top-level directory named %{name}-%{version}. We create that
# directory structure in /tmp, copy the relevant source files into it,
# then archive it as a .tar.gz.
echo "--> Creating source tarball..."
TMP_SRC="/tmp/${PKG_NAME}"
rm -rf "$TMP_SRC"
mkdir -p "$TMP_SRC"

# Copy only the files needed for the build (no .git, no tests, no VMs).
cp -r ttp assets packaging pyproject.toml README.md LICENSE "$TMP_SRC/"

# Create the tarball in the SOURCES directory where rpmbuild expects it.
tar -czf "$RPM_DIR/SOURCES/${PKG_NAME}.tar.gz" -C "/tmp" "$PKG_NAME"

# Clean up the temporary source directory (the tarball is all we need).
rm -rf "$TMP_SRC"

# Prepare the spec file
# The .spec file in our repo uses @@VERSION@@ as a placeholder so it
# can be version-controlled without hardcoding the version number.
# We copy it to the SPECS directory and replace the placeholder with
# the actual version extracted from pyproject.toml.
# shellcheck source=packaging/bundled-transitions.env disable=SC1091
. packaging/bundled-transitions.env
echo "--> Fetching bundled transitions ${TRANSITIONS_VERSION}..."
curl -fsSL --retry 3 -o "$RPM_DIR/SOURCES/$TRANSITIONS_WHEEL" "$TRANSITIONS_URL"
# The digest is pinned: a different file under the same name is refused, not
# packaged.
echo "$TRANSITIONS_SHA256  $RPM_DIR/SOURCES/$TRANSITIONS_WHEEL" | sha256sum -c --quiet -

echo "--> Preparing spec file..."
cp packaging/ttp.spec "$RPM_DIR/SPECS/"
sed -i "s/@@VERSION@@/$VERSION/g" "$RPM_DIR/SPECS/ttp.spec"
sed -i -e "s/@@TRANSITIONS_VERSION@@/$TRANSITIONS_VERSION/g" \
       -e "s/@@TRANSITIONS_WHEEL@@/$TRANSITIONS_WHEEL/g" "$RPM_DIR/SPECS/ttp.spec"

# Run rpmbuild
# rpmbuild -bb = "build binary only" (we don't need source RPMs).
# --define "_topdir ..." overrides the default ~/rpmbuild location.
echo "--> Running rpmbuild..."
rpmbuild --define "_topdir $RPM_DIR" --nodeps -bb "$RPM_DIR/SPECS/ttp.spec"

# Collect the output .rpm
# rpmbuild places the finished .rpm inside RPMS/<arch>/.
# Since our package is 'noarch' (pure Python), it goes in RPMS/noarch/.
# We copy it back to our packaging/ directory for easy access.
cp "$RPM_DIR"/RPMS/noarch/*.rpm packaging/

echo "==> Done! RPM is ready: $(ls packaging/transparent-tor-proxy-*.rpm)"
