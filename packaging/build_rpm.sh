#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# TTP — RPM Package Builder
# ══════════════════════════════════════════════════════════════════════
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
# ══════════════════════════════════════════════════════════════════════

# Strict mode: exit on error, undefined variables, and pipe failures.
set -euo pipefail

# Navigate to the project root.
# $(dirname "$0") resolves to packaging/, so /.. takes us to the root.
cd "$(dirname "$0")/.."

# Extract the version string from pyproject.toml (single source of truth).
# Example: version = "0.1.0" → VERSION="0.1.0"
VERSION=$(grep -m 1 '^version =' pyproject.toml | cut -d '"' -f 2)

# rpmbuild requires the source directory to be named exactly
# %{name}-%{version} (e.g., "ttp-0.1.0"). This variable is used
# for the tarball and the temporary source directory.
PKG_NAME="ttp-${VERSION}"

echo "==> Building native RPM for ttp version $VERSION..."

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
RPM_DIR="/tmp/ttp-rpmbuild"
rm -rf "$RPM_DIR"
mkdir -p "$RPM_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# ── Prepare the source tarball ───────────────────────────────────────
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

# ── Prepare the spec file ────────────────────────────────────────────
# The .spec file in our repo uses @@VERSION@@ as a placeholder so it
# can be version-controlled without hardcoding the version number.
# We copy it to the SPECS directory and replace the placeholder with
# the actual version extracted from pyproject.toml.
echo "--> Preparing spec file..."
cp packaging/ttp.spec "$RPM_DIR/SPECS/"
sed -i "s/@@VERSION@@/$VERSION/g" "$RPM_DIR/SPECS/ttp.spec"

# ── Run the build ────────────────────────────────────────────────────
# rpmbuild -bb = "build binary only" (we don't need source RPMs).
# --define "_topdir ..." overrides the default ~/rpmbuild location.
echo "--> Running rpmbuild..."
rpmbuild --define "_topdir $RPM_DIR" -bb "$RPM_DIR/SPECS/ttp.spec"

# ── Collect the output ───────────────────────────────────────────────
# rpmbuild places the finished .rpm inside RPMS/<arch>/.
# Since our package is 'noarch' (pure Python), it goes in RPMS/noarch/.
# We copy it back to our packaging/ directory for easy access.
cp "$RPM_DIR"/RPMS/noarch/*.rpm packaging/

echo "==> Done! RPM is ready: $(ls packaging/ttp-*.rpm)"
