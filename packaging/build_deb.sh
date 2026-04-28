#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# TTP — Debian Package Builder
# ══════════════════════════════════════════════════════════════════════
#
# This script builds a native .deb package for Debian/Ubuntu systems.
#
# How Debian packaging works (simplified):
#   1. A .deb file is essentially a compressed archive containing two
#      things: the actual files to install (mirroring their target
#      locations on disk), and a DEBIAN/ metadata folder.
#   2. The DEBIAN/control file describes the package (name, version,
#      dependencies). When a user runs `apt install ./ttp.deb`, apt
#      reads this file and auto-installs any missing dependencies.
#   3. Optional scripts like DEBIAN/postinst run automatically after
#      the package files are copied to the system.
#   4. dpkg-deb compresses the entire directory tree into a .deb file.
#
# Output:
#   packaging/ttp_<version>_all.deb
#
# Usage:
#   ./packaging/build_deb.sh
#
# Prerequisites:
#   dpkg-deb (pre-installed on Debian/Ubuntu)
# ══════════════════════════════════════════════════════════════════════

# Strict mode: exit on error (-e), error on undefined variables (-u),
# and propagate pipe failures (-o pipefail).
set -euo pipefail

# Change the current directory to the root of the project.
# $0 is the path to this script. `dirname` gets the folder it's in (packaging/).
# `/..` moves one level up to the root folder (TransparentTorProxy/).
cd "$(dirname "$0")/.."

# Parse the pyproject.toml file to extract the current version number.
# grep finds the line starting with 'version ='. cut splits the line by double quotes (") 
# and takes the second piece (the actual version string, e.g., 0.1.0).
VERSION=$(grep -m 1 '^version =' pyproject.toml | cut -d '"' -f 2)

# Define the package name using the Debian naming convention: name_version_architecture
# 'all' means this package contains Python code which is architecture-independent.
PKG_NAME="ttp_${VERSION}_all"

# Define a temporary working directory where we will construct the package file structure.
BUILD_DIR="/tmp/${PKG_NAME}"

echo "==> Building $PKG_NAME.deb..."

# Clean up any previous build attempts by removing the temporary directory.
rm -rf "$BUILD_DIR"

# Create the specific directory structure that Debian packages require.
# /usr/bin is where executable commands go.
mkdir -p "$BUILD_DIR/usr/bin"
# /usr/lib/python3/dist-packages is the standard location for system-wide Python libraries on Debian.
mkdir -p "$BUILD_DIR/usr/lib/python3/dist-packages"
# /lib/systemd/system is where systemd service files live.
mkdir -p "$BUILD_DIR/lib/systemd/system"
# /DEBIAN is a special metadata folder used by dpkg (the underlying Debian package manager).
mkdir -p "$BUILD_DIR/DEBIAN"

# Install the Python 'build' module (if not already installed) silently (>/dev/null).
python3 -m pip install build >/dev/null

# Build the Python project into a standard format called a 'wheel' (.whl).
# This bundles all our Python source code into an archive in the 'dist/' folder.
python3 -m build --wheel >/dev/null

# Find the newly created wheel file in the dist/ directory.
WHEEL_FILE=$(ls dist/ttp-${VERSION}-py3-none-any.whl)

# Unzip the wheel file directly into the Debian dist-packages directory.
# This effectively "installs" the Python library files into the package structure.
unzip -q "$WHEEL_FILE" -d "$BUILD_DIR/usr/lib/python3/dist-packages/"

# Create the main executable script that the user will run (the 'ttp' command).
# This is a short Python script that imports our CLI app and runs it.
cat << 'EOF' > "$BUILD_DIR/usr/bin/ttp"
#!/usr/bin/python3
import sys
from ttp.cli import app

if __name__ == '__main__':
    sys.exit(app())
EOF

# Make the executable script runnable.
chmod +x "$BUILD_DIR/usr/bin/ttp"

# Copy the systemd service file from our repo into the package structure.
cp packaging/ttp.service "$BUILD_DIR/lib/systemd/system/"

# Create the documentation folder to store the copyright (required by Debian standards)
mkdir -p "$BUILD_DIR/usr/share/doc/ttp"
cp LICENSE "$BUILD_DIR/usr/share/doc/ttp/copyright"

# Create the 'control' file inside the DEBIAN folder.
# This is the most important metadata file. It tells apt what this package is,
# who made it, and most crucially, what other system packages it depends on.
# When a user runs 'apt install ./ttp.deb', apt reads 'Depends:' and installs tor and nftables automatically.
cat << EOF > "$BUILD_DIR/DEBIAN/control"
Package: ttp
Version: $VERSION
Architecture: all
Maintainer: onyks <ttp.nzkav@aleeas.com>
Section: net
Priority: optional
Homepage: https://github.com/onyks-os/TransparentTorProxy
License: MIT
Depends: python3, python3-typer, python3-rich, python3-stem, nftables, tor
Description: Transparent Tor Proxy
 A Linux CLI tool that transparently routes all system traffic through the Tor network.
EOF

# Create a 'postinst' (post-installation) script.
# Debian runs this bash script automatically right AFTER the package files are copied to the system.
cat << 'EOF' > "$BUILD_DIR/DEBIAN/postinst"
#!/bin/sh
set -e
# If the package is being configured (installed/upgraded)...
if [ "$1" = "configure" ]; then
    # Tell systemd to reload its configuration so it recognizes the new ttp.service file.
    systemctl daemon-reload || true
    echo "TTP installed. To enable on boot: sudo systemctl enable ttp"
fi
EOF

# Make the post-installation script executable.
chmod +x "$BUILD_DIR/DEBIAN/postinst"

# Finally, use the dpkg-deb tool to compress the BUILD_DIR structure into a final .deb file.
# --root-owner-group ensures files inside the package are owned by root, which is required for system files.
dpkg-deb --root-owner-group --build "$BUILD_DIR" "packaging/${PKG_NAME}.deb"

echo "==> Done: packaging/${PKG_NAME}.deb"
