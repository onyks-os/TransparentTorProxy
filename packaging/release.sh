#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

# TTP Release Builder
#
# This script orchestrates the full release pipeline for TTP:
#
#   0. Build and verify Python Wheel/Sdist metadata (via build/twine)
#   1. Clean old artifacts from packaging/ and dist/
#   2. Build a .deb package  (Debian/Ubuntu)  via packaging/build_deb.sh
#   3. Build an .rpm package (Fedora/RHEL)    via packaging/build_rpm.sh
#   4. Generate SHA256 checksums of all produced packages
#
# The resulting files are placed inside packaging/:
#   - ttp_<version>_all.deb
#   - ttp-<version>-1.<dist>.noarch.rpm
#   - SHA256SUMS.txt
#
# Usage:
#   ./packaging/release.sh
#
# Prerequisites:
#   - build, twine (pip install .[dev])
#   - dpkg-deb  (comes with Debian/Ubuntu by default)
#   - rpmbuild  (install with: sudo dnf install rpm-build)

# Strict mode: exit on error (-e), error on undefined variables (-u),
# and propagate pipe failures (-o pipefail).
set -euo pipefail

# Keep artifact permissions independent of the operator's umask (see build_deb.sh).
umask 022

# Navigate to the project root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

# Reproducible builds: every timestamp inside every artifact is the commit's, so
# two builds of the same commit produce the same bytes. An explicit value wins,
# which is how the container builds and scripts/check-reproducible.sh pass it on.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || true)"
fi
if [ -z "$SOURCE_DATE_EPOCH" ]; then
    echo "Error: SOURCE_DATE_EPOCH is not set and this is not a git checkout." >&2
    exit 1
fi
export SOURCE_DATE_EPOCH

# Extract the version string from pyproject.toml (the single source of truth).
VERSION=$(grep -m 1 '^version =' pyproject.toml | cut -d '"' -f 2)

# The directory where all build scripts live and where outputs are placed.
RELEASE_DIR="packaging"

# The release signing key published in docs/verification.md. Override only if the
# project key is rotated - and update docs/verification.md in the same commit.
GPG_KEY_ID="${GPG_KEY_ID:-34774E0CEC668426}"

echo "============================================"
echo "  TTP Release Builder - v${VERSION}"
echo "============================================"
echo ""

# Step 0: verify Python package (wheel/sdist + twine)
echo "[0/5] Building and verifying Python distribution..."
# Scope TMPDIR to this invocation only: exporting it breaks later steps
# (e.g. dpkg-deb) after we rm -rf the directory below.
BUILD_TMP="$(pwd)/.build_tmp"
rm -rf dist/ build/ "$BUILD_TMP"
mkdir -p "$BUILD_TMP"

# The build environment is pinned by hash (packaging/build_python.sh).
TMPDIR="$BUILD_TMP" packaging/build_python.sh dist > /dev/null
python3 -m twine check dist/*

rm -rf "$BUILD_TMP"

echo "      [OK] Python metadata is valid."
echo ""

# Step 1: clean old packaging artifacts
echo "[1/5] Cleaning old system artifacts..."
rm -rf "$(pwd)/.build_tmp"
rm -f "$RELEASE_DIR"/*.deb "$RELEASE_DIR"/*.rpm "$RELEASE_DIR"/*.tar.gz "$RELEASE_DIR"/*.whl "$RELEASE_DIR"/*.cdx.json "$RELEASE_DIR"/SHA256SUMS.txt "$RELEASE_DIR"/SHA256SUMS.txt.asc
echo "      Done."
echo ""

# Step 2: build .deb
echo "[2/5] Building Debian package (.deb)..."
if bash "$RELEASE_DIR/build_deb.sh"; then
    echo "      [OK] .deb built successfully."
else
    echo "      [FAILED] .deb build failed!"
    exit 1
fi
echo ""

# Step 3: build .rpm
echo "[3/5] Building RPM package (.rpm)..."
if command -v rpmbuild >/dev/null 2>&1; then
    if bash "$RELEASE_DIR/build_rpm.sh"; then
        echo "      [OK] .rpm built successfully."
    else
        echo "      [FAILED] .rpm build failed!"
        exit 1
    fi
else
    echo "      [!] rpmbuild not found, skipping .rpm"
fi
echo ""

# Step 3.5: copy python artifacts
echo "[3.5/5] Copying Python source distribution and wheel to release directory..."
cp dist/*.tar.gz dist/*.whl "$RELEASE_DIR"/
echo "      Done."
echo ""

# Step 3.6: one SBOM per artifact, read from the artifact itself
echo "[3.6/5] Writing an SBOM for each artifact..."
rm -f "$RELEASE_DIR"/*.cdx.json
SBOM_INPUTS=()
for ext in whl tar.gz deb rpm; do
    for f in "$RELEASE_DIR"/*."$ext"; do
        [ -f "$f" ] && SBOM_INPUTS+=("$f")
    done
done
python3 "$RELEASE_DIR/make_sbom.py" "${SBOM_INPUTS[@]}" | sed 's/^/      /'
echo ""

# Step 4: SHA256 checksums for packages
echo "[4/5] Generating SHA256 checksums..."
(
    cd "$RELEASE_DIR"
    PACKAGES=()
    for ext in deb rpm tar.gz whl; do
        for f in *."$ext"; do
            [ -f "$f" ] && PACKAGES+=("$f")
        done
    done

    if [ ${#PACKAGES[@]} -eq 0 ]; then
        echo "      [FAILED] No packages found to checksum!"
        exit 1
    fi

    sha256sum "${PACKAGES[@]}" > SHA256SUMS.txt
    echo "      [OK] SHA256SUMS.txt generated."

    # GPG release signing
    if command -v gpg >/dev/null 2>&1; then
        # Pin the signing key. Without --local-user gpg picks the first usable
        # secret key, which on a machine with several keys silently produces a
        # signature made by a key that docs/verification.md does not publish.
        if gpg --list-secret-keys "$GPG_KEY_ID" >/dev/null 2>&1; then
            echo "      [GPG] Signing SHA256SUMS.txt with $GPG_KEY_ID..."
            gpg --detach-sign --armor --yes --local-user "$GPG_KEY_ID" SHA256SUMS.txt
            echo "      [OK] SHA256SUMS.txt.asc signature generated."
        else
            echo "      [!] Release signing key $GPG_KEY_ID not available. Skipping GPG signing."
            echo "          Release assets published by CI are signed with Sigstore instead;"
            echo "          see docs/verification.md."
        fi
    else
        echo "      [!] GPG command not found. Skipping automatic signing."
    fi
)
echo ""

# Summary
echo "============================================"
echo "  Release artifacts ready:"
echo "============================================"
ls -lh "$RELEASE_DIR"/*.deb "$RELEASE_DIR"/*.rpm "$RELEASE_DIR"/*.tar.gz "$RELEASE_DIR"/*.whl "$RELEASE_DIR"/SHA256SUMS.txt "$RELEASE_DIR"/SHA256SUMS.txt.asc 2>/dev/null || :
echo ""
echo "SHA256 checksums:"
cat "$RELEASE_DIR/SHA256SUMS.txt" 2>/dev/null || echo "N/A"
echo ""
echo "Next steps:"
echo "  1. Test .deb on Ubuntu VM: scp -P 2224 packaging/transparent-tor-proxy_*.deb ubuntu@localhost:~/"
echo "  2. Test .rpm on Fedora VM: scp -P 2225 packaging/transparent-tor-proxy-*.rpm fedora@localhost:~/"
echo "  3. Create GitHub Release v${VERSION} and upload assets."
echo "============================================"
