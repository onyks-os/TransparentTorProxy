#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# TTP Release Builder
# ══════════════════════════════════════════════════════════════════════
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
# ══════════════════════════════════════════════════════════════════════

# Strict mode: exit on error (-e), error on undefined variables (-u),
# and propagate pipe failures (-o pipefail).
set -euo pipefail

# Navigate to the project root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

# Extract the version string from pyproject.toml (the single source of truth).
VERSION=$(grep -m 1 '^version =' pyproject.toml | cut -d '"' -f 2)

# The directory where all build scripts live and where outputs are placed.
RELEASE_DIR="packaging"

echo "============================================"
echo "  TTP Release Builder — v${VERSION}"
echo "============================================"
echo ""

# ── Step 0: Verify Python Package ────────────────────────────────────
echo "[0/5] Building and verifying Python distribution..."
rm -rf dist/ build/
python3 -m build > /dev/null
python3 -m twine check dist/*
echo "      ✅ Python metadata is valid."
echo ""

# ── Step 1: Clean old artifacts ──────────────────────────────────────
echo "[1/5] Cleaning old system artifacts..."
rm -f "$RELEASE_DIR"/*.deb "$RELEASE_DIR"/*.rpm "$RELEASE_DIR"/SHA256SUMS.txt
echo "      Done."
echo ""

# ── Step 2: Build .deb ───────────────────────────────────────────────
echo "[2/5] Building Debian package (.deb)..."
if bash "$RELEASE_DIR/build_deb.sh"; then
    echo "      ✅ .deb built successfully."
else
    echo "      ❌ .deb build failed!"
    exit 1
fi
echo ""

# ── Step 3: Build .rpm ───────────────────────────────────────────────
echo "[3/5] Building RPM package (.rpm)..."
if command -v rpmbuild >/dev/null 2>&1; then
    if bash "$RELEASE_DIR/build_rpm.sh"; then
        echo "      ✅ .rpm built successfully."
    else
        echo "      ❌ .rpm build failed!"
        exit 1
    fi
else
    echo "      ⚠ rpmbuild not found, skipping .rpm"
fi
echo ""

# ── Step 4: Generate SHA256 checksums ────────────────────────────────
echo "[4/5] Generating SHA256 checksums..."
(
    cd "$RELEASE_DIR"
    PACKAGES=()
    for ext in deb rpm; do
        for f in *."$ext"; do
            [ -f "$f" ] && PACKAGES+=("$f")
        done
    done

    if [ ${#PACKAGES[@]} -eq 0 ]; then
        echo "      ❌ No packages found to checksum!"
        exit 1
    fi

    sha256sum "${PACKAGES[@]}" > SHA256SUMS.txt
    echo "      ✅ SHA256SUMS.txt generated."
)
echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo "============================================"
echo "  Release artifacts ready:"
echo "============================================"
ls -lh "$RELEASE_DIR"/*.deb "$RELEASE_DIR"/*.rpm "$RELEASE_DIR"/SHA256SUMS.txt 2>/dev/null || :
ls -lh dist/* 2>/dev/null || :
echo ""
echo "SHA256 checksums:"
cat "$RELEASE_DIR/SHA256SUMS.txt" 2>/dev/null || echo "N/A"
echo ""
echo "Next steps:"
echo "  1. Test .deb on Ubuntu VM: scp -P 2224 packaging/transparent-tor-proxy_*.deb ubuntu@localhost:~/"
echo "  2. Test .rpm on Fedora VM: scp -P 2225 packaging/transparent-tor-proxy-*.rpm fedora@localhost:~/"
echo "  3. Create GitHub Release v${VERSION} and upload assets."
echo "============================================"
