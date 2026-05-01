#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# TTP — Code Sync to VM
# ══════════════════════════════════════════════════════════════════════
#
# Syncs the TTP source code from the host machine into the active
# QEMU VM. Auto-detects which VM is running by checking for QEMU
# processes that reference each disk image.
#
# Uses tar-over-SSH instead of rsync because rsync may not be
# pre-installed on minimal VM images (e.g., Arch netinstall).
#
# Excluded directories: .git, .venv, venv, __pycache__, .pytest_cache, vm
#
# Prerequisites:
#   - A running VM (started via ./start.sh)
#   - SSH access configured (password or key-based)
#
# Usage:
#   ./send.sh
# ══════════════════════════════════════════════════════════════════════

# Get the absolute path to the project root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit

# Auto-detect running VM
if pgrep -f "debian.qcow2" > /dev/null; then
    VM_TYPE="debian"
    REMOTE_USER="debian"
    REMOTE_PORT="2222"
elif pgrep -f "arch.qcow2" > /dev/null; then
    VM_TYPE="arch"
    REMOTE_USER="arch"
    REMOTE_PORT="2223"
elif pgrep -f "ubuntu.qcow2" > /dev/null; then
    VM_TYPE="ubuntu"
    REMOTE_USER="ubuntu"
    REMOTE_PORT="2224"
else
    echo "❌ No active TTP VM detected!"
    echo "Please start one first using ./start.sh"
    exit 1
fi

REMOTE_HOST="localhost"
DEST_FOLDER="$HOME/ttp/"

echo "🚀 Sending code to $VM_TYPE VM (port $REMOTE_PORT)..."

# Ensure the destination folder exists
ssh -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "mkdir -p $DEST_FOLDER"

# Sync using tar over ssh (robust fallback when rsync is missing on target)
EXCLUDES=(
    --exclude='scripts/vms'
    --exclude='.git'
    --exclude='.venv'
    --exclude='venv'
    --exclude='dist'
    --exclude='build'
    --exclude='*__pycache__*'
    --exclude='.pytest_cache'
    --exclude='.ruff_cache'
    --exclude='*.deb'
    --exclude='*.rpm'
    --exclude='*.qcow2'
    --exclude='*.iso'
)

if tar -C "$ROOT_DIR" "${EXCLUDES[@]}" -cf - . | ssh -p "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST" "tar -C $DEST_FOLDER -xf -"; then
    echo "✅ Sync completed!"
else
    echo "❌ Sync error."
fi
