#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# TTP — QEMU Snapshot Manager
# ══════════════════════════════════════════════════════════════════════
#
# Manages QEMU internal snapshots for safe TTP testing. Snapshots
# capture the entire disk state so you can instantly roll back if
# TTP leaves the VM in an unrecoverable state (e.g., broken network).
#
# Common workflow:
#   ./snapshot.sh debian save pre-test    ← save a clean state
#   # ... run ttp start, test, break things ...
#   ./snapshot.sh debian load pre-test    ← instant rollback
#
# Note: The VM must be STOPPED before loading a snapshot. Saving
# a snapshot while the VM is running is supported by QEMU but may
# cause filesystem inconsistencies.
#
# Usage:
#   ./snapshot.sh {debian|arch|ubuntu} {save|load|list} [name]
# ══════════════════════════════════════════════════════════════════════

# Get the absolute path to the project root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit

usage() {
    echo "Usage: $0 {debian|arch|ubuntu} {save|load|list} [snapshot_name]"
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

VM_TYPE=$1
COMMAND=$2
SNAP_NAME=$3

case $VM_TYPE in
    debian) DISK_IMG="$ROOT_DIR/scripts/vms/debian.qcow2" ;;
    arch)   DISK_IMG="$ROOT_DIR/scripts/vms/arch.qcow2" ;;
    ubuntu) DISK_IMG="$ROOT_DIR/scripts/vms/ubuntu.qcow2" ;;
    *)      echo "❌ Unknown VM type: $VM_TYPE"; usage ;;
esac

case "$COMMAND" in
    save)
        if [ -z "$SNAP_NAME" ]; then usage; fi
        echo "📸 Saving snapshot '$SNAP_NAME' for $VM_TYPE..."
        qemu-img snapshot -c "$SNAP_NAME" "$DISK_IMG"
        ;;
    load)
        if [ -z "$SNAP_NAME" ]; then usage; fi
        echo "⏪ Restoring snapshot '$SNAP_NAME' for $VM_TYPE..."
        qemu-img snapshot -a "$SNAP_NAME" "$DISK_IMG"
        ;;
    list)
        echo "📜 Available snapshots for $VM_TYPE:"
        qemu-img snapshot -l "$DISK_IMG"
        ;;
    *)
        usage
        ;;
esac
