#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# TTP — QEMU VM Launcher
# ══════════════════════════════════════════════════════════════════════
#
# Starts a QEMU virtual machine for testing TTP on real Linux
# distributions. This is part of the development workflow:
#
#   1. ./start.sh debian     ← start a VM
#   2. ./send.sh             ← sync code into it
#   3. ssh -p 2222 ...       ← test inside the VM
#   4. ./snapshot.sh ...     ← save/restore VM state
#
# Each VM type has a unique SSH port to allow running multiple VMs
# simultaneously:
#   debian → port 2222
#   arch   → port 2223
#   ubuntu → port 2224
#
# The disk images (.qcow2) and ISOs live in ../vm/ (gitignored).
# KVM acceleration is required (the host must support hardware
# virtualization).
#
# Usage:
#   ./start.sh [debian|arch|ubuntu]
# ══════════════════════════════════════════════════════════════════════

# Get the absolute path to the project root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit

# Default values
VM_TYPE=${1:-debian}
RAM="6148"
CORES="8"

case $VM_TYPE in
    debian)
        DISK_IMG="$ROOT_DIR/scripts/vms/debian.qcow2"
        ISO_IMG="$ROOT_DIR/scripts/vms/debian.iso"
        SSH_PORT="2222"
        ;;
    arch)
        DISK_IMG="$ROOT_DIR/scripts/vms/arch.qcow2"
        ISO_IMG="$ROOT_DIR/scripts/vms/arch.iso"
        SSH_PORT="2223"
        ;;
    ubuntu)
        DISK_IMG="$ROOT_DIR/scripts/vms/ubuntu.qcow2"
        ISO_IMG="$ROOT_DIR/scripts/vms/ubuntu.iso"
        SSH_PORT="2224"
        ;;
    *)
        echo "❌ Unknown VM type: $VM_TYPE"
        echo "Usage: $0 [debian|arch|ubuntu]"
        exit 1
        ;;
esac

if [ ! -f "$DISK_IMG" ]; then
    echo "⚠️  Warning: Disk image $DISK_IMG not found. QEMU might fail if you are not installing from ISO."
fi

echo "🚀 Starting TTP Development VM ($VM_TYPE)..."
echo "🔗 SSH available at localhost:$SSH_PORT"

qemu-system-x86_64 \
    -m $RAM \
    -enable-kvm \
    -cpu host \
    -smp $CORES \
    -drive file="$DISK_IMG",format=qcow2 \
    -cdrom "$ISO_IMG" \
    -netdev user,id=net0,hostfwd=tcp::$SSH_PORT-:22 \
    -device virtio-net-pci,netdev=net0
    # -nographic
