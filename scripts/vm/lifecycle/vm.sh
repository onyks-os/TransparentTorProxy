#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Lifecycle VM harness (#30): a disposable Debian VM under QEMU, driven from
# outside, so TTP can be taken through transitions a container cannot have -
# reboot, poweroff, suspend/resume - while every packet the guest sends is
# recorded where the guest cannot influence it.
#
# Why a VM and why this shape:
#   - `ttp start` routes its whole host through Tor. Inside a VM that host is
#     the guest; the machine running this script keeps its own network, which
#     is what a CI runner needs to survive the test.
#   - QEMU user networking needs no root on the host, and `filter-dump` writes
#     the guest's traffic to a pcap below the guest's own firewall - evidence
#     TTP cannot vouch for itself.
#   - The QEMU monitor socket gives suspend/wake and hard power-off from outside.
#
# Source this file; it defines functions and changes nothing on load.
#   VM_WORK   working directory (images, keys, logs, pcaps)   [required]
#   VM_SSH_PORT host port forwarded to the guest's sshd       [default 2222]
#   VM_MEM / VM_CPUS                                          [2048 / 2]

set -euo pipefail

VM_SSH_PORT="${VM_SSH_PORT:-2222}"
VM_MEM="${VM_MEM:-2048}"
VM_CPUS="${VM_CPUS:-2}"
VM_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest"
VM_IMAGE_NAME="debian-13-genericcloud-amd64.qcow2"

vm_log() { printf '[vm %s] %s\n' "$(date +%T)" "$*" >&2; }

# Download the base image once and refuse it unless its SHA512 matches the
# published list. -L matters: the URL redirects to a mirror.
vm_fetch_image() {
    local base="$VM_WORK/$VM_IMAGE_NAME"
    curl -fsSL -o "$VM_WORK/SHA512SUMS" "$VM_IMAGE_URL/SHA512SUMS"
    if [ ! -f "$base" ] || ! (cd "$VM_WORK" && grep " $VM_IMAGE_NAME\$" SHA512SUMS | sha512sum -c --status -); then
        vm_log "downloading $VM_IMAGE_NAME"
        curl -fsSL -o "$base" "$VM_IMAGE_URL/$VM_IMAGE_NAME"
    fi
    (cd "$VM_WORK" && grep " $VM_IMAGE_NAME\$" SHA512SUMS | sha512sum -c -) >&2
}

# A fresh copy-on-write disk and a cloud-init seed with a throwaway SSH key.
vm_prepare() {
    rm -f "${VM_WORK:?}/disk.qcow2" "${VM_WORK:?}/id_vm" "${VM_WORK:?}/id_vm.pub"
    qemu-img create -q -f qcow2 -F qcow2 -b "$VM_WORK/$VM_IMAGE_NAME" "$VM_WORK/disk.qcow2" 8G
    ssh-keygen -q -t ed25519 -N '' -f "$VM_WORK/id_vm"
    mkdir -p "$VM_WORK/seed"
    cat >"$VM_WORK/seed/meta-data" <<EOF
instance-id: ttp-lifecycle-$(date +%s)
local-hostname: ttp-lifecycle
EOF
    cat >"$VM_WORK/seed/user-data" <<EOF
#cloud-config
users:
  - name: ttp
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "$VM_WORK/id_vm.pub")
package_update: true
packages: [nftables, tor, python3-venv, python3-pip, curl, rsync, iproute2]
EOF
    genisoimage -quiet -output "$VM_WORK/seed.iso" -volid cidata -joliet -rock \
        "$VM_WORK/seed/user-data" "$VM_WORK/seed/meta-data"
}

# Boot in the background, with no capture: provisioning moves hundreds of MB
# (packages, the source tree) that no scenario needs, and a capture of it once
# grew to 9 GB. Capture only around a scenario, with vm_capture_start/stop.
vm_boot() {
    VM_NETDEV=n0
    VM_BOOTS=$((${VM_BOOTS:-0} + 1)) # one console log per boot of this run
    rm -f "${VM_WORK:?}/qemu.pid" "${VM_WORK:?}/monitor.sock"
    qemu-system-x86_64 \
        -machine pc,accel=kvm -cpu host -m "$VM_MEM" -smp "$VM_CPUS" \
        -global PIIX4_PM.disable_s3=0 \
        -drive file="$VM_WORK/disk.qcow2",if=virtio \
        -drive file="$VM_WORK/seed.iso",if=virtio,format=raw,readonly=on \
        -netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$VM_SSH_PORT"-:22 \
        -device virtio-net-pci,netdev=n0,id=nic0 \
        -display none -serial file:"$VM_WORK/console-$VM_BOOTS.log" \
        -monitor unix:"$VM_WORK/monitor.sock",server,nowait \
        -daemonize -pidfile "$VM_WORK/qemu.pid"
    vm_log "booted"
}

vm_ssh() {
    ssh -q -i "$VM_WORK/id_vm" -p "$VM_SSH_PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
        ttp@127.0.0.1 "$@"
}

# Wait until the guest answers over SSH and cloud-init has finished.
vm_wait_ready() {
    local deadline=$((SECONDS + ${1:-300}))
    until vm_ssh true 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || { vm_log "no SSH within ${1:-300}s"; return 1; }
        sleep 3
    done
    vm_ssh 'cloud-init status --wait >/dev/null 2>&1 || true'
    vm_log "guest ready"
}

# Send a command to the QEMU monitor (e.g. system_wakeup, system_powerdown, quit).
vm_monitor() {
    python3 - "$VM_WORK/monitor.sock" "$1" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(0.2); s.recv(4096)
s.sendall(sys.argv[2].encode() + b"\n"); time.sleep(0.5)
print(s.recv(4096).decode(errors="replace"))
PY
}

# Record the guest's traffic into $VM_WORK/<name>.pcap from now until
# vm_capture_stop. Headers only (maxlen): enough to say where a packet went and
# on what port, and it bounds the file whatever the guest sends.
vm_capture_start() {
    vm_monitor "object_add filter-dump,id=cap,netdev=${VM_NETDEV:-n0},file=$VM_WORK/$1.pcap,maxlen=128" >/dev/null
    vm_log "capturing to $1.pcap"
}

vm_capture_stop() {
    vm_monitor "object_del cap" >/dev/null
    vm_log "capture stopped"
}

# Move the guest to a different network, as a laptop does between two places:
# unplug the NIC, and plug a new one into a user network on subnet $1 (e.g.
# 192.168.77.0/24). The guest sees a new link and must acquire a new lease.
# Stop any capture first; it is attached to the old network.
vm_swap_network() {
    local next="n$((${VM_NETDEV#n} + 1))"
    vm_monitor "device_del nic0" >/dev/null
    sleep 2
    vm_monitor "netdev_del ${VM_NETDEV:-n0}" >/dev/null
    vm_monitor "netdev_add user,id=$next,net=$1,hostfwd=tcp:127.0.0.1:$VM_SSH_PORT-:22" >/dev/null
    vm_monitor "device_add virtio-net-pci,netdev=$next,id=nic0" >/dev/null
    VM_NETDEV="$next"
    vm_log "guest moved to $1 ($next)"
}

# Block until the QEMU process has exited (guest poweroff, or `quit`).
vm_wait_exit() {
    local pid deadline=$((SECONDS + ${1:-120}))
    pid="$(cat "$VM_WORK/qemu.pid" 2>/dev/null || true)"
    [ -n "$pid" ] || return 0
    while kill -0 "$pid" 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || { vm_log "QEMU still running after ${1:-120}s"; return 1; }
        sleep 1
    done
}

vm_kill() {
    local pid
    pid="$(cat "$VM_WORK/qemu.pid" 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
    fi
    vm_wait_exit 30 || true
}

# Copy the working tree into the guest and install TTP the way the integration
# containers do: a venv with the package installed from source.
vm_install_ttp() {
    local src="$1"
    # Only what git considers part of the tree (tracked, plus new files that are
    # not ignored): the ignored scripts/vms/ holds tens of GB of dev VM images.
    (cd "$src" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -czf -) |
        vm_ssh 'sudo rm -rf /opt/ttp && sudo mkdir -p /opt/ttp && sudo tar -C /opt/ttp -xzf -'
    vm_ssh 'sudo python3 -m venv /opt/ttp/venv && sudo /opt/ttp/venv/bin/pip install -q /opt/ttp \
        && sudo ln -sf /opt/ttp/venv/bin/ttp /usr/local/bin/ttp'
    vm_log "TTP installed: $(vm_ssh 'ttp --version 2>&1 | head -1')"
}

# Everything that says which state the guest is in, as one text report.
vm_snapshot_state() {
    vm_ssh 'sudo bash -s' <<'EOF'
echo "## nft tables";            nft list tables 2>&1
echo "## inet ttp present";      nft list table inet ttp >/dev/null 2>&1 && echo yes || echo no
echo "## /run/ttp";              ls -la /run/ttp 2>&1
echo "## ttp-tor.service";       systemctl is-active ttp-tor 2>&1; systemctl is-enabled ttp-tor 2>&1
echo "## watchdog units";        systemctl list-units --all --no-legend 'ttp*' 2>&1
echo "## resolv.conf mount";     findmnt /etc/resolv.conf 2>&1 || echo "not a mount point"
echo "## resolv.conf";           cat /etc/resolv.conf 2>&1
echo "## ttp status";            ttp status 2>&1 | tail -20
echo "## default route";         ip route show default 2>&1
EOF
}
