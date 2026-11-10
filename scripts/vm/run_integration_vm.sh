#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Run the existing distribution userspace matrix inside a disposable Fedora
# kernel VM. Containers cannot load TTP's host AppArmor policy; do not grant
# them access to the runner's securityfs or disable its AppArmor protections.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DISTRO=${1:?usage: run_integration_vm.sh debian|fedora|arch}
case "$DISTRO" in debian|fedora|arch) ;; *) echo "Unsupported userspace: $DISTRO" >&2; exit 2 ;; esac
: "${VM_WORK:?set VM_WORK to a new, disposable directory}"
mkdir -m 0700 "$VM_WORK" # refuse existing disks and control files
VM_WORK=$(cd "$VM_WORK" && pwd)
export VM_WORK
export VM_DISTRO=fedora
export VM_MEM=${VM_MEM:-4096}
export VM_SSH_PORT
VM_SSH_PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)
# shellcheck source=scripts/vm/lifecycle/vm.sh disable=SC1091
source "$ROOT/scripts/vm/lifecycle/vm.sh"
export VM_PACKAGES="moby-engine, docker-cli, docker-buildx, rsync, python3, tar"
trap 'vm_kill' EXIT
vm_fetch_image
vm_prepare
qemu-img resize -q "$VM_WORK/disk.qcow2" 20G
vm_boot
vm_wait_ready 900
vm_ssh 'sudo systemctl start docker; sudo docker info; uname -r; sudo cat /sys/kernel/security/lsm' \
    >"$VM_WORK/kernel-and-engine.txt"
# This matrix measures distribution userspaces on Fedora's actual kernel.
# Native AppArmor enforcement is exercised separately in AppArmor-enabled VMs.
vm_ssh 'sudo mkdir -p /opt/ttp'
(cd "$ROOT" && git ls-files -z | tar --null -T - -czf -) |
    vm_ssh 'sudo tar -C /opt/ttp -xzf -'
set +e
vm_ssh "cd /opt/ttp && sudo scripts/vm/run_integration_tests.sh $DISTRO" \
    2>&1 | tee "$VM_WORK/integration.log"
code=${PIPESTATUS[0]}
set -e
printf '%s\n' "$code" >"$VM_WORK/exit-code.txt"
exit "$code"
