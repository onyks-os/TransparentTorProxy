#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# The watchdog chaos sweep (tests/chaos_monkey.py) inside a disposable VM (#30).
#
# It was a manual gate because `ttp start` takes over its whole host, and on a
# hosted runner that is the runner's own connection. In the guest it takes over
# the guest. The sweep runs detached inside it: two of its faults cut this
# script's SSH session on purpose - the link flap takes the interface down, and
# the emergency killswitch drops inbound traffic too - so it writes its log and
# exit code to files, and this script collects them once the guest answers again.
#
#   VM_WORK=~/.cache/ttp-lifecycle-vm scripts/vm/lifecycle/chaos.sh
#
# Exits with the sweep's own exit code. Needs what run.sh needs; no root.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
: "${VM_WORK:?set VM_WORK to a working directory with a few GB free}"
mkdir -p "$VM_WORK"
# shellcheck source=scripts/vm/lifecycle/vm.sh
source "$HERE/vm.sh"

rm -f "${VM_WORK:?}/chaos.log"
trap 'vm_kill' EXIT

vm_kill # a VM left running by an earlier run holds the disk this one recreates
vm_fetch_image
vm_prepare
vm_boot
vm_wait_ready 600
vm_install_ttp "$ROOT"

vm_ssh 'sudo systemd-run --quiet --unit=ttp-chaos --property=Type=exec \
    /bin/sh -c "python3 /opt/ttp/tests/chaos_monkey.py >/var/tmp/chaos.log 2>&1; echo \$? >/var/tmp/chaos.rc"'
vm_log "chaos sweep started in the guest"

# The sweep plans every fault once and caps itself at --duration (420 s); the
# deadline here only has to outlast that plus `ttp start` and cleanup.
deadline=$((SECONDS + 1200))
until vm_ssh 'test -f /var/tmp/chaos.rc' 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        vm_log "no result from the sweep within 20 minutes"
        vm_ssh 'sudo cat /var/tmp/chaos.log' >"$VM_WORK/chaos.log" 2>/dev/null || true
        exit 1
    fi
    sleep 15
done

vm_ssh 'sudo cat /var/tmp/chaos.log' >"$VM_WORK/chaos.log"
rc="$(vm_ssh 'cat /var/tmp/chaos.rc')"
grep -E '^\[(INFO\] Injecting|AUDIT|ALERT|CANARY|PASS-VERDICT|PASS|FAIL|ERROR)' "$VM_WORK/chaos.log" || true
vm_log "chaos sweep exited $rc"
exit "$rc"
