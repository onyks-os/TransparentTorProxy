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
# exit code to files, collected through QGA independently of the guest network.
#
#   VM_WORK=~/.cache/ttp-lifecycle-vm [CHAOS_ARGS="--reset-between --no-bypass"] scripts/vm/lifecycle/chaos.sh
#
# CHAOS_ARGS is passed to tests/chaos_monkey.py as-is (see its --help).
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
VM_CAPTURE_MAXLEN=65535 vm_capture_start chaos

vm_ssh 'sudo systemd-run --quiet --unit=ttp-chaos --property=Type=exec \
    /bin/sh -c "TTP_DISPOSABLE_VM=1 python3 -u /opt/ttp/tests/chaos_monkey.py --evidence-dir /var/tmp/chaos-boundary '"${CHAOS_ARGS:-}"' >/var/tmp/chaos.log 2>&1; echo \$? >/var/tmp/chaos.rc"'
vm_log "chaos sweep started in the guest (${CHAOS_ARGS:-default: one session, canary})"

# The sweep plans every fault once and caps itself at --duration; with
# --reset-between every fault also pays a Tor bootstrap. The deadline here only
# has to outlast that plus cleanup.
deadline=$((SECONDS + ${CHAOS_DEADLINE:-2700}))
until vm_guest 'test -f /var/tmp/chaos.rc' 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        vm_log "no result from the sweep within ${CHAOS_DEADLINE:-2700} s"
        vm_guest 'cat /var/tmp/chaos.log; systemctl status ttp-chaos --no-pager; journalctl -u ttp-chaos -n 40 --no-pager' \
            >"$VM_WORK/chaos.log" 2>&1 || true
        exit 1
    fi
    sleep 15
done

vm_guest 'cat /var/tmp/chaos.log' >"$VM_WORK/chaos.log"
rc="$(vm_guest 'cat /var/tmp/chaos.rc')"
vm_capture_stop
mkdir -p "$VM_WORK/chaos-boundary"
for file in events.jsonl stimulus.jsonl; do
    # Bound every QGA reply; a long independent sweep can exceed the agent's
    # single-command output buffer. Truncated evidence must never be accepted.
    size=$(vm_guest "stat --printf=%s /var/tmp/chaos-boundary/$file")
    [[ "$size" =~ ^[0-9]+$ ]] || { echo "Invalid evidence file size" >&2; exit 1; }
    : >"$VM_WORK/chaos-boundary/$file"
    for ((offset=0; offset<size; offset+=65536)); do
        vm_guest "dd if=/var/tmp/chaos-boundary/$file bs=65536 skip=$((offset/65536)) count=1 status=none | base64 -w0" |
            base64 --decode >>"$VM_WORK/chaos-boundary/$file"
    done
    [ "$(wc -c <"$VM_WORK/chaos-boundary/$file")" -eq "$size" ] || exit 1
done
observation_rc=0
python3 "$HERE/chaos_capture.py" "$VM_WORK/chaos.pcap" "$VM_WORK/chaos-boundary" \
    "$VM_WORK/chaos-boundary-report.json" >"$VM_WORK/chaos-boundary-summary.log" || observation_rc=$?
cat "$VM_WORK/chaos-boundary-summary.log"
grep -E '^\[(INFO\] (Injecting|Bootstrapping)|AUDIT|ALERT|CANARY|RECOVERY-VERDICT|PASS|FAIL|ERROR)' "$VM_WORK/chaos.log" || true
vm_log "chaos sweep exited $rc"
if [ "$observation_rc" -ne 0 ]; then exit "$observation_rc"; fi
exit "$rc"
