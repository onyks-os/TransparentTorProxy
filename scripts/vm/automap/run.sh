#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
: "${VM_WORK:?set VM_WORK to a fresh disposable VM work directory}"
mkdir -p "$VM_WORK"
git -C "$ROOT" rev-parse HEAD >"$VM_WORK/source.txt"
git -C "$ROOT" diff --binary HEAD >"$VM_WORK/source.diff"
# shellcheck source=scripts/vm/lifecycle/vm.sh disable=SC1091
source "$HERE/../lifecycle/vm.sh"
trap 'vm_guest sync >/dev/null 2>&1 || true; vm_kill' EXIT
vm_kill
vm_fetch_image
vm_prepare
vm_boot
vm_wait_ready 600
vm_install_ttp "$ROOT"
VM_CAPTURE_MAXLEN=65535 vm_capture_start automap
vm_guest 'systemd-run --quiet --unit=ttp-automap /bin/sh -c "TTP_DISPOSABLE_VM=1 /opt/ttp/venv/bin/python -u /opt/ttp/scripts/vm/automap/guest.py >/var/tmp/automap.jsonl 2>/var/tmp/automap-errors.log; echo \$? >/var/tmp/automap.rc"'
deadline=$((SECONDS+1500))
until vm_guest 'test -f /var/tmp/automap.rc' 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        vm_guest 'cat /var/tmp/automap-errors.log' >"$VM_WORK/automap-errors.log" || true
        exit 1
    fi
    sleep 10
done
vm_capture_stop
vm_guest 'cat /var/tmp/automap.jsonl' >"$VM_WORK/automap.jsonl"
vm_guest 'cat /var/tmp/automap-errors.log' >"$VM_WORK/automap-errors.log"
rc=$(vm_guest 'cat /var/tmp/automap.rc')
observation_rc=0
python3 "$HERE/capture.py" "$VM_WORK/automap.pcap" "$VM_WORK/automap.jsonl" "$VM_WORK/automap-report.json" >"$VM_WORK/automap-summary.log" || observation_rc=$?
cat "$VM_WORK/automap-summary.log"
[ "$rc" = 0 ] && [ "$observation_rc" = 0 ]
