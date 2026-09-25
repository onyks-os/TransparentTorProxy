#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Lifecycle transitions of #30, measured in a disposable VM: shutdown with an
# active session, reboot with an active session, suspend/resume onto a new
# network. Every verdict comes from a capture taken by QEMU outside the guest,
# of a probe that keeps trying to reach 198.51.100.7 in cleartext (probe.py).
#
#   VM_WORK=~/.cache/ttp-lifecycle-vm scripts/vm/lifecycle/run.sh
#
# Writes captures, state snapshots and results.txt into $VM_WORK; exits non-zero
# if any check fails. Needs KVM, qemu-system-x86_64, genisoimage and curl; no root.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
: "${VM_WORK:?set VM_WORK to a working directory with a few GB free}"
mkdir -p "$VM_WORK"
# shellcheck source=scripts/vm/lifecycle/vm.sh
source "$HERE/vm.sh"

PROBE_DST=198.51.100.7
RESULTS="$VM_WORK/results.txt"
# Outputs of an earlier run must not be read as this run's: a stale
# ttp-start-failure.txt already misled once.
rm -f "${VM_WORK:?}"/*.pcap "${VM_WORK:?}"/state-*.txt "${VM_WORK:?}/ttp-start-failure.txt"
: >"$RESULTS"
FAILED=0

check() { # check <name> <pass|fail> <detail>
    printf '%-4s %-44s %s\n' "$(tr '[:lower:]' '[:upper:]' <<<"$2")" "$1" "$3" | tee -a "$RESULTS"
    [ "$2" = pass ] || FAILED=1
}

hits() { python3 "$HERE/egress.py" "$VM_WORK/$1.pcap" --net "${2:-10.0.2.0/24}" --hits "$PROBE_DST"; }

probe_start() { # the probe runs as the unprivileged, non-bypassed login user
    vm_ssh "sudo systemd-run --quiet --uid=ttp --unit=ttp-probe python3 /usr/local/lib/ttp-probe.py"
}

probe_stop() { vm_ssh 'sudo systemctl stop ttp-probe 2>/dev/null || true'; }

# The probe is stopped across `ttp start`: it is not what is being measured
# while Tor bootstraps, and a failed start should not have to rule it out.
ttp_start() {
    probe_stop
    if ! vm_ssh 'sudo ttp start --bootstrap-timeout 300 >/tmp/ttp-start.log 2>&1'; then
        vm_ssh 'cat /tmp/ttp-start.log; sudo journalctl -u ttp-tor --no-pager -n 60' \
            >"$VM_WORK/ttp-start-failure.txt" 2>&1 || true
        vm_log "ttp start failed; see ttp-start-failure.txt"
        return 1
    fi
    probe_start
}

snapshot() { vm_snapshot_state >"$VM_WORK/state-$1.txt" 2>&1 || true; }

state_is() { grep -A1 "^## inet ttp present" "$VM_WORK/state-$1.txt" | tail -1; }

trap 'vm_kill' EXIT

# --- setup -------------------------------------------------------------------
vm_kill # a VM left running by an earlier run holds the disk this one recreates
vm_fetch_image
vm_prepare
vm_boot
vm_wait_ready 600
vm_install_ttp "$ROOT"
vm_ssh 'sudo tee /usr/local/lib/ttp-probe.py >/dev/null' <"$HERE/probe.py"

# --- positive control: the capture must see the probe when nothing contains it
probe_start
vm_capture_start c0-control
sleep 5
vm_capture_stop
n="$(hits c0-control)"
if [ "$n" -gt 0 ]; then
    check "positive control (no TTP)" pass "$n probe packet(s) seen"
else
    check "positive control (no TTP)" fail "0 probe packets: the capture is not measuring, nothing below means anything"
    exit 1
fi

# --- steady state: the same probe, contained ---------------------------------
ttp_start
vm_capture_start s1-session
sleep 10
vm_capture_stop
n="$(hits s1-session)"
if [ "$n" -eq 0 ]; then
    check "active session" pass "0 probe packets"
else
    check "active session" fail "$n probe packet(s) escaped"
fi

# --- shutdown with an active session -------------------------------------------
vm_capture_start s2-poweroff
vm_ssh 'sudo systemctl poweroff' || true
vm_wait_exit 180
n="$(hits s2-poweroff)"
if [ "$n" -eq 0 ]; then
    check "poweroff with active session" pass "0 probe packets until power-off"
else
    check "poweroff with active session" fail "$n probe packet(s) escaped while shutting down"
fi

# --- reboot with an active session ---------------------------------------------
# The session lives in /run and does not survive a reboot. What is checked is
# that the host comes back in ONE defined state - no half-session with rules
# and no Tor, or an overlay and no rules - and that the cleartext it is then in
# is visible to the probe, i.e. that the capture after a reboot still measures.
vm_boot
vm_wait_ready 300
ttp_start
vm_capture_start s3-reboot
vm_ssh 'sudo systemctl reboot' || true
sleep 5
vm_wait_ready 300
probe_start
sleep 10
vm_capture_stop
snapshot after-reboot
if [ "$(state_is after-reboot)" = no ] &&
    grep -q "Status: INACTIVE" "$VM_WORK/state-after-reboot.txt" &&
    ! grep -q "tmpfs\[/ttp/resolv.conf\]" "$VM_WORK/state-after-reboot.txt"; then
    check "reboot leaves one defined state" pass "session ended cleanly: no table, no overlay, status INACTIVE"
else
    check "reboot leaves one defined state" fail "partial session state after reboot, see state-after-reboot.txt"
fi
n="$(hits s3-reboot)"
if [ "$n" -gt 0 ]; then
    check "after reboot the host is in cleartext" pass "$n probe packet(s): expected, recorded"
else
    check "after reboot the host is in cleartext" fail "0 probe packets after reboot: capture not measuring"
fi

# --- suspend/resume onto a different network -----------------------------------
ttp_start
vm_ssh 'sudo systemctl suspend' || true
sleep 10
vm_monitor system_wakeup >/dev/null
sleep 3
vm_swap_network 192.168.77.0/24
vm_capture_start s4-resume-newnet
vm_wait_ready 120
sleep 15
vm_capture_stop
snapshot after-resume
n="$(hits s4-resume-newnet 192.168.77.0/24)"
if [ "$n" -eq 0 ]; then
    check "resume onto a new network" pass "0 probe packets"
else
    check "resume onto a new network" fail "$n probe packet(s) escaped after resume"
fi
if [ "$(state_is after-resume)" = yes ] && grep -q "Status: ACTIVE" "$VM_WORK/state-after-resume.txt"; then
    check "session survives suspend/resume" pass "status ACTIVE, table present"
else
    check "session survives suspend/resume" fail "see state-after-resume.txt"
fi

exit "$FAILED"
