#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Guest-only mutation, called after a real managed start with required watchdog.
# The caller records packets outside this disposable guest during the mutation.
set -euo pipefail
python3 - <<'PY'
import time
from ttp import state
from ttp.apparmor import observe
from ttp.session_report import observe_session

lock = state.read_lock(strict=True)
assert lock['apparmor'] == {'required': True, 'profile': 'ttp-tor'}
assert observe(lock['apparmor'], lock['tor_uid'])['state'] == 'unverified'
deadline = time.monotonic() + 40
while True:
    report = observe_session()
    if report['health'] == 'emergency_verified':
        assert any(item['component'] == 'apparmor' for item in report['emergency']['causes'])
        print(report, flush=True)
        break
    assert time.monotonic() < deadline, report
    time.sleep(1)
PY
apparmor_parser --replace --skip-cache /run/ttp/ttp-tor.apparmor
set +e
ttp check
code=$?
set -e
test "$code" = 7  # Reinstating enforce mode cannot clear the emergency latch.
