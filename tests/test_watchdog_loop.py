# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The legacy loop was replaced by test_supervision_contract.py.

Verify the public entry point cannot bypass session policy, readiness or the
persistent emergency coordinator.
"""

from ttp import watchdog
from ttp.watchdog.supervisor import run_supervisor


def test_public_supervisor_is_the_contract_implementation():
    assert watchdog.run_supervisor is run_supervisor
    assert not hasattr(watchdog, "run_watchdog_loop")
