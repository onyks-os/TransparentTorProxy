# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Opt-in private-bus tests; never contact a real desktop session."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.real_binary_lookup,
    pytest.mark.skipif(
        os.environ.get("TTP_NOTIFICATION_INTEGRATION") != "1",
        reason="Run only in the disposable notification container",
    ),
]


@pytest.mark.parametrize("mode,state", [("accept", "accepted"), ("timeout", "unconfirmed")])
def test_real_desktop_protocol_acceptance_and_ambiguous_timeout(tmp_path, mode, state):
    assert os.geteuid() != 0
    output = tmp_path / "receipt.json"
    fixture = Path(__file__).parent / "fixtures" / "notification_probe.py"
    response = subprocess.run(
        ["/usr/bin/dbus-run-session", "--", sys.executable, str(fixture), str(output), mode],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert response.returncode == 0, response.stdout + response.stderr
    assert json.loads(output.read_text())["state"] == state
