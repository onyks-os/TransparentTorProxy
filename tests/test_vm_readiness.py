# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""A reachable SSH server cannot mask failed guest provisioning."""

import os
import subprocess

import pytest


@pytest.mark.parametrize("status", [0, 1, 124])
def test_cloud_init_must_complete_successfully(tmp_path, status):
    result = subprocess.run(
        [
            "bash",
            "-c",
            """
source scripts/vm/lifecycle/vm.sh
vm_ssh() {
    case "$1" in
        true) return 0 ;;
        *'cloud-init status'*) echo provisioning-evidence; return "$READINESS_STATUS" ;;
        *) echo guest-diagnostics; return 0 ;;
    esac
}
vm_wait_ready 5
""",
        ],
        env={**os.environ, "VM_WORK": str(tmp_path), "VM_DISTRO": "debian", "READINESS_STATUS": str(status)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    evidence = (tmp_path / "cloud-init.txt").read_text()
    assert "provisioning-evidence" in evidence
    if status == 0:
        assert result.returncode == 0
        assert "guest ready" in result.stderr
    else:
        assert result.returncode != 0
        assert "guest ready" not in result.stderr
        assert "guest-diagnostics" in evidence
