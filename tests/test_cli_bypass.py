# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.cli - CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from ttp.cli import app

runner = CliRunner()


def _mock_cmd_tokens(cmd: object) -> list[str]:
    """Split mocked subprocess.run argv into tokens (avoids substring `in` on raw cmd)."""
    if isinstance(cmd, str):
        return cmd.split()
    if isinstance(cmd, (list, tuple)):
        return [str(arg) for arg in cmd]
    return str(cmd).split()


@pytest.fixture(autouse=True)
def _mock_logging():
    with patch("ttp.cli._setup_logging"):
        yield


@pytest.fixture(autouse=True)
def _mock_tmpfs_preflight():
    """start() calls check_tmpfs_space(); mock so CLI tests stay hermetic."""
    with patch("ttp.state.check_tmpfs_space"):
        yield


@pytest.fixture(autouse=True)
def _mock_root_euid():
    """Most CLI commands require root; mock geteuid to 0 by default."""
    with patch("os.geteuid", return_value=0):
        yield


# start


@patch("os.geteuid", return_value=1000)
def test_bypass_requires_root(mock_euid):
    """bypass without root -> exit code 1."""
    result = runner.invoke(app, ["bypass", "curl", "http://example.com"])
    assert result.exit_code == 1
    assert "must be run with sudo" in result.output
    assert mock_euid.call_count == 1


@patch("os.path.exists", return_value=False)
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
def test_bypass_requires_systemd(mock_exists):
    """bypass fails if systemd is missing."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "requires systemd" in result.output
    assert mock_exists.call_count == 1


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value=None)
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
def test_bypass_requires_active_session(mock_read, mock_exists):
    """bypass fails if no TTP session is active."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "no active session" in result.output.lower()
    assert mock_read.call_count == 1


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {}, clear=True)
def test_bypass_requires_sudo_env(mock_read, mock_exists):
    """bypass fails if SUDO_UID or SUDO_GID is missing."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "must be run with sudo" in result.output


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
@patch("ttp.commands.admin.resolve_optional", return_value=None)
def test_bypass_requires_systemd_run(mock_which, mock_read, mock_exists):
    """bypass fails if systemd-run is missing."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "systemd-run' command is required" in result.output
    assert mock_which.call_count == 1


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
@patch("ttp.commands.admin.resolve_optional", return_value="/usr/bin/systemd-run")
@patch("subprocess.run")
def test_bypass_happy_path(mock_run, mock_which, mock_read, mock_exists):
    """bypass runs systemd-run and returns its exit code."""
    mock_run.return_value = MagicMock(returncode=42)
    result = runner.invoke(app, ["bypass", "curl", "http://example.com"])
    assert result.exit_code == 42
    assert mock_run.call_count == 1

    argv = mock_run.call_args[0][0]
    assert argv[0] == "/usr/bin/systemd-run"
    assert "--uid=1000" in argv
    assert "--gid=1000" in argv
    assert "--slice=ttp-bypass" in argv
    assert "--scope" in argv
    assert argv[argv.index("--") + 1 :] == ["curl", "http://example.com"]
