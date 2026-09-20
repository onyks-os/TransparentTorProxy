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
    """bypass fails if systemd is missing.

    The assertion is on *which path* the guard interrogated, not on how many
    times ``os.path.exists`` was called. The patch is global, so the call count
    also counts whatever the interpreter, Typer and Rich happen to stat on the
    way through - a number that is not ours to predict and that has no bearing
    on whether the guard works.
    """
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "requires systemd" in result.output
    assert any(call.args and call.args[0] == "/run/systemd/system" for call in mock_exists.call_args_list)


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
@patch(
    "ttp.commands.admin.resolve_optional",
    side_effect=lambda name: {
        "systemd-run": "/usr/bin/systemd-run",
        "setpriv": "/usr/bin/setpriv",
    }[name],
)
@patch("subprocess.run")
def test_bypass_happy_path(mock_run, mock_which, mock_read, mock_exists):
    """bypass runs systemd-run and returns its exit code."""
    mock_run.return_value = MagicMock(returncode=42)
    result = runner.invoke(app, ["bypass", "curl", "http://example.com"])
    assert result.exit_code == 42
    assert mock_run.call_count == 1

    argv = mock_run.call_args[0][0]
    assert argv[0] == "/usr/bin/systemd-run"
    assert "--slice=ttp-bypass" in argv
    assert "--scope" in argv
    assert argv[argv.index("--") + 1 :] == [
        "/usr/bin/setpriv",
        "--reuid=1000",
        "--regid=1000",
        "--init-groups",
        "--",
        "curl",
        "http://example.com",
    ]


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
@patch(
    "ttp.commands.admin.resolve_optional",
    side_effect=lambda name: {
        "systemd-run": "/usr/bin/systemd-run",
        "setpriv": "/usr/bin/setpriv",
    }[name],
)
@patch("subprocess.run")
def test_bypass_resets_the_supplementary_group_vector(mock_run, mock_which, mock_read, mock_exists):
    """The drop must reset groups, not only uid and gid.

    systemd-run --scope execs the command itself -- setresgid, setresuid,
    execvpe -- and never calls initgroups(), so --uid/--gid alone leaves
    root's supplementary groups (gid 0 at minimum, and whatever else root is
    a member of) on a process the docstring says is de-escalated.
    """
    mock_run.return_value = MagicMock(returncode=0)
    runner.invoke(app, ["bypass", "id"])

    argv = mock_run.call_args[0][0]
    assert "--init-groups" in argv
    # The credential change belongs to setpriv now, not to systemd-run.
    assert not any(a.startswith("--uid=") for a in argv)
    assert not any(a.startswith("--gid=") for a in argv)


# ---------------------------------------------------------------------------
# The numeric guard on SUDO_UID / SUDO_GID
# ---------------------------------------------------------------------------
#
# `bypass` interpolates these straight into `systemd-run --uid=... --gid=...`,
# and they come from the environment, which the invoking user controls. The
# `.isdigit()` check (`admin.py:145-150`) is what constrains them to the
# numeric form. It is the only thing standing between an attacker-chosen
# environment and the identity the bypassed process runs as - so it needs a
# test that fails if the check is removed, not just coverage of the line.


@pytest.mark.parametrize(
    ("uid", "gid", "case"),
    [
        pytest.param("root", "1000", "uid-as-name", id="uid-is-a-name"),
        pytest.param("1000", "root", "gid-as-name", id="gid-is-a-name"),
        pytest.param("0 --property=User=root", "1000", "uid-with-flags", id="uid-carries-flags"),
        pytest.param("-1", "1000", "negative", id="uid-is-negative"),
    ],
)
@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.commands.admin.resolve_optional", return_value="/usr/bin/systemd-run")
@patch("subprocess.run")
def test_bypass_refuses_a_non_numeric_sudo_identity(mock_run, mock_which, mock_read, mock_exists, uid, gid, case):
    """A non-numeric UID/GID must be rejected before it reaches systemd-run.

    `--uid=` is not restricted to numbers by systemd-run itself, so a value
    that survives this check is a value that decides which identity the
    bypassed - and therefore un-proxied - process runs as.

    The assertion that matters is the second one: `subprocess.run` was never
    reached. Exiting 1 while still having built and executed the command would
    satisfy the exit code and defeat the purpose.
    """
    with patch.dict("os.environ", {"SUDO_UID": uid, "SUDO_GID": gid}):
        result = runner.invoke(app, ["bypass", "curl"])

    assert result.exit_code == 1, case
    assert "must be numeric" in result.output
    assert mock_run.call_count == 0, f"{case}: the tainted value reached systemd-run"


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
@patch("ttp.commands.admin.resolve_optional", return_value="/usr/bin/systemd-run")
@patch("subprocess.run", side_effect=OSError("systemd-run: Permission denied"))
def test_bypass_reports_a_failed_execution_instead_of_reporting_success(mock_run, mock_which, mock_read, mock_exists):
    """If systemd-run cannot be executed the process never ran under the bypass
    slice. Exiting 0 here would tell the user their command ran unproxied when
    it did not run at all (`admin.py:186-188`)."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "Execution Failure" in result.output
    assert "Permission denied" in result.output


@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.commands.admin.resolve_optional", return_value="/usr/bin/systemd-run")
@patch("subprocess.run")
@patch.dict("os.environ", {"SUDO_UID": "", "SUDO_GID": "1000"})
def test_bypass_refuses_an_empty_sudo_identity(mock_run, mock_which, mock_read, mock_exists):
    """An empty SUDO_UID is caught one guard earlier, by the falsy check at
    `admin.py:138`, so it reports the execution context rather than the numeric
    format. Same refusal, different message - asserted separately so the two
    guards stay distinguishable if either one moves."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "Invalid Execution Context" in result.output
    assert mock_run.call_count == 0
