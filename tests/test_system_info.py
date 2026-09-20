# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.system_info - diagnostic data gathering."""

from unittest.mock import MagicMock, patch

from ttp.system_info import collect_diagnostics


@patch("ttp.system_info.subprocess.run")
@patch("ttp.system_info.tor_control.get_controller")
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.tor_detect.detect_tor",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
    },
)
def test_collect_diagnostics_has_all_keys(mock_detect, mock_read, mock_ctrl, mock_run):
    """It should return a dictionary with all expected keys."""
    mock_run.return_value = MagicMock(stdout="mocked output", returncode=0)

    result = collect_diagnostics()

    expected_keys = {
        "os",
        "tor_service",
        "torrc",
        "nftables",
        "dns",
        "control_interface",
        "ttp_state",
    }

    assert set(result.keys()) == expected_keys


@patch("ttp.system_info.subprocess.run")
@patch("ttp.system_info.tor_control.get_controller", return_value=None)
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.tor_detect.detect_tor",
    return_value={
        "is_installed": False,
        "is_running": False,
        "is_configured": False,
        "tor_user": "unknown",
    },
)
def test_collect_diagnostics_subprocess_failure_does_not_crash(mock_detect, mock_read, mock_ctrl, mock_run):
    """It should not crash if subprocesses raise exceptions.
    Instead, it should store the error message in the dictionary.
    """
    # Simulate a missing command (e.g. systemctl or nft not found)
    mock_run.side_effect = FileNotFoundError("No such file or directory: 'nft'")

    result = collect_diagnostics()

    # The dictionary should still be returned successfully
    assert isinstance(result, dict)

    # The error should be caught and stored as a string
    assert "No such file or directory" in result["nftables"]
    assert "No such file or directory" in result["tor_service"]


@patch("ttp.system_info.subprocess.run")
@patch("ttp.system_info.tor_control.get_controller", return_value=None)
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.tor_detect.detect_tor",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
    },
)
def test_collect_diagnostics_returns_only_strings(mock_detect, mock_read, mock_ctrl, mock_run):
    """It should return only strings, no Rich objects or other complex types."""
    mock_run.return_value = MagicMock(stdout="standard output", returncode=0)

    result = collect_diagnostics()

    for key, value in result.items():
        assert isinstance(key, str)
        assert isinstance(value, str), f"Value for {key} is not a string: {type(value)}"


@patch("ttp.system_info.subprocess.run")
@patch("ttp.system_info.tor_control.get_controller", return_value=None)
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.tor_detect.detect_tor",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "toranon",
        "is_fedora": True,
        "selinux": True,
        "selinux_module": True,
    },
)
def test_collect_diagnostics_includes_selinux_info(mock_detect, mock_read, mock_ctrl, mock_run):
    """It should include SELinux module status in the diagnostic output."""
    mock_run.return_value = MagicMock(stdout="standard output", returncode=0)

    result = collect_diagnostics()
    ttp_state = result["ttp_state"]

    assert "OS Family: Fedora/RedHat" in ttp_state
    assert "SELinux Enforcing: True" in ttp_state
    assert "SELinux Module: INSTALLED" in ttp_state


# ---------------------------------------------------------------------------
# Probes. Each of these gates a privileged decision, so "I could not tell"
# must read as False rather than propagate or guess.
# ---------------------------------------------------------------------------


import subprocess  # noqa: E402

import pytest  # noqa: E402

from ttp import system_info  # noqa: E402


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        pytest.param("Enforcing\n", True, id="enforcing"),
        pytest.param("Permissive\n", False, id="permissive"),
        pytest.param("Disabled\n", False, id="disabled"),
    ],
)
def test_is_selinux_enforcing_reads_getenforce(stdout: str, expected: bool) -> None:
    with (
        patch("ttp.system_info.resolve_optional", return_value="/usr/sbin/getenforce"),
        patch("ttp.system_info.subprocess.run", return_value=MagicMock(stdout=stdout)),
    ):
        assert system_info.is_selinux_enforcing() is expected


@pytest.mark.parametrize(
    "failure",
    [subprocess.SubprocessError("boom"), FileNotFoundError("getenforce")],
    ids=["subprocess-error", "missing-binary"],
)
def test_is_selinux_enforcing_is_false_when_it_cannot_tell(failure: Exception) -> None:
    with (
        patch("ttp.system_info.resolve_optional", return_value="/usr/sbin/getenforce"),
        patch("ttp.system_info.subprocess.run", side_effect=failure),
    ):
        assert system_info.is_selinux_enforcing() is False


def test_is_selinux_enforcing_is_false_without_the_binary() -> None:
    """A host with no getenforce is not enforcing, and must not be probed."""
    with (
        patch("ttp.system_info.resolve_optional", return_value=None),
        patch("ttp.system_info.subprocess.run") as run,
    ):
        assert system_info.is_selinux_enforcing() is False
    run.assert_not_called()


def test_is_selinux_module_installed_matches_the_exact_version() -> None:
    """A different version of the module is not the one TTP ships."""
    with patch("ttp.system_info.resolve_optional", return_value="/usr/sbin/semodule"):
        with patch("ttp.system_info.subprocess.run", return_value=MagicMock(stdout="ttp_tor_policy 1.2\n")):
            assert system_info.is_selinux_module_installed() is True
        with patch("ttp.system_info.subprocess.run", return_value=MagicMock(stdout="ttp_tor_policy 1.1\n")):
            assert system_info.is_selinux_module_installed() is False


def test_is_selinux_module_installed_is_false_when_semodule_fails() -> None:
    with (
        patch("ttp.system_info.resolve_optional", return_value="/usr/sbin/semodule"),
        patch("ttp.system_info.subprocess.run", side_effect=subprocess.SubprocessError("boom")),
    ):
        assert system_info.is_selinux_module_installed() is False


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param('ID=fedora\nPRETTY_NAME="Fedora 44"\n', True, id="fedora"),
        pytest.param('ID=rhel\nPRETTY_NAME="RHEL 9"\n', True, id="rhel"),
        pytest.param('ID=debian\nPRETTY_NAME="Debian 13"\n', False, id="debian"),
    ],
)
def test_is_fedora_family_reads_os_release(content: str, expected: bool, tmp_path) -> None:
    release = tmp_path / "os-release"
    release.write_text(content, encoding="utf-8")
    with patch("ttp.system_info.Path", return_value=release):
        assert system_info.is_fedora_family() is expected


def test_is_fedora_family_is_false_when_os_release_is_unreadable(tmp_path) -> None:
    release = tmp_path / "os-release"
    release.write_text("ID=fedora\n", encoding="utf-8")
    with (
        patch("ttp.system_info.Path", return_value=release),
        patch.object(type(release), "read_text", side_effect=OSError("permission denied")),
    ):
        assert system_info.is_fedora_family() is False
