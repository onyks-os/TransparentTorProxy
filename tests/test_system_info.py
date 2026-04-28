"""Tests for ttp.system_info — diagnostic data gathering."""

from unittest.mock import MagicMock, patch

from ttp.system_info import collect_diagnostics


@patch("ttp.system_info.subprocess.run")
@patch("ttp.system_info._get_service_name", return_value="tor@default")
@patch("ttp.system_info.dns.detect_dns_mode", return_value="resolvectl")
@patch("ttp.system_info.tor_control.get_controller")
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.system_info.detect_tor",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
    },
)
def test_collect_diagnostics_has_all_keys(
    mock_detect, mock_read, mock_ctrl, mock_dns, mock_svc, mock_run
):
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
@patch("ttp.system_info._get_service_name", return_value="tor")
@patch("ttp.system_info.dns.detect_dns_mode", return_value="resolvectl")
@patch("ttp.system_info.tor_control.get_controller", return_value=None)
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.system_info.detect_tor",
    return_value={
        "is_installed": False,
        "is_running": False,
        "is_configured": False,
        "tor_user": "unknown",
    },
)
def test_collect_diagnostics_subprocess_failure_does_not_crash(
    mock_detect, mock_read, mock_ctrl, mock_dns, mock_svc, mock_run
):
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
@patch("ttp.system_info._get_service_name", return_value="tor")
@patch("ttp.system_info.dns.detect_dns_mode", return_value="resolvectl")
@patch("ttp.system_info.tor_control.get_controller", return_value=None)
@patch("ttp.system_info.state.read_lock", return_value=None)
@patch(
    "ttp.system_info.detect_tor",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
    },
)
def test_collect_diagnostics_returns_only_strings(
    mock_detect, mock_read, mock_ctrl, mock_dns, mock_svc, mock_run
):
    """It should return only strings, no Rich objects or other complex types."""
    mock_run.return_value = MagicMock(stdout="standard output", returncode=0)

    result = collect_diagnostics()

    for key, value in result.items():
        assert isinstance(key, str)
        assert isinstance(value, str), f"Value for {key} is not a string: {type(value)}"
