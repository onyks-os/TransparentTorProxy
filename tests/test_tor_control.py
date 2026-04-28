"""Tests for ttp.tor_control — Tor interaction logic.

All external network calls and Stem interactions are mocked.
"""

import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from ttp import tor_control
from ttp.exceptions import TorError

# Stem might not be installed, so we mock it completely in tests
try:
    from stem import Signal
except ImportError:
    Signal = MagicMock()


# ── get_exit_ip ────────────────────────────────────────────────────


@patch("ttp.tor_control.urllib.request.urlopen")
def test_get_exit_ip_success(mock_urlopen):
    """get_exit_ip parses JSON from the first responding endpoint."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"IsTor": true, "IP": "1.2.3.4"}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    assert tor_control.get_exit_ip() == "1.2.3.4"


@patch("ttp.tor_control.urllib.request.urlopen")
def test_get_exit_ip_failure(mock_urlopen):
    """get_exit_ip returns 'unknown' when all endpoints fail."""
    mock_urlopen.side_effect = urllib.error.URLError("Network unreachable")
    assert tor_control.get_exit_ip() == "unknown"


@patch("ttp.tor_control.urllib.request.urlopen")
def test_get_exit_ip_fallback(mock_urlopen):
    """get_exit_ip falls back to secondary endpoint when primary fails."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"ip": "5.6.7.8"}'
    mock_urlopen.side_effect = [
        urllib.error.URLError("Primary down"),  # check.torproject.org fails
        MagicMock(__enter__=MagicMock(return_value=mock_resp)),  # ipify works
    ]
    assert tor_control.get_exit_ip() == "5.6.7.8"


# ── get_controller ─────────────────────────────────────────────────


@patch("ttp.tor_control.os.path.exists", return_value=True)
@patch("ttp.tor_control.Controller")
def test_get_controller_unix_socket(mock_controller_cls, mock_exists):
    """get_controller prefers the Unix socket if it exists."""
    mock_ctrl = MagicMock()
    mock_controller_cls.from_socket_file.return_value = mock_ctrl

    ctrl = tor_control.get_controller()
    assert ctrl is mock_ctrl
    mock_ctrl.authenticate.assert_called_once()
    mock_controller_cls.from_port.assert_not_called()


@patch("ttp.tor_control.os.path.exists", return_value=False)
@patch("ttp.tor_control.Controller")
def test_get_controller_tcp_port(mock_controller_cls, mock_exists):
    """get_controller falls back to TCP port 9051 if Unix socket doesn't exist."""
    mock_ctrl = MagicMock()
    mock_controller_cls.from_port.return_value = mock_ctrl

    ctrl = tor_control.get_controller()
    assert ctrl is mock_ctrl
    mock_ctrl.authenticate.assert_called_once()
    mock_controller_cls.from_socket_file.assert_not_called()


@patch("ttp.tor_control.os.path.exists", return_value=True)
@patch("ttp.tor_control.Controller")
def test_get_controller_socket_auth_fails(mock_controller_cls, mock_exists):
    """If Unix socket fails authentication, it falls back to TCP."""
    mock_socket_ctrl = MagicMock()
    mock_socket_ctrl.authenticate.side_effect = Exception("Auth failed")
    mock_controller_cls.from_socket_file.return_value = mock_socket_ctrl

    mock_tcp_ctrl = MagicMock()
    mock_controller_cls.from_port.return_value = mock_tcp_ctrl

    ctrl = tor_control.get_controller()
    assert ctrl is mock_tcp_ctrl
    mock_controller_cls.from_port.assert_called_once_with(port=9051)


# ── wait_for_bootstrap ─────────────────────────────────────────────


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_controller")
def test_wait_for_bootstrap_success(mock_get_ctrl, mock_sleep):
    """wait_for_bootstrap succeeds when PROGRESS=100 is reached."""
    mock_ctrl = MagicMock()
    # First call returns 80%, second call returns 100%
    mock_ctrl.get_info.side_effect = [
        'NOTICE BOOTSTRAP PROGRESS=80 TAG=conn_or SUMMARY="Connecting to the Tor network"',
        'NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"',
    ]
    mock_get_ctrl.return_value = mock_ctrl

    # Using a list to capture progress values
    progress_values = []

    result = tor_control.wait_for_bootstrap(
        progress_callback=lambda x: progress_values.append(x)
    )

    assert result is True
    assert progress_values == [80, 100]


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_controller", return_value=None)
def test_wait_for_bootstrap_no_controller(mock_get_ctrl, mock_sleep):
    """wait_for_bootstrap raises TorError if it can't connect to Tor."""
    with pytest.raises(TorError, match="Could not connect"):
        tor_control.wait_for_bootstrap()


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_controller")
def test_wait_for_bootstrap_timeout(mock_get_ctrl, mock_sleep):
    """wait_for_bootstrap raises TorError if it doesn't reach 100% in 60s."""
    mock_ctrl = MagicMock()
    mock_ctrl.get_info.return_value = "PROGRESS=50"
    mock_get_ctrl.return_value = mock_ctrl

    with pytest.raises(TorError, match="timed out"):
        tor_control.wait_for_bootstrap()


# ── verify_tor ─────────────────────────────────────────────────────


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.urllib.request.urlopen")
def test_verify_tor_success(mock_urlopen, mock_sleep):
    """verify_tor returns (True, IP) when the primary endpoint responds."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"IsTor": true, "IP": "8.8.8.8"}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    is_tor, ip = tor_control.verify_tor()
    assert is_tor is True
    assert ip == "8.8.8.8"


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.urllib.request.urlopen")
def test_verify_tor_retries(mock_urlopen, mock_sleep):
    """verify_tor retries all endpoints across all attempts before giving up."""
    mock_urlopen.side_effect = urllib.error.URLError("Timeout")

    is_tor, ip = tor_control.verify_tor()

    assert is_tor is False
    assert ip == "unknown"
    # 5 attempts × 3 endpoints = 15 calls
    assert mock_urlopen.call_count == 15


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.urllib.request.urlopen")
def test_verify_tor_fallback_endpoint(mock_urlopen, mock_sleep):
    """verify_tor falls back to secondary endpoint when primary is down."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"ip": "9.9.9.9"}'
    mock_urlopen.side_effect = [
        urllib.error.URLError("Primary down"),  # check.torproject.org
        MagicMock(__enter__=MagicMock(return_value=mock_resp)),  # ipify
    ]

    is_tor, ip = tor_control.verify_tor()
    assert is_tor is True
    assert ip == "9.9.9.9"


# ── request_new_circuit ────────────────────────────────────────────


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_exit_ip")
@patch("ttp.tor_control.get_controller")
def test_request_new_circuit_success(mock_get_ctrl, mock_get_ip, mock_sleep):
    """request_new_circuit returns (True, new_ip) when IP changes."""
    mock_ctrl = MagicMock()
    mock_get_ctrl.return_value = mock_ctrl

    # First call to get_exit_ip gets old IP. Second call gets old IP (simulating delay).
    # Third call gets new IP.
    mock_get_ip.side_effect = ["1.1.1.1", "1.1.1.1", "2.2.2.2"]

    changed, new_ip = tor_control.request_new_circuit()

    assert changed is True
    assert new_ip == "2.2.2.2"
    mock_ctrl.signal.assert_called_once()


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_exit_ip")
@patch("ttp.tor_control.get_controller")
def test_request_new_circuit_timeout(mock_get_ctrl, mock_get_ip, mock_sleep):
    """request_new_circuit returns (False, old_ip) if IP doesn't change."""
    mock_ctrl = MagicMock()
    mock_get_ctrl.return_value = mock_ctrl
    mock_get_ip.return_value = "1.1.1.1"  # IP never changes

    changed, new_ip = tor_control.request_new_circuit()

    assert changed is False
    assert new_ip == "1.1.1.1"
