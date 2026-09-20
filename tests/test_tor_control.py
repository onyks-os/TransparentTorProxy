# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.tor_control - Tor interaction logic.

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


# get_exit_ip


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


# get_controller


@patch("ttp.tor_control.os.path.exists", return_value=True)
@patch("ttp.tor_control.Controller")
def test_get_controller_unix_socket(mock_controller_cls, mock_exists):
    """get_controller connects only via the TTP private Unix socket."""
    mock_ctrl = MagicMock()
    mock_controller_cls.from_socket_file.return_value = mock_ctrl

    ctrl = tor_control.get_controller()
    assert ctrl is mock_ctrl
    mock_controller_cls.from_socket_file.assert_called_once_with("/run/tor/ttp/control.sock")
    mock_ctrl.authenticate.assert_called_once()
    mock_controller_cls.from_port.assert_not_called()


@patch("ttp.tor_control.os.path.exists", return_value=False)
@patch("ttp.tor_control.Controller")
def test_get_controller_no_socket_returns_none(mock_controller_cls, mock_exists):
    """get_controller returns None if the TTP control socket is absent."""
    assert tor_control.get_controller() is None
    mock_controller_cls.from_socket_file.assert_not_called()
    mock_controller_cls.from_port.assert_not_called()


@patch("ttp.tor_control.os.path.exists", return_value=True)
@patch("ttp.tor_control.Controller")
def test_get_controller_socket_auth_fails_returns_none(mock_controller_cls, mock_exists):
    """If TTP socket auth fails, get_controller returns None (no system Tor fallback)."""
    import stem.connection

    mock_socket_ctrl = MagicMock()
    mock_socket_ctrl.authenticate.side_effect = stem.connection.AuthenticationFailure("Auth failed")
    mock_controller_cls.from_socket_file.return_value = mock_socket_ctrl

    ctrl = tor_control.get_controller()
    assert ctrl is None
    mock_controller_cls.from_port.assert_not_called()


# wait_for_bootstrap


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

    result = tor_control.wait_for_bootstrap(progress_callback=lambda x: progress_values.append(x))

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


# verify_tor


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
    # 5 attempts x 3 endpoints = 15 calls
    assert mock_urlopen.call_count == 15


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.urllib.request.urlopen")
def test_verify_tor_fallback_endpoint(mock_urlopen, mock_sleep):
    """verify_tor falls back to secondary endpoint when primary is down and returns is_tor=False."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"ip": "9.9.9.9"}'
    mock_urlopen.side_effect = [
        urllib.error.URLError("Primary down"),  # check.torproject.org
        MagicMock(__enter__=MagicMock(return_value=mock_resp)),  # ipify
    ]

    is_tor, ip = tor_control.verify_tor()
    assert is_tor is False
    assert ip == "9.9.9.9"


# request_new_circuit


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


# graceful_shutdown


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_controller")
def test_graceful_shutdown_success(mock_get_ctrl, mock_sleep):
    """graceful_shutdown sends SHUTDOWN signal and returns True."""
    mock_ctrl = MagicMock()
    # First call: send signal. Subsequent calls: Tor is gone (None).
    mock_get_ctrl.side_effect = [mock_ctrl, None]

    result = tor_control.graceful_shutdown(timeout=5)

    assert result is True
    mock_ctrl.signal.assert_called_once_with(Signal.SHUTDOWN)


@patch("ttp.tor_control.get_controller", return_value=None)
def test_graceful_shutdown_no_controller(mock_get_ctrl):
    """graceful_shutdown returns False when no controller is available."""
    result = tor_control.graceful_shutdown()
    assert result is False


@patch("ttp.tor_control.time.sleep")
@patch("ttp.tor_control.get_controller")
def test_graceful_shutdown_signal_exception(mock_get_ctrl, mock_sleep):
    """graceful_shutdown returns False if signal raises an exception."""
    import stem

    mock_ctrl = MagicMock()
    mock_ctrl.signal.side_effect = stem.ControllerError("Connection lost")
    mock_ctrl.__enter__ = MagicMock(return_value=mock_ctrl)
    mock_ctrl.__exit__ = MagicMock(return_value=False)
    mock_get_ctrl.return_value = mock_ctrl

    result = tor_control.graceful_shutdown(timeout=1)
    assert result is False


# ---------------------------------------------------------------------------
# Only check.torproject.org may assert IsTor, and only an address may be
# reported as one.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("index", [1, 2], ids=["ipify", "ifconfig-me"])
def test_a_fallback_reflector_cannot_assert_is_tor(index: int) -> None:
    """A fallback that answers with an IsTor field must not raise the verdict.

    The fallbacks are ordinary IP echo services with no Tor knowledge. Making
    check.torproject.org unreachable is free for anyone on the path -- it is
    also routinely rate-limited for Tor clients -- so field presence alone
    must never decide this.
    """
    responses = [None] * len(tor_control.VERIFY_ENDPOINTS)
    responses[index] = {"IsTor": True, "IP": "203.0.113.66"}

    def _fetch(endpoint: str):
        return responses[tor_control.VERIFY_ENDPOINTS.index(endpoint)]

    with (
        patch.object(tor_control, "_fetch_endpoint", side_effect=_fetch),
        patch("time.sleep"),
    ):
        is_tor, ip = tor_control.verify_tor()

    assert is_tor is False
    assert ip != "203.0.113.66"


def test_the_authoritative_endpoint_is_still_believed() -> None:
    with (
        patch.object(tor_control, "_fetch_endpoint", return_value={"IsTor": True, "IP": "185.220.101.7"}),
        patch("time.sleep"),
    ):
        assert tor_control.verify_tor() == (True, "185.220.101.7")


def test_a_censored_network_is_unchanged() -> None:
    """With the authoritative endpoint down, an honest fallback still reports."""
    responses = [None, {"ip": "198.51.100.9"}, None]

    def _fetch(endpoint: str):
        return responses[tor_control.VERIFY_ENDPOINTS.index(endpoint)]

    with (
        patch.object(tor_control, "_fetch_endpoint", side_effect=_fetch),
        patch("time.sleep"),
    ):
        assert tor_control.verify_tor() == (False, "198.51.100.9")


@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param("203.0.113.9[/bogus]", id="markup-tag"),
        pytest.param("203.0.113.9\x1bc", id="terminal-reset"),
        pytest.param("203.0.113.9\x1b[2J\x1b[H[TTP] Exit IP: 185.220.101.7", id="repaint"),
        pytest.param("....", id="not-an-address"),
        pytest.param("999.999.999.999", id="out-of-range"),
        pytest.param(12345, id="wrong-type"),
    ],
)
def test_a_reflector_value_that_is_not_an_address_never_reaches_a_caller(hostile) -> None:
    """These strings are rendered into Rich markup and onto a terminal.

    rich strips only BEL/BS/VT/FF/CR, never ESC, and an unbalanced markup tag
    raises MarkupError out of console.print -- aborting the command mid-output.
    """
    with patch.object(tor_control, "_fetch_endpoint", return_value={"ip": hostile}):
        assert tor_control.get_exit_ip() == tor_control.MALFORMED_ANSWER


def test_no_reply_and_a_malformed_reply_are_distinguishable() -> None:
    """Callers print a different message for "could not reach any endpoint"."""
    with (
        patch.object(tor_control, "_fetch_endpoint", return_value=None),
        patch("time.sleep"),
    ):
        assert tor_control.get_exit_ip() == tor_control.NO_ANSWER
    assert tor_control.NO_ANSWER != tor_control.MALFORMED_ANSWER


# ---------------------------------------------------------------------------
# Control-socket failure modes. Each must be a clean refusal, never a crash:
# the callers decide whether the session is usable on the back of these.
# ---------------------------------------------------------------------------


def test_get_controller_returns_none_without_stem() -> None:
    """stem is optional; its absence is not an error."""
    with patch.object(tor_control, "Controller", None):
        assert tor_control.get_controller() is None


@pytest.mark.parametrize(
    "exc_name",
    ["SocketError", "AuthenticationFailure", "ControllerError", "OSError"],
    ids=["unreachable", "auth-failed", "controller-error", "oserror"],
)
def test_get_controller_reports_every_failure_as_none(exc_name: str) -> None:
    """A failure to reach or authenticate the control socket yields None.

    Anything else would propagate into `ttp start` after the firewall is
    already applied.
    """
    import stem
    import stem.connection

    exc = {
        "SocketError": stem.SocketError("refused"),
        "AuthenticationFailure": stem.connection.AuthenticationFailure("bad cookie"),
        "ControllerError": stem.ControllerError("boom"),
        "OSError": OSError("no socket"),
    }[exc_name]

    fake = MagicMock()
    fake.from_socket_file.side_effect = exc
    with patch.object(tor_control, "Controller", fake):
        assert tor_control.get_controller() is None


def test_request_new_circuit_refuses_without_a_controller() -> None:
    with patch.object(tor_control, "get_controller", return_value=None):
        with pytest.raises(TorError, match="Cannot connect to Tor control interface"):
            tor_control.request_new_circuit()


def test_request_new_circuit_wraps_a_controller_error() -> None:
    import stem

    ctrl = MagicMock()
    ctrl.__enter__.return_value = ctrl
    ctrl.signal.side_effect = stem.ControllerError("NEWNYM refused")
    with (
        patch.object(tor_control, "get_controller", return_value=ctrl),
        patch.object(tor_control, "Signal", MagicMock()),
    ):
        with pytest.raises(TorError, match="Failed to request new circuit"):
            tor_control.request_new_circuit()


def test_the_authoritative_endpoint_answering_without_istor_is_not_an_upgrade() -> None:
    """A trusted origin with an unexpected shape must not fall through.

    Letting the loop continue would hand the verdict to a fallback reflector,
    which is exactly what the origin binding exists to prevent.
    """
    with (
        patch.object(tor_control, "_fetch_endpoint", return_value={"IP": "185.220.101.7"}),
        patch("time.sleep"),
    ):
        assert tor_control.verify_tor() == (False, "185.220.101.7")
