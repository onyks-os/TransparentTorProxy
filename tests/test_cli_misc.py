# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.cli - CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import MagicMock, mock_open, patch

import pytest
from typer.testing import CliRunner

from ttp.cli import app
from ttp.commands._common import setup_logging as original_setup_logging
from ttp.exceptions import TorError

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


# start


@patch("ttp.tor_control.get_exit_ip", return_value="5.6.7.8")
@patch("ttp.state.is_orphan", return_value=False)
@patch(
    "ttp.state.read_lock",
    return_value={
        "timestamp": "2025-04-10T14:32:01",
        "pid": 12345,
    },
)
def test_status_active(mock_read, mock_orphan, mock_ip):
    """status with active session -> shows IP and timestamp."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "ACTIVE" in result.output
    assert "5.6.7.8" in result.output
    assert mock_read.call_count == 1


@patch("ttp.state.read_lock", return_value=None)
def test_status_inactive(mock_read):
    """status with no session -> shows INACTIVE."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "INACTIVE" in result.output
    assert mock_read.call_count == 1


# start with --interface


@patch("ttp.commands.admin._do_stop")
@patch("ttp.commands.admin.tor_install.remove_selinux_module")
@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.state.delete_star_sentinel")
@patch("os.geteuid", return_value=0)
def test_uninstall_calls_cleanup(mock_euid, mock_del_star, mock_read, mock_is_sel, mock_rem_sel, mock_stop):
    """uninstall -> stops session, removes SELinux."""
    result = runner.invoke(app, ["uninstall"])
    assert result.exit_code == 0
    assert "Uninstallation complete" in result.output

    assert mock_stop.call_count == 1
    assert mock_rem_sel.call_count == 1
    assert mock_del_star.call_count == 1


# start with --bootstrap-timeout


@patch("ttp.tor_control.get_controller")
@patch("ttp.tor_control.verify_tor", return_value=(True, "100.200.100.200"))
def test_check_success(mock_verify_tor, mock_get_ctrl):
    mock_get_ctrl.return_value = True

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "100.200.100.200" in result.output
    assert "Yes (IsTor=True)" in result.output
    assert "Yes (Controller connected)" in result.output
    assert mock_verify_tor.call_count == 1


@patch("ttp.tor_control.verify_tor", return_value=(False, "unknown"))
def test_check_failure(mock_verify_tor):
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 1
    assert "Failed to reach any IP verification endpoint" in result.output
    assert mock_verify_tor.call_count == 1


# check-leak


@patch("subprocess.run")
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("ttp.tor_control.verify_tor", return_value=(True, "1.1.1.1"))
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_success(mock_read, mock_verify, mock_which, mock_run):
    def side_effect(cmd, *args, **kwargs):
        mock_result = MagicMock()
        tokens = _mock_cmd_tokens(cmd)
        if any(t == "check.torproject.org" for t in tokens) and not any(t == "TXT" for t in tokens):
            mock_result.stdout = "2.2.2.2\n"
        elif any(t == "whoami.ipv4.akahelp.net" for t in tokens):
            mock_result.stdout = '"9.9.9.9"\n'
        return mock_result

    mock_run.side_effect = side_effect

    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 0
    assert "No leaks detected" in result.output
    assert mock_verify.call_count == 1
    assert mock_read.call_count == 1


@patch("subprocess.run")
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("ttp.tor_control.verify_tor", return_value=(True, "1.1.1.1"))
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_akahelp_txt_ip_not_a_leak(mock_read, mock_verify, mock_which, mock_run):
    """Resolver IP from Akamai TXT must not set has_leaks (regression for false positives)."""

    def side_effect(cmd, *args, **kwargs):
        mock_result = MagicMock()
        tokens = _mock_cmd_tokens(cmd)
        if any(t == "check.torproject.org" for t in tokens) and not any(t == "TXT" for t in tokens):
            mock_result.stdout = "2.2.2.2\n"
        elif any(t == "whoami.ipv4.akahelp.net" for t in tokens):
            mock_result.stdout = "192.168.50.1\n"
        return mock_result

    mock_run.side_effect = side_effect

    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 0
    assert "No leaks detected" in result.output
    assert mock_verify.call_count == 1


@patch("ttp.tor_control.verify_tor", return_value=(False, "8.8.8.8"))
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_detected_istor_false(mock_read, mock_verify):
    with (
        patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig"),
        patch("subprocess.run") as mock_run,
    ):

        def side_effect(cmd, *args, **kwargs):
            mock_result = MagicMock()
            tokens = _mock_cmd_tokens(cmd)
            if any(t == "check.torproject.org" for t in tokens) and not any(t == "TXT" for t in tokens):
                mock_result.stdout = "2.2.2.2\n"
            elif any(t == "whoami.ipv4.akahelp.net" for t in tokens):
                mock_result.stdout = ""
            return mock_result

        mock_run.side_effect = side_effect

        result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output
    assert mock_verify.call_count == 1


@patch("ttp.tor_control.verify_tor", return_value=(False, "unknown"))
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("subprocess.run")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_tor_api_error(mock_read, mock_run, mock_which, mock_verify):
    def side_effect(cmd, *args, **kwargs):
        m = MagicMock()
        m.stdout = "1.2.3.4\n"
        return m

    mock_run.side_effect = side_effect
    result = runner.invoke(app, ["-v", "check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output
    assert mock_verify.call_count == 1


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.1.1.1"))
@patch("ttp.commands.session.resolve_optional", return_value=None)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_no_dig_binary(mock_read, mock_which, mock_verify):
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output
    assert mock_which.call_count == 1


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.1.1.1"))
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("subprocess.run")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_empty_dig_a(mock_read, mock_run, mock_which, mock_verify):
    def side_effect(cmd, *args, **kwargs):
        m = MagicMock()
        tokens = _mock_cmd_tokens(cmd)
        if any(t == "check.torproject.org" for t in tokens) and not any(t == "TXT" for t in tokens):
            m.stdout = ""
        elif any(t == "whoami.ipv4.akahelp.net" for t in tokens):
            m.stdout = '"1.1.1.1"'
        return m

    mock_run.side_effect = side_effect
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output
    assert mock_verify.call_count == 1


@patch("ttp.state.read_lock", return_value=None)
def test_check_leak_inactive(mock_read):
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "INACTIVE" in result.output
    assert mock_read.call_count == 1


# logs


@patch("ttp.commands.admin._LOG_PATH")
def test_logs_command(mock_log_path):
    mock_log_path.exists.return_value = True
    mock_log_path.read_text.return_value = "Mock log content"

    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 0
    assert "Mock log content" in result.output
    assert mock_log_path.read_text.call_args.kwargs == {"encoding": "utf-8"}
    assert mock_log_path.exists.call_count == 1


@patch("ttp.commands.admin._LOG_PATH")
def test_logs_command_no_file(mock_log_path):
    mock_log_path.exists.return_value = False

    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 1
    assert "No log file found" in result.output
    assert mock_log_path.exists.call_count == 1


# tmpfs pre-flight


@patch("ttp.tor_control.get_exit_ip", return_value="5.6.7.8")
@patch("ttp.state.is_orphan", return_value=False)
@patch(
    "ttp.state.read_lock",
    return_value={
        "timestamp": "2025-04-10T14:32:01",
        "pid": 12345,
        "transport_port": 9080,
        "dns_port": 9090,
    },
)
def test_status_shows_custom_ports(mock_read, mock_orphan, mock_ip):
    """status displays custom ports from the active lock file."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "ACTIVE" in result.output
    assert "TransPort: 9080" in result.output
    assert "DNSPort: 9090" in result.output
    assert mock_read.call_count == 1


@patch("ttp.tor_control.get_controller")
@patch("ttp.tor_control.verify_tor", return_value=(True, "100.200.100.200"))
@patch(
    "ttp.state.read_lock",
    return_value={
        "transport_port": 9080,
        "dns_port": 9090,
    },
)
def test_check_shows_custom_ports(mock_read, mock_verify_tor, mock_get_ctrl):
    """check displays custom ports from the lock file."""
    mock_get_ctrl.return_value = True

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "TransPort:       9080" in result.output
    assert "DNSPort:         9090" in result.output
    assert mock_read.call_count == 1


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value=None)
def test_watchdog_start_no_session(mock_read, mock_euid):
    """watchdog start fails if no TTP session is running."""
    result = runner.invoke(app, ["watchdog", "start"])
    assert result.exit_code == 1
    assert "No active TTP session found" in result.output
    assert mock_read.call_count == 1


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.watchdog.start_watchdog")
def test_watchdog_start_success(mock_start_wd, mock_read, mock_euid):
    """watchdog start succeeds when session is running."""
    result = runner.invoke(app, ["watchdog", "start"])
    assert result.exit_code == 0
    assert "Watchdog daemon started successfully" in result.output
    assert mock_start_wd.call_count == 1
    assert mock_read.call_count == 1


@patch("os.geteuid", return_value=0)
@patch("ttp.watchdog.stop_watchdog")
def test_watchdog_stop(mock_stop_wd, mock_euid):
    """watchdog stop calls watchdog.stop_watchdog."""
    result = runner.invoke(app, ["watchdog", "stop"])
    assert result.exit_code == 0
    assert "Watchdog daemon stopped successfully" in result.output
    assert mock_stop_wd.call_count == 1


@patch("ttp.state.read_lock", return_value=None)
def test_watchdog_status_no_session(mock_read):
    """watchdog status indicates INACTIVE when no session exists."""
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "INACTIVE (TTP is not running)" in result.output
    assert mock_read.call_count == 1


@patch("ttp.state.read_lock", return_value={"watchdog_active": False})
def test_watchdog_status_inactive(mock_read):
    """watchdog status shows INACTIVE if session exists but watchdog is disabled."""
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "Watchdog Status: INACTIVE" in result.output
    assert mock_read.call_count == 1


@patch("ttp.watchdog.service.watchdog_liveness", return_value=(True, 9999))
@patch(
    "ttp.state.read_lock",
    return_value={"watchdog_active": True, "watchdog_pid": 9999},
)
def test_watchdog_status_active(mock_read, _mock_live):
    """watchdog status shows ACTIVE and PID if the unit really is up."""
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "Watchdog Status: ACTIVE" in result.output
    assert "Watchdog PID: 9999" in result.output
    assert mock_read.call_count == 1


@patch("ttp.watchdog.service.watchdog_liveness", return_value=(False, None))
@patch(
    "ttp.state.read_lock",
    return_value={"watchdog_active": True, "watchdog_pid": 9999},
)
def test_watchdog_status_does_not_trust_a_stale_active_flag(_mock_read, _mock_live):
    """A lock that still says ACTIVE must not outvote the live unit state.

    watchdog_active is written once at start and nothing ever wrote it back to
    False except an explicit `ttp watchdog stop`, so it survived the daemon
    exiting on the killswitch path, an OOM kill, or a direct systemctl stop.
    """
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "Watchdog Status: INACTIVE" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.watchdog.run_watchdog_loop")
def test_watchdog_run(mock_run_loop, mock_euid):
    """watchdog run hidden command executes run_watchdog_loop."""
    result = runner.invoke(app, ["watchdog", "run", "--interval", "10"])
    assert result.exit_code == 0
    assert mock_run_loop.call_args.kwargs == {"interval_seconds": 10}


# 9. JSON Logging Tests


def test_json_formatter_records():
    """JSONFormatter converts a LogRecord into a valid JSON string with expected keys."""
    import json
    import logging

    from ttp.commands._common import JSONFormatter

    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="ttp.test",
        level=logging.INFO,
        pathname="test_cli.py",
        lineno=10,
        msg="Hello JSON logging!",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    data = json.loads(formatted)

    assert "timestamp" in data
    assert data["level"] == "INFO"
    assert data["logger"] == "ttp.test"
    assert data["message"] == "Hello JSON logging!"
    assert "exception" not in data

    # Test with exception
    try:
        raise ValueError("Oops!")
    except ValueError:
        import sys

        record_exc = logging.LogRecord(
            name="ttp.test",
            level=logging.ERROR,
            pathname="test_cli.py",
            lineno=20,
            msg="An error occurred",
            args=(),
            exc_info=sys.exc_info(),
        )

    formatted_exc = formatter.format(record_exc)
    data_exc = json.loads(formatted_exc)
    assert "exception" in data_exc
    assert "ValueError: Oops!" in data_exc["exception"]


@patch("ttp.commands._logging._open_log_file_safely", return_value=True)
@patch("ttp.state.ensure_runtime_dir")
@patch("logging.handlers.RotatingFileHandler")
@patch("logging.StreamHandler")
def test_setup_logging_json(mock_stream, mock_file, mock_ensure, _mock_open_ok):
    """_setup_logging configures JSON formatter on handlers when log_format is 'json'."""
    from ttp.commands._common import JSONFormatter, cli_state, logger

    mock_file_handler = MagicMock()
    mock_file.return_value = mock_file_handler

    mock_stream_handler = MagicMock()
    mock_stream.return_value = mock_stream_handler

    # Save original state
    orig_format = cli_state.log_format
    orig_quiet = cli_state.quiet
    orig_verbose = cli_state.verbose

    try:
        cli_state.log_format = "json"
        cli_state.quiet = False
        cli_state.verbose = True

        original_setup_logging()

        # Check file handler setup
        assert mock_file.call_count == 1
        args, _ = mock_file_handler.setFormatter.call_args
        assert isinstance(args[0], JSONFormatter)

        # Check stream handler setup
        assert mock_stream.call_count == 1
        args_s, _ = mock_stream_handler.setFormatter.call_args
        assert isinstance(args_s[0], JSONFormatter)

    finally:
        # Restore state
        cli_state.log_format = orig_format
        cli_state.quiet = orig_quiet
        cli_state.verbose = orig_verbose
        for h in list(logger.handlers):
            logger.removeHandler(h)


def test_log_format_argument_parsing():
    """Passing --log-format json updates cli_state.log_format accordingly."""
    from ttp.commands._common import cli_state

    orig_format = cli_state.log_format
    try:
        # Run help or a dummy run command to trigger main callback
        runner.invoke(app, ["--log-format", "json", "watchdog", "status"])
        assert cli_state.log_format == "json"
    finally:
        cli_state.log_format = orig_format


def test_get_uid_from_port_parser():
    """Verify that _get_uid_from_port correctly parses /proc/net/tcp."""
    from ttp.commands._common import get_uid_from_port as _get_uid_from_port

    mock_content = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:2351 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 30737 1 0000000000000000\n"
    )
    with patch("builtins.open", mock_open(read_data=mock_content)):
        uid = _get_uid_from_port(9041)
        assert uid == 1001


# ---------------------------------------------------------------------------
# refresh - the fourth state-changing command, and the only one with no tests
# ---------------------------------------------------------------------------
#
# `start`, `stop` and `restart` each had dedicated files; `refresh` had none,
# so its entire body - including the TorError path a user hits whenever the
# control socket is unreachable - was reached only by importing the module.


@patch("os.geteuid", return_value=1000)
def test_refresh_requires_root(mock_euid):
    """Rotating a circuit talks to Tor's control socket, which is root-owned."""
    result = runner.invoke(app, ["refresh"])
    assert result.exit_code == 1
    assert "must be run as root" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value=None)
def test_refresh_requires_an_active_session(mock_read, mock_euid):
    """With no session there is no circuit to rotate, and no Tor of ours running."""
    result = runner.invoke(app, ["refresh"])
    assert result.exit_code == 1
    assert "No active session" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.tor_control.request_new_circuit", return_value=(True, "185.220.101.5"))
def test_refresh_reports_the_new_exit_ip(mock_circuit, mock_read, mock_euid):
    result = runner.invoke(app, ["refresh"])
    assert result.exit_code == 0
    assert "185.220.101.5" in result.output
    assert mock_circuit.call_count == 1


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.tor_control.request_new_circuit", return_value=(False, "185.220.101.5"))
def test_refresh_succeeds_even_when_the_exit_ip_did_not_change(mock_circuit, mock_read, mock_euid):
    """NEWNYM rotates the circuit; it does not promise a different exit node.

    Tor can legitimately hand back the same exit, and the command exits 0 with
    a caveat rather than reporting a failure - the rotation did happen. Exiting
    non-zero here would train users to ignore the one exit code that matters.
    """
    result = runner.invoke(app, ["refresh"])
    assert result.exit_code == 0
    assert "may not have changed" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.tor_control.request_new_circuit", side_effect=TorError("Connection refused"))
def test_refresh_reports_an_unreachable_control_socket(mock_circuit, mock_read, mock_euid):
    """The failure a user actually hits: ControlPort/ControlSocket not enabled.

    The progress spinner is `transient=True`, so it must be stopped before the
    error panel prints or Rich paints the panel over a live spinner region.
    """
    result = runner.invoke(app, ["refresh"])
    assert result.exit_code == 1
    assert "Connection Failed" in result.output
    assert "Connection refused" in result.output
    assert "ControlSocket" in result.output


# ---------------------------------------------------------------------------
# status / check: the reporting branches that describe the host's IPv6 posture
# ---------------------------------------------------------------------------


@patch("ttp.state.read_lock", return_value=None)
@patch("urllib.request.urlopen", side_effect=OSError("no route to host"))
def test_status_reports_an_unknown_ip_rather_than_guessing(mock_urlopen, mock_read):
    """When the lookup fails, status says "Unknown" instead of omitting the line.

    This is the same principle as the leak oracles: a check that could not run
    must say so. Printing nothing would let the reader supply their own answer.
    """
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Unknown" in result.output


@patch("ttp.tor_control.get_exit_ip", return_value="5.6.7.8")
@patch("ttp.state.is_orphan", return_value=False)
@patch("ttp.state.read_lock", return_value={"pid": 1, "no_ipv6": True})
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_status_distinguishes_ipv6_dropped_by_us_from_unsupported(mock_v6, mock_read, mock_orphan, mock_ip):
    """`--no-ipv6` and "the host has no IPv6" produce the same packets and very
    different diagnoses, so status must not collapse them into one message."""
    result = runner.invoke(app, ["status"])
    assert "Force Dropped" in result.output


@patch("ttp.tor_control.get_exit_ip", return_value="5.6.7.8")
@patch("ttp.state.is_orphan", return_value=False)
@patch("ttp.state.read_lock", return_value={"pid": 1})
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_status_reports_ipv6_unsupported_by_the_host(mock_v6, mock_read, mock_orphan, mock_ip):
    result = runner.invoke(app, ["status"])
    assert "Not supported by host" in result.output


@patch("ttp.tor_control.get_controller", return_value=MagicMock())
@patch("ttp.tor_control.verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.state.read_lock", return_value={"pid": 1, "no_ipv6": True})
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_check_distinguishes_ipv6_dropped_by_us_from_unsupported(mock_v6, mock_read, mock_verify, mock_ctrl):
    result = runner.invoke(app, ["check"])
    assert "Force Dropped" in result.output


@patch("ttp.tor_control.get_controller", return_value=MagicMock())
@patch("ttp.tor_control.verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.state.read_lock", return_value={"pid": 1})
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_check_reports_ipv6_unsupported_by_the_host(mock_v6, mock_read, mock_verify, mock_ctrl):
    result = runner.invoke(app, ["check"])
    assert "Not supported" in result.output


# ---------------------------------------------------------------------------
# check-leak: the branches where a probe fails rather than reports
# ---------------------------------------------------------------------------


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("ttp.state.read_lock", return_value={"pid": 1})
@patch("subprocess.run", side_effect=OSError("dig: cannot execute"))
def test_check_leak_treats_an_unrunnable_dig_as_a_leak(mock_run, mock_read, mock_which, mock_verify):
    """A DNS path that cannot be probed is reported as a leak, not as clean.

    The verdict is the same one the empty-pcap bug got wrong in the other
    direction: not being able to measure is not evidence of safety.
    """
    result = runner.invoke(app, ["-v", "check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected" in result.output


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("ttp.state.read_lock", return_value={"pid": 1})
@patch("subprocess.run")
def test_check_leak_treats_a_failing_resolver_probe_as_a_leak(mock_run, mock_read, mock_which, mock_verify):
    """The Akamai TXT probe is informational - its *result* can never set
    `has_leaks`, because a resolver IP is not a leak (`session.py:213`).

    Its *failure* does, and that asymmetry is deliberate: the probe returning
    an address tells us nothing alarming, but the probe not completing means
    the DNS path is not behaving, which is. Worth pinning down precisely
    because it reads like an inconsistency until you see which way it fails.
    """

    def _by_record_type(cmd, **kwargs):
        if "TXT" in cmd:
            raise OSError("resolver unreachable")
        return MagicMock(stdout="1.2.3.4\n", returncode=0)

    mock_run.side_effect = _by_record_type
    result = runner.invoke(app, ["-v", "check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected" in result.output


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.commands.session.resolve_optional", return_value=None)
@patch("ttp.state.read_lock", return_value={"pid": 1})
def test_check_leak_without_dig_explains_itself_in_verbose(mock_read, mock_which, mock_verify, caplog):
    """Missing `dig` fails the check; -v must say which probe was skipped, or
    the user sees a leak verdict with no way to tell it was a tooling gap."""
    with caplog.at_level("DEBUG", logger="ttp"):
        result = runner.invoke(app, ["-v", "check-leak"])
    assert result.exit_code == 1
    assert "dig not found" in caplog.text


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.commands.session.resolve_optional", return_value="/usr/bin/dig")
@patch("ttp.state.read_lock", return_value={"pid": 1})
@patch("subprocess.run")
def test_check_leak_logs_the_return_code_when_dig_answers_nothing(mock_run, mock_read, mock_which, mock_verify, caplog):
    """An empty answer and a failed lookup are different faults; the debug line
    carries the return code so they can be told apart after the fact."""
    mock_run.return_value = MagicMock(stdout="", returncode=9)
    with caplog.at_level("DEBUG", logger="ttp"):
        result = runner.invoke(app, ["-v", "check-leak"])
    assert result.exit_code == 1
    assert "returncode=9" in caplog.text


# ---------------------------------------------------------------------------
# diagnose
# ---------------------------------------------------------------------------


@patch("os.geteuid", return_value=1000)
def test_diagnose_requires_root(mock_euid):
    """It reads /run/tor/ttp/torrc and the live nftables ruleset."""
    result = runner.invoke(app, ["diagnose"])
    assert result.exit_code == 1
    assert "must be run as root" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.system_info.collect_diagnostics")
def test_diagnose_renders_every_section_it_collected(mock_collect, mock_euid):
    """A diagnostic report that silently drops a section is worse than none:
    the reader cannot tell an absent section from an empty one, and this is the
    output people paste into bug reports.
    """
    sections = {
        "os": "Fedora 44",
        "tor_service": "active (running)",
        "torrc": "TransPort 9041",
        "nftables": "table inet ttp",
        "dns": "nameserver 127.0.0.1",
        "control_interface": "ControlSocket ok",
        "ttp_state": "pid 123",
    }
    mock_collect.return_value = sections
    result = runner.invoke(app, ["diagnose"])
    assert result.exit_code == 0
    for key, value in sections.items():
        assert value in result.output, f"section {key!r} was collected but never rendered"
    assert "Diagnostic complete" in result.output
