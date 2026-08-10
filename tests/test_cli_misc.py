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


@patch("ttp.state.read_lock", return_value=None)
def test_status_inactive(mock_read):
    """status with no session -> shows INACTIVE."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "INACTIVE" in result.output


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

    mock_stop.assert_called_once()
    mock_rem_sel.assert_called_once()
    mock_del_star.assert_called_once()


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


@patch("ttp.tor_control.verify_tor", return_value=(False, "unknown"))
def test_check_failure(mock_verify_tor):
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 1
    assert "Failed to reach any IP verification endpoint" in result.output


# check-leak


@patch("subprocess.run")
@patch("shutil.which", return_value="/usr/bin/dig")
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


@patch("subprocess.run")
@patch("shutil.which", return_value="/usr/bin/dig")
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


@patch("ttp.tor_control.verify_tor", return_value=(False, "8.8.8.8"))
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_detected_istor_false(mock_read, mock_verify):
    with (
        patch("shutil.which", return_value="/usr/bin/dig"),
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


@patch("ttp.tor_control.verify_tor", return_value=(False, "unknown"))
@patch("shutil.which", return_value="/usr/bin/dig")
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


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.1.1.1"))
@patch("shutil.which", return_value=None)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_no_dig_binary(mock_read, mock_which, mock_verify):
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output


@patch("ttp.tor_control.verify_tor", return_value=(True, "1.1.1.1"))
@patch("shutil.which", return_value="/usr/bin/dig")
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


@patch("ttp.state.read_lock", return_value=None)
def test_check_leak_inactive(mock_read):
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "INACTIVE" in result.output


# logs


@patch("ttp.commands.admin._LOG_PATH")
def test_logs_command(mock_log_path):
    mock_log_path.exists.return_value = True
    mock_log_path.read_text.return_value = "Mock log content"

    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 0
    assert "Mock log content" in result.output
    mock_log_path.read_text.assert_called_once_with(encoding="utf-8")


@patch("ttp.commands.admin._LOG_PATH")
def test_logs_command_no_file(mock_log_path):
    mock_log_path.exists.return_value = False

    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 1
    assert "No log file found" in result.output


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


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value=None)
def test_watchdog_start_no_session(mock_read, mock_euid):
    """watchdog start fails if no TTP session is running."""
    result = runner.invoke(app, ["watchdog", "start"])
    assert result.exit_code == 1
    assert "No active TTP session found" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.watchdog.start_watchdog")
def test_watchdog_start_success(mock_start_wd, mock_read, mock_euid):
    """watchdog start succeeds when session is running."""
    result = runner.invoke(app, ["watchdog", "start"])
    assert result.exit_code == 0
    assert "Watchdog daemon started successfully" in result.output
    mock_start_wd.assert_called_once()


@patch("os.geteuid", return_value=0)
@patch("ttp.watchdog.stop_watchdog")
def test_watchdog_stop(mock_stop_wd, mock_euid):
    """watchdog stop calls watchdog.stop_watchdog."""
    result = runner.invoke(app, ["watchdog", "stop"])
    assert result.exit_code == 0
    assert "Watchdog daemon stopped successfully" in result.output
    mock_stop_wd.assert_called_once()


@patch("ttp.state.read_lock", return_value=None)
def test_watchdog_status_no_session(mock_read):
    """watchdog status indicates INACTIVE when no session exists."""
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "INACTIVE (TTP is not running)" in result.output


@patch("ttp.state.read_lock", return_value={"watchdog_active": False})
def test_watchdog_status_inactive(mock_read):
    """watchdog status shows INACTIVE if session exists but watchdog is disabled."""
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "Watchdog Status: INACTIVE" in result.output


@patch(
    "ttp.state.read_lock",
    return_value={"watchdog_active": True, "watchdog_pid": 9999},
)
def test_watchdog_status_active(mock_read):
    """watchdog status shows ACTIVE and PID if running."""
    result = runner.invoke(app, ["watchdog", "status"])
    assert result.exit_code == 0
    assert "Watchdog Status: ACTIVE" in result.output
    assert "Watchdog PID: 9999" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.watchdog.run_watchdog_loop")
def test_watchdog_run(mock_run_loop, mock_euid):
    """watchdog run hidden command executes run_watchdog_loop."""
    result = runner.invoke(app, ["watchdog", "run", "--interval", "10"])
    assert result.exit_code == 0
    mock_run_loop.assert_called_once_with(interval_seconds=10)


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


@patch("ttp.state.ensure_runtime_dir")
@patch("logging.handlers.RotatingFileHandler")
@patch("logging.StreamHandler")
def test_setup_logging_json(mock_stream, mock_file, mock_ensure):
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
        mock_file.assert_called_once()
        args, _ = mock_file_handler.setFormatter.call_args
        assert isinstance(args[0], JSONFormatter)

        # Check stream handler setup
        mock_stream.assert_called_once()
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
