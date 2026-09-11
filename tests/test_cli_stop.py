# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.cli - CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from ttp.cli import app
from ttp.commands._common import EXIT_UNVERIFIED

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


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown", return_value=True)
@patch(
    "ttp.state.read_lock",
    return_value={"dns_backup": {"mount_target": "/etc/resolv.conf"}},
)
def test_stop_active_session(
    mock_read,
    mock_graceful,
    mock_stop_tor,
    mock_fw,
    mock_dns,
    mock_del,
    mock_stop_wd,
):
    """stop with active session -> graceful shutdown, then stops tor, restores network."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "terminated" in result.output
    assert mock_graceful.call_count == 1
    assert mock_graceful.call_args.kwargs == {"timeout": 10}
    assert mock_stop_tor.call_count == 1
    assert mock_fw.call_count == 1
    assert mock_dns.call_count == 1
    assert mock_del.call_count == 1
    assert mock_stop_wd.call_count == 1


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown", return_value=False)
@patch(
    "ttp.state.read_lock",
    return_value={"dns_backup": {"mount_target": "/etc/resolv.conf"}},
)
def test_stop_graceful_shutdown_failure_continues(
    mock_read,
    mock_graceful,
    mock_stop_tor,
    mock_fw,
    mock_dns,
    mock_del,
    mock_stop_wd,
):
    """stop continues even if graceful_shutdown fails."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "terminated" in result.output
    assert mock_graceful.call_count == 1
    assert mock_stop_tor.call_count == 1
    assert mock_fw.call_count == 1
    assert mock_stop_wd.call_count == 1


@patch("ttp.state.read_lock", return_value=None)
def test_stop_no_session(mock_read):
    """stop with no session -> clean exit."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "No active session" in result.output
    assert mock_read.call_count == 1


# status


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch(
    "ttp.state.read_lock",
    return_value={"dns_backup": {"mount_target": "/etc/resolv.conf"}},
)
def test_stop_restore_only_with_lock(
    mock_read,
    mock_stop_tor,
    mock_fw,
    mock_dns,
    mock_del,
    mock_stop_wd,
):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    assert "Network restored" in result.output
    assert mock_stop_tor.call_count == 1
    assert mock_fw.call_count == 1
    assert mock_dns.call_args[0][0] == {"mount_target": "/etc/resolv.conf"}
    assert mock_del.call_count == 1
    assert mock_stop_wd.call_count == 1


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.state.read_lock", return_value=None)
def test_stop_restore_only_no_lock(
    mock_read,
    mock_stop_tor,
    mock_fw,
    mock_dns,
    mock_del,
    mock_stop_wd,
):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    assert "Network restored" in result.output
    assert mock_stop_tor.call_count == 1
    assert mock_fw.call_count == 1
    assert mock_dns.call_args[0][0] is None
    assert mock_del.call_count == 1
    assert mock_stop_wd.call_count == 1


# restart


@patch("ttp.commands.stop_restart.start_command")
@patch("time.sleep")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_restart_active_session(mock_read, mock_stop, mock_sleep, mock_start):
    result = runner.invoke(app, ["restart", "--interface", "wlan0", "--bootstrap-timeout", "300"])
    assert result.exit_code == 0
    assert "Stopping current session" in result.output
    assert mock_stop.call_count == 1
    assert mock_sleep.call_args[0][0] == 1
    kwargs = mock_start.call_args.kwargs
    assert kwargs["interface"] == "wlan0"
    assert kwargs["bootstrap_timeout"] == 300
    assert kwargs["transport_port"] == 9041
    assert kwargs["dns_port"] == 9054
    assert kwargs["allow_root"] is False
    assert kwargs["external_daemon"] is False
    assert kwargs["no_ipv6"] is False


@patch("ttp.commands.stop_restart.start_command", side_effect=typer.Exit(code=EXIT_UNVERIFIED))
@patch("time.sleep")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_restart_propagates_the_unverified_exit_code(mock_read, mock_stop, mock_sleep, mock_start):
    """
    restart must not swallow the distinction start draws.

    restart tears the session down and then calls start, so it inherits both of
    start's failure windows: a Tor unit that will not start leaves the host on
    clearnet (exit 1), and a Tor that never bootstraps leaves it blocked but
    fail-closed (exit 3). Those demand opposite responses from a caller, so the
    code has to survive the wrapper rather than collapsing into 0 or 1.
    """
    result = runner.invoke(app, ["restart"])
    assert result.exit_code == EXIT_UNVERIFIED
    assert mock_stop.call_count == 1


@patch("ttp.commands.stop_restart.start_command")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value=None)
def test_restart_inactive_session(mock_read, mock_stop, mock_start):
    result = runner.invoke(app, ["restart"])
    assert result.exit_code == 0
    assert "No active session found, starting a new one" in result.output
    assert mock_stop.call_count == 0
    kwargs = mock_start.call_args.kwargs
    assert kwargs["interface"] is None
    assert kwargs["bootstrap_timeout"] == 180
    assert kwargs["transport_port"] == 9041
    assert kwargs["dns_port"] == 9054
    assert kwargs["allow_root"] is False
    assert kwargs["external_daemon"] is False
    assert kwargs["no_ipv6"] is False


# check


@patch("ttp.commands.stop_restart.start_command")
@patch("time.sleep")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_restart_custom_ports(mock_read, mock_stop, mock_sleep, mock_start):
    """restart propagates custom ports to start command."""
    result = runner.invoke(app, ["restart", "-t", "9080", "-d", "9090"])
    assert result.exit_code == 0
    assert "Stopping current session" in result.output
    assert mock_stop.call_count == 1
    kwargs = mock_start.call_args.kwargs
    assert kwargs["transport_port"] == 9080
    assert kwargs["dns_port"] == 9090
    assert kwargs["bootstrap_timeout"] == 180


@patch("ttp.state.read_lock")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown")
def test_stop_external_daemon(
    mock_shutdown,
    mock_stop_svc,
    mock_destroy,
    mock_restore,
    mock_delete_lock,
    mock_read_lock,
):
    """Verify stop command on BYOD session removes firewall/DNS but does not stop Tor daemon."""
    mock_read_lock.return_value = {
        "pid": 1234,
        "dns_backup": {"interface": "eth0"},
        "external_daemon": True,
    }

    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "Session terminated" in result.output

    assert mock_shutdown.call_count == 0
    assert mock_stop_svc.call_count == 0
    assert mock_destroy.call_count == 1
    assert mock_restore.call_args[0][0] == {"interface": "eth0"}
    assert mock_delete_lock.call_count == 1


@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("subprocess.run")
@patch("ttp.commands.lifecycle.resolve_optional", return_value="/usr/sbin/conntrack")
@patch("time.sleep")
@patch("ttp.firewall.apply_active_socket_slaughter")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_install.unlabel_ports_selinux")
@patch("ttp.tor_control.graceful_shutdown")
@patch("ttp.firewall.apply_teardown_lockdown")
@patch("pwd.getpwnam")
@patch(
    "ttp.state.read_lock",
    return_value={"dns_backup": {}, "tor_uid": 123, "transport_port": 9041},
)
@patch("ttp.watchdog.stop_watchdog")
def test_stop_graceful_teardown_sequence(
    mock_stop_wd,
    mock_read,
    mock_getpwnam,
    mock_lockdown,
    mock_graceful,
    mock_unlabel,
    mock_stop_tor,
    mock_slaughter,
    mock_sleep,
    mock_which,
    mock_run,
    mock_destroy,
    mock_restore,
    mock_delete,
):
    """Verify stop executes the full lockdown, Tor graceful teardown, socket slaughter, delay, conntrack flush, and cleanup sequence in order."""
    call_order = []
    mock_stop_wd.side_effect = lambda *args, **kwargs: call_order.append("stop_wd")
    mock_lockdown.side_effect = lambda *args, **kwargs: call_order.append("lockdown")
    mock_graceful.side_effect = lambda *args, **kwargs: call_order.append("graceful")
    mock_stop_tor.side_effect = lambda *args, **kwargs: call_order.append("stop_tor")
    mock_unlabel.side_effect = lambda *args, **kwargs: call_order.append("unlabel")
    mock_slaughter.side_effect = lambda *args, **kwargs: call_order.append("slaughter")
    mock_sleep.side_effect = lambda *args, **kwargs: call_order.append("sleep")
    mock_run.side_effect = lambda *args, **kwargs: call_order.append("run")
    mock_destroy.side_effect = lambda *args, **kwargs: call_order.append("destroy")
    mock_restore.side_effect = lambda *args, **kwargs: call_order.append("restore")
    mock_delete.side_effect = lambda *args, **kwargs: call_order.append("delete")

    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0

    assert mock_run.call_args[0][0] == ["/usr/sbin/conntrack", "-F"]
    assert mock_run.call_args.kwargs == {"capture_output": True, "text": True, "check": True, "timeout": 10}
    assert mock_lockdown.call_args[0][0] == 123
    assert mock_slaughter.call_count == 1
    assert mock_sleep.call_args[0][0] == 0.3

    expected_order = [
        "stop_wd",
        "lockdown",
        "graceful",
        "stop_tor",
        "unlabel",
        "slaughter",
        "sleep",
        "run",
        "destroy",
        "restore",
        "delete",
    ]
    assert call_order == expected_order


@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("subprocess.run")
@patch("ttp.commands.lifecycle.resolve_optional", return_value=None)
@patch("time.sleep")
@patch("ttp.firewall.apply_active_socket_slaughter")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_install.unlabel_ports_selinux")
@patch("ttp.tor_control.graceful_shutdown")
@patch("ttp.firewall.apply_teardown_lockdown")
@patch("pwd.getpwnam")
@patch(
    "ttp.state.read_lock",
    return_value={"dns_backup": {}, "tor_uid": 123, "transport_port": 9041},
)
@patch("ttp.watchdog.stop_watchdog")
def test_stop_graceful_teardown_no_conntrack(
    mock_stop_wd,
    mock_read,
    mock_getpwnam,
    mock_lockdown,
    mock_graceful,
    mock_unlabel,
    mock_stop_tor,
    mock_slaughter,
    mock_sleep,
    mock_which,
    mock_run,
    mock_destroy,
    mock_restore,
    mock_delete,
):
    """Verify stop skips conntrack flushing if conntrack binary is not found in PATH."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert mock_which.call_args[0][0] == "conntrack"
    assert mock_run.call_count == 0


# bypass
