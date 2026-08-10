# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.cli - CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import patch

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


# start


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown", return_value=True)
@patch(
    "ttp.state.read_lock",
    return_value={
        "dns_backup": {"mount_target": "/etc/resolv.conf"},
    },
)
@patch("os.geteuid", return_value=0)
def test_stop_active_session(
    mock_euid,
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
    mock_graceful.assert_called_once_with(timeout=10)
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()
    mock_dns.assert_called_once()
    mock_del.assert_called_once()
    mock_stop_wd.assert_called_once()


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown", return_value=False)
@patch(
    "ttp.state.read_lock",
    return_value={
        "dns_backup": {"mount_target": "/etc/resolv.conf"},
    },
)
@patch("os.geteuid", return_value=0)
def test_stop_graceful_shutdown_failure_continues(
    mock_euid,
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
    mock_graceful.assert_called_once()
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()
    mock_stop_wd.assert_called_once()


@patch("ttp.state.read_lock", return_value=None)
@patch("os.geteuid", return_value=0)
def test_stop_no_session(mock_euid, mock_read):
    """stop with no session -> clean exit."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "No active session" in result.output


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
@patch("os.geteuid", return_value=0)
def test_stop_restore_only_with_lock(mock_euid, mock_read, mock_stop_tor, mock_fw, mock_dns, mock_del, mock_stop_wd):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()
    mock_dns.assert_called_once_with({"mount_target": "/etc/resolv.conf"})
    mock_del.assert_called_once()
    mock_stop_wd.assert_called_once()


@patch("ttp.watchdog.stop_watchdog")
@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.tor_install.stop_tor_service")
@patch("ttp.state.read_lock", return_value=None)
@patch("os.geteuid", return_value=0)
def test_stop_restore_only_no_lock(
    mock_euid,
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
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()
    mock_dns.assert_called_once_with(None)
    mock_del.assert_called_once()
    mock_stop_wd.assert_called_once()


# restart


@patch("ttp.commands.stop_restart.start_command")
@patch("time.sleep")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("os.geteuid", return_value=0)
def test_restart_active_session(mock_euid, mock_read, mock_stop, mock_sleep, mock_start):
    result = runner.invoke(app, ["restart", "--interface", "wlan0", "--bootstrap-timeout", "300"])
    assert result.exit_code == 0
    mock_stop.assert_called_once()
    mock_sleep.assert_called_once_with(1)
    mock_start.assert_called_once_with(
        interface="wlan0",
        bootstrap_timeout=300,
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        no_lan_bypass=False,
        watchdog=False,
        external_daemon=False,
        tor_uid=None,
        no_ipv6=False,
    )


@patch("ttp.commands.stop_restart.start_command")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value=None)
@patch("os.geteuid", return_value=0)
def test_restart_inactive_session(mock_euid, mock_read, mock_stop, mock_start):
    result = runner.invoke(app, ["restart"])
    assert result.exit_code == 0
    mock_stop.assert_not_called()
    mock_start.assert_called_once_with(
        interface=None,
        bootstrap_timeout=180,
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        no_lan_bypass=False,
        watchdog=False,
        external_daemon=False,
        tor_uid=None,
        no_ipv6=False,
    )


# check


@patch("ttp.commands.stop_restart.start_command")
@patch("time.sleep")
@patch("ttp.commands.stop_restart._do_stop")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("os.geteuid", return_value=0)
def test_restart_custom_ports(mock_euid, mock_read, mock_stop, mock_sleep, mock_start):
    """restart propagates custom ports to start command."""
    result = runner.invoke(app, ["restart", "-t", "9080", "-d", "9090"])
    assert result.exit_code == 0
    mock_stop.assert_called_once()
    mock_start.assert_called_once_with(
        interface=None,
        bootstrap_timeout=180,
        transport_port=9080,
        dns_port=9090,
        allow_root=False,
        no_lan_bypass=False,
        watchdog=False,
        external_daemon=False,
        tor_uid=None,
        no_ipv6=False,
    )


@patch("os.geteuid", return_value=0)
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
    mock_euid,
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

    mock_shutdown.assert_not_called()
    mock_stop_svc.assert_not_called()
    mock_destroy.assert_called_once()
    mock_restore.assert_called_once_with({"interface": "eth0"})
    mock_delete_lock.assert_called_once()


@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("subprocess.run")
@patch("shutil.which", return_value="/usr/sbin/conntrack")
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
@patch("os.geteuid", return_value=0)
def test_stop_graceful_teardown_sequence(
    mock_euid,
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

    mock_run.assert_called_once_with(
        ["/usr/sbin/conntrack", "-F"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    mock_lockdown.assert_called_once_with(123)
    mock_slaughter.assert_called_once()
    mock_sleep.assert_called_once_with(0.3)

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
@patch("shutil.which", return_value=None)
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
@patch("os.geteuid", return_value=0)
def test_stop_graceful_teardown_no_conntrack(
    mock_euid,
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
    mock_which.assert_called_once_with("conntrack")
    mock_run.assert_not_called()


# bypass
