# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.cli - CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock, mock_open

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


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_happy_path(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with all systems go -> session active."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    assert "Session active" in result.output
    mock_write.assert_called_once()
    mock_apply_fw.assert_called_once()


@patch("os.geteuid", return_value=1000)
def test_start_requires_root(mock_euid):
    """start without root -> exit code 1."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "root" in result.output


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.attempt_recovery")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.state.is_orphan", return_value=True)
@patch("os.geteuid", return_value=0)
def test_start_orphan_recovery(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_recovery,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with orphaned session (PID dead) -> auto-recovers and continues."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    mock_recovery.assert_called_once()
    assert "recovering" in result.output.lower()


@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_concurrency_error(mock_euid, mock_orphan, mock_read):
    """start with another TTP instance running (PID alive) -> error."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "concurrency error" in result.output.lower()


# stop


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


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "wlan0"})
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_with_interface_flag(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_apply_dns,
    mock_verify,
):
    """start --interface wlan0 -> uses wlan0 instead of auto-detect."""
    result = runner.invoke(app, ["start", "--interface", "wlan0"])
    assert result.exit_code == 0
    mock_apply_dns.assert_called_once_with("wlan0", disable_ipv6=False, dns_port=9054)


# health check warning


@patch("ttp.commands.start._verify_tor", return_value=(False, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_tor_verification_fails(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with Tor not verified -> shows warning."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    assert "verification failed" in result.output


# uninstall


@patch("ttp.commands.admin._do_stop")
@patch("ttp.commands.admin.tor_install.remove_selinux_module")
@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.state.delete_star_sentinel")
@patch("os.geteuid", return_value=0)
def test_uninstall_calls_cleanup(
    mock_euid, mock_del_star, mock_read, mock_is_sel, mock_rem_sel, mock_stop
):
    """uninstall -> stops session, removes SELinux."""
    result = runner.invoke(app, ["uninstall"])
    assert result.exit_code == 0
    assert "Uninstallation complete" in result.output

    mock_stop.assert_called_once()
    mock_rem_sel.assert_called_once()
    mock_del_star.assert_called_once()


# start with --bootstrap-timeout


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={"is_installed": True, "version": "0.4.8.10"},
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_with_bootstrap_timeout(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    result = runner.invoke(app, ["start", "--bootstrap-timeout", "300"])
    assert result.exit_code == 0
    mock_verify.assert_called_once_with(timeout=300)


# stop --restore-only


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
def test_stop_restore_only_with_lock(
    mock_euid, mock_read, mock_stop_tor, mock_fw, mock_dns, mock_del, mock_stop_wd
):
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
def test_restart_active_session(
    mock_euid, mock_read, mock_stop, mock_sleep, mock_start
):
    result = runner.invoke(
        app, ["restart", "--interface", "wlan0", "--bootstrap-timeout", "300"]
    )
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
@patch("urllib.request.urlopen")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_success(mock_read, mock_urlopen, mock_which, mock_run):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": True, "IP": "1.1.1.1"}
    ).encode()

    def side_effect(cmd, *args, **kwargs):
        mock_result = MagicMock()
        tokens = _mock_cmd_tokens(cmd)
        if any(t == "check.torproject.org" for t in tokens) and not any(
            t == "TXT" for t in tokens
        ):
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
@patch("urllib.request.urlopen")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_akahelp_txt_ip_not_a_leak(
    mock_read, mock_urlopen, mock_which, mock_run
):
    """Resolver IP from Akamai TXT must not set has_leaks (regression for false positives)."""
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": True, "IP": "1.1.1.1"}
    ).encode()

    def side_effect(cmd, *args, **kwargs):
        mock_result = MagicMock()
        tokens = _mock_cmd_tokens(cmd)
        if any(t == "check.torproject.org" for t in tokens) and not any(
            t == "TXT" for t in tokens
        ):
            mock_result.stdout = "2.2.2.2\n"
        elif any(t == "whoami.ipv4.akahelp.net" for t in tokens):
            mock_result.stdout = "192.168.50.1\n"
        return mock_result

    mock_run.side_effect = side_effect

    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 0
    assert "No leaks detected" in result.output


@patch("urllib.request.urlopen")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_detected_istor_false(mock_read, mock_urlopen):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": False, "IP": "8.8.8.8"}
    ).encode()

    with (
        patch("shutil.which", return_value="/usr/bin/dig"),
        patch("subprocess.run") as mock_run,
    ):

        def side_effect(cmd, *args, **kwargs):
            mock_result = MagicMock()
            tokens = _mock_cmd_tokens(cmd)
            if any(t == "check.torproject.org" for t in tokens) and not any(
                t == "TXT" for t in tokens
            ):
                mock_result.stdout = "2.2.2.2\n"
            elif any(t == "whoami.ipv4.akahelp.net" for t in tokens):
                mock_result.stdout = ""
            return mock_result

        mock_run.side_effect = side_effect

        result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output


@patch("urllib.request.urlopen", side_effect=OSError("network down"))
@patch("shutil.which", return_value="/usr/bin/dig")
@patch("subprocess.run")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_tor_api_error(mock_read, mock_run, mock_which, mock_urlopen):
    def side_effect(cmd, *args, **kwargs):
        m = MagicMock()
        m.stdout = "1.2.3.4\n"
        return m

    mock_run.side_effect = side_effect
    result = runner.invoke(app, ["-v", "check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output


@patch("urllib.request.urlopen")
@patch("shutil.which", return_value=None)
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_no_dig_binary(mock_read, mock_which, mock_urlopen):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps({"IsTor": True}).encode()

    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output


@patch("urllib.request.urlopen")
@patch("shutil.which", return_value="/usr/bin/dig")
@patch("subprocess.run")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
def test_check_leak_empty_dig_a(mock_read, mock_run, mock_which, mock_urlopen):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps({"IsTor": True}).encode()

    def side_effect(cmd, *args, **kwargs):
        m = MagicMock()
        tokens = _mock_cmd_tokens(cmd)
        if any(t == "check.torproject.org" for t in tokens) and not any(
            t == "TXT" for t in tokens
        ):
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


@patch("ttp.state.check_tmpfs_space")
@patch("ttp.state.read_lock", return_value=None)
@patch("os.geteuid", return_value=0)
def test_start_tmpfs_check_fails(mock_euid, mock_read, mock_check):
    """start aborts cleanly when /run has no space, without touching system state."""
    from ttp.exceptions import StateError

    mock_check.side_effect = StateError("Insufficient space on /run")

    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "Pre-flight Failed" in result.output
    assert "Insufficient space" in result.output


# Custom Ports and Validation Tests


@patch("ttp.commands.start._is_port_in_use", return_value=False)
@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_custom_ports_success(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
    mock_in_use,
):
    """start with custom valid ports -> propagates them down correctly."""
    result = runner.invoke(
        app, ["start", "--transport-port", "9080", "--dns-port", "9090"]
    )
    assert result.exit_code == 0
    assert "Session active" in result.output

    mock_ensure.assert_called_once_with(
        transport_port=9080,
        dns_port=9090,
        use_bridges=False,
        bridges=[],
        disable_ipv6=False,
    )
    mock_apply_fw.assert_called_once_with(
        tor_user="debian-tor",
        transport_port=9080,
        dns_port=9090,
        allow_root=False,
        lan_bypass=True,
        disable_ipv6=False,
    )
    mock_write.assert_called_once_with(
        dns_backup={"interface": "eth0"},
        transport_port=9080,
        dns_port=9090,
        allow_root=False,
        lan_bypass=True,
        interface="eth0",
        external_daemon=False,
        no_ipv6=False,
        tor_uid=None,
    )


@patch("os.geteuid", return_value=0)
def test_start_invalid_transport_port(mock_euid):
    """start with privileged or invalid transport port -> validation error."""
    # Under 1024
    result = runner.invoke(app, ["start", "-t", "80"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output

    # Over 65535
    result = runner.invoke(app, ["start", "-t", "70000"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output


@patch("os.geteuid", return_value=0)
def test_start_invalid_dns_port(mock_euid):
    """start with privileged or invalid dns port -> validation error."""
    # Under 1024
    result = runner.invoke(app, ["start", "-d", "53"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output

    # Over 65535
    result = runner.invoke(app, ["start", "-d", "65536"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output


@patch("os.geteuid", return_value=0)
def test_start_duplicate_ports(mock_euid):
    """start with same port for transport and dns -> validation error."""
    result = runner.invoke(app, ["start", "-t", "9000", "-d", "9000"])
    assert result.exit_code == 1
    assert "Port Conflict" in result.output
    assert "cannot be the same" in result.output


@patch("ttp.commands.start._is_port_in_use", return_value=True)
@patch("os.geteuid", return_value=0)
def test_start_port_already_in_use(mock_euid, mock_in_use):
    """start with port already in use -> pre-flight check error."""
    result = runner.invoke(app, ["start", "-t", "9041"])
    assert result.exit_code == 1
    assert "Port In Use" in result.output
    assert "already in use by another process" in result.output


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


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_with_allow_root_and_no_lan_bypass(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with --allow-root and --no-lan-bypass flags -> passes down options."""
    result = runner.invoke(app, ["start", "--allow-root", "--no-lan-bypass"])
    assert result.exit_code == 0
    mock_apply_fw.assert_called_once_with(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        allow_root=True,
        lan_bypass=False,
        disable_ipv6=False,
    )
    mock_write.assert_called_once_with(
        dns_backup={"interface": "eth0"},
        transport_port=9041,
        dns_port=9054,
        allow_root=True,
        lan_bypass=False,
        interface="eth0",
        external_daemon=False,
        no_ipv6=False,
        tor_uid=None,
    )


# watchdog commands


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
    import logging
    import json
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
    from ttp.commands._common import cli_state, JSONFormatter, logger

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


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
@patch("pwd.getpwnam")
@patch("grp.getgrnam")
def test_start_with_bypass_user_and_group(
    mock_grp_nam,
    mock_pwd_nam,
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """Test start command with valid bypass users and groups."""
    mock_pwd_nam.side_effect = lambda name: (
        MagicMock(pw_uid=1001) if name == "user1" else MagicMock(pw_uid=1002)
    )
    mock_grp_nam.return_value = MagicMock(gr_gid=2001)

    result = runner.invoke(
        app, ["start", "--bypass-user", "user1,user2", "--bypass-group", "group1"]
    )
    assert result.exit_code == 0
    assert "Session active" in result.output

    # Check write_lock is called with bypass_users/bypass_groups
    _, kwargs_write = mock_write.call_args
    assert kwargs_write["bypass_users"] == ["user1", "user2"]
    assert kwargs_write["bypass_groups"] == ["group1"]

    # Check apply_rules is called with bypass_uids/bypass_gids
    _, kwargs_fw = mock_apply_fw.call_args
    assert kwargs_fw["bypass_uids"] == [1001, 1002]
    assert kwargs_fw["bypass_gids"] == [2001]


@patch("os.geteuid", return_value=0)
@patch("pwd.getpwnam", side_effect=KeyError)
def test_start_with_invalid_bypass_user(mock_pwd_nam, mock_euid):
    """Test start command with invalid bypass user returns an error."""
    result = runner.invoke(app, ["start", "--bypass-user", "nonexistentuser"])
    assert result.exit_code == 1
    assert "User 'nonexistentuser' does not exist" in result.output


# CLI Bridges Tests


@patch("ttp.state.write_lock")
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.tor_install.ensure_tor_ready")
@patch("ttp.firewall.apply_rules")
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.dns.apply_dns", return_value={"resolv": "conf"})
@patch("ttp.commands.start._verify_tor", return_value=(True, "198.51.100.1"))
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_with_bridges_direct(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_verify,
    mock_apply_dns,
    mock_iface,
    mock_apply_fw,
    mock_ensure,
    mock_selinux,
    mock_write,
):
    """Test start command with direct --bridge option."""
    result = runner.invoke(
        app,
        [
            "start",
            "--bridge",
            "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
            "--bridge",
            "snowflake 192.0.2.2:4321 601234567890ABCDEF",
        ],
    )
    assert result.exit_code == 0
    assert "Session active" in result.output

    # check ensure_tor_ready arguments
    _, kwargs_ensure = mock_ensure.call_args
    assert kwargs_ensure["use_bridges"] is True
    assert kwargs_ensure["bridges"] == [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]

    # check write_lock arguments
    _, kwargs_write = mock_write.call_args
    assert kwargs_write["use_bridges"] is True
    assert kwargs_write["bridges"] == [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]


@patch("ttp.state.write_lock")
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.tor_install.ensure_tor_ready")
@patch("ttp.firewall.apply_rules")
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.dns.apply_dns", return_value={"resolv": "conf"})
@patch("ttp.commands.start._verify_tor", return_value=(True, "198.51.100.1"))
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
def test_start_with_bridge_file(
    mock_euid,
    mock_orphan,
    mock_read,
    mock_verify,
    mock_apply_dns,
    mock_iface,
    mock_apply_fw,
    mock_ensure,
    mock_selinux,
    mock_write,
    tmp_path,
):
    """Test start command with --bridge-file parsing comments and empty lines."""
    bridge_file = tmp_path / "my_bridges.txt"
    bridge_file.write_text(
        "# This is a comment\n"
        "\n"
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0\n"
        "   \n"
        "snowflake 192.0.2.2:4321 601234567890ABCDEF\n"
    )

    result = runner.invoke(app, ["start", "--bridge-file", str(bridge_file)])
    assert result.exit_code == 0
    assert "Session active" in result.output

    _, kwargs_ensure = mock_ensure.call_args
    assert kwargs_ensure["use_bridges"] is True
    assert kwargs_ensure["bridges"] == [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]


@patch("os.geteuid", return_value=0)
def test_start_with_invalid_bridge_format(mock_euid):
    """Test start command with invalid bridge format returns validation error."""
    result = runner.invoke(app, ["start", "--bridge", "obfs4_no_ip_port"])
    assert result.exit_code == 1
    assert "Invalid Bridge Line" in result.output


@patch("os.geteuid", return_value=0)
def test_start_use_bridges_without_bridges(mock_euid):
    """Test start command with --use-bridges but no bridges specified returns error."""
    result = runner.invoke(app, ["start", "--use-bridges"])
    assert result.exit_code == 1
    assert "No Bridges Provided" in result.output


# external-daemon (BYOD) mode tests


@patch("os.geteuid", return_value=0)
def test_start_external_daemon_watchdog_conflict(mock_euid):
    """Verify that passing --external-daemon and --watchdog raises a conflict error."""
    result = runner.invoke(app, ["start", "--external-daemon", "--watchdog"])
    assert result.exit_code == 1
    assert "Configuration Conflict" in result.output
    assert "Watchdog daemon cannot be used in external-daemon mode" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.commands.start._is_port_listening_tcp", return_value=False)
@patch("ttp.commands.start._is_port_listening_udp", return_value=False)
def test_start_external_daemon_inactive(mock_euid, mock_udp, mock_tcp):
    """Verify that starting TTP in BYOD mode when ports are not active fails."""
    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 1
    assert "Tor Not Running" in result.output


@patch("os.geteuid", return_value=0)
@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("pwd.getpwnam")
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch("ttp.state.write_lock")
@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_happy_path_manual_uid(
    mock_ensure,
    mock_verify,
    mock_lock,
    mock_firewall,
    mock_active_if,
    mock_dns,
    mock_pwnam,
    mock_udp,
    mock_tcp,
    mock_euid,
):
    """Verify happy path in BYOD mode with manual --tor-uid override."""
    # Mock user "debian-tor" to have UID 101
    mock_user = MagicMock()
    mock_user.pw_uid = 101
    mock_pwnam.return_value = mock_user

    result = runner.invoke(
        app, ["start", "--external-daemon", "--tor-uid", "debian-tor"]
    )
    assert result.exit_code == 0
    assert "Tor daemon detected operating under UID: 101" in result.output

    mock_ensure.assert_not_called()
    mock_firewall.assert_called_once_with(
        tor_user="101",
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        lan_bypass=True,
        disable_ipv6=False,
    )

    _, kwargs_lock = mock_lock.call_args
    assert kwargs_lock["external_daemon"] is True


@patch("os.geteuid", return_value=0)
@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("ttp.commands.start._get_uid_from_port", return_value=105)
@patch("pwd.getpwuid")
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch("ttp.state.write_lock")
@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_happy_path_auto_uid(
    mock_ensure,
    mock_verify,
    mock_lock,
    mock_firewall,
    mock_active_if,
    mock_dns,
    mock_pwuid,
    mock_get_uid,
    mock_udp,
    mock_tcp,
    mock_euid,
):
    """Verify happy path in BYOD mode with port-owner auto-detected UID."""
    mock_user = MagicMock()
    mock_user.pw_name = "tor-process"
    mock_pwuid.return_value = mock_user

    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 0
    assert "Tor daemon detected operating under UID: 105" in result.output

    mock_get_uid.assert_called_once_with(9041)
    mock_firewall.assert_called_once_with(
        tor_user="105",
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        lan_bypass=True,
        disable_ipv6=False,
    )


@patch("os.geteuid", return_value=0)
@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("ttp.commands.start._get_uid_from_port", return_value=None)
@patch("pwd.getpwnam")
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch("ttp.state.write_lock")
@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_happy_path_fallback_user(
    mock_ensure,
    mock_verify,
    mock_lock,
    mock_firewall,
    mock_active_if,
    mock_dns,
    mock_pwnam,
    mock_get_uid,
    mock_udp,
    mock_tcp,
    mock_euid,
):
    """Verify happy path in BYOD mode with fallback standard system users."""
    mock_user = MagicMock()
    mock_user.pw_uid = 110
    # Let "tor" lookup succeed, returning user object
    mock_pwnam.return_value = mock_user

    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 0
    assert "Tor daemon detected operating under UID: 110" in result.output

    mock_pwnam.assert_any_call("tor")


@patch("os.geteuid", return_value=0)
@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("ttp.commands.start._get_uid_from_port", return_value=None)
@patch("pwd.getpwnam", side_effect=KeyError("Not found"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_uid_resolution_failure(
    mock_ensure,
    mock_lock,
    mock_firewall,
    mock_active_if,
    mock_dns,
    mock_pwnam,
    mock_get_uid,
    mock_udp,
    mock_tcp,
    mock_euid,
):
    """Verify that startup fails if no Tor UID can be determined."""
    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 1
    assert "Tor UID Resolution Failed" in result.output


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


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={"is_installed": True, "version": "0.4.8.10"},
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_start_no_ipv6_unsupported(
    mock_ipv6,
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """Verify superfluous warning is printed when IPv6 is unsupported and --no-ipv6 is passed."""
    result = runner.invoke(app, ["start", "--no-ipv6"])
    assert result.exit_code == 0
    assert "superfluous" in result.output
    # verify disable_ipv6=True is propagated down
    mock_ensure.assert_called_once_with(
        transport_port=9041,
        dns_port=9054,
        use_bridges=False,
        bridges=[],
        disable_ipv6=True,
    )
    mock_apply_fw.assert_called_once_with(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        lan_bypass=True,
        disable_ipv6=True,
    )
    mock_apply_dns.assert_called_once_with("eth0", disable_ipv6=True, dns_port=9054)
    mock_write.assert_called_once_with(
        dns_backup={"interface": "eth0"},
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        lan_bypass=True,
        interface="eth0",
        external_daemon=False,
        no_ipv6=True,
        tor_uid=None,
    )


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.dns.detect_active_interface", return_value="eth0")
@patch("ttp.firewall.apply_rules")
@patch(
    "ttp.tor_install.ensure_tor_ready",
    return_value={"is_installed": True, "version": "0.4.8.10"},
)
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.read_lock", return_value=None)
@patch("ttp.state.is_orphan", return_value=False)
@patch("os.geteuid", return_value=0)
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_start_no_ipv6_supported(
    mock_ipv6,
    mock_euid,
    mock_orphan,
    mock_read,
    mock_write,
    mock_selinux,
    mock_ensure,
    mock_apply_fw,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """Verify info message is printed when IPv6 is supported and --no-ipv6 is passed."""
    result = runner.invoke(app, ["start", "--no-ipv6"])
    assert result.exit_code == 0
    assert "IPv6 traffic will be dropped" in result.output
    # verify disable_ipv6=True is propagated down
    mock_ensure.assert_called_once_with(
        transport_port=9041,
        dns_port=9054,
        use_bridges=False,
        bridges=[],
        disable_ipv6=True,
    )
    mock_apply_fw.assert_called_once_with(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        lan_bypass=True,
        disable_ipv6=True,
    )
    mock_apply_dns.assert_called_once_with("eth0", disable_ipv6=True, dns_port=9054)
    mock_write.assert_called_once_with(
        dns_backup={"interface": "eth0"},
        transport_port=9041,
        dns_port=9054,
        allow_root=False,
        lan_bypass=True,
        interface="eth0",
        external_daemon=False,
        no_ipv6=True,
        tor_uid=None,
    )


@patch("ttp.state.delete_lock")
@patch("ttp.dns.restore_dns")
@patch("ttp.firewall.destroy_rules")
@patch("subprocess.run")
@patch("shutil.which", return_value="/usr/sbin/conntrack")
@patch("time.sleep")
@patch("ttp.firewall.apply_active_socket_slaughter")
@patch("ttp.tor_install.stop_tor_service")
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
    )
    mock_lockdown.assert_called_once_with(123)
    mock_slaughter.assert_called_once()
    mock_sleep.assert_called_once_with(0.3)

    expected_order = [
        "stop_wd",
        "lockdown",
        "graceful",
        "stop_tor",
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


@patch("os.geteuid", return_value=1000)
def test_bypass_requires_root(mock_euid):
    """bypass without root -> exit code 1."""
    result = runner.invoke(app, ["bypass", "curl", "http://example.com"])
    assert result.exit_code == 1
    assert "must be run with sudo" in result.output


@patch("os.geteuid", return_value=0)
@patch("os.path.exists", return_value=False)
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
def test_bypass_requires_systemd(mock_exists, mock_euid):
    """bypass fails if systemd is missing."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "requires systemd" in result.output


@patch("os.geteuid", return_value=0)
@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value=None)
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
def test_bypass_requires_active_session(mock_read, mock_exists, mock_euid):
    """bypass fails if no TTP session is active."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "no active session" in result.output.lower()


@patch("os.geteuid", return_value=0)
@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {}, clear=True)
def test_bypass_requires_sudo_env(mock_read, mock_exists, mock_euid):
    """bypass fails if SUDO_UID or SUDO_GID is missing."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "must be run with sudo" in result.output


@patch("os.geteuid", return_value=0)
@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
@patch("shutil.which", return_value=None)
def test_bypass_requires_systemd_run(mock_which, mock_read, mock_exists, mock_euid):
    """bypass fails if systemd-run is missing."""
    result = runner.invoke(app, ["bypass", "curl"])
    assert result.exit_code == 1
    assert "systemd-run' command is required" in result.output


@patch("os.geteuid", return_value=0)
@patch("os.path.exists", return_value=True)
@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})
@patch("shutil.which", return_value="/usr/bin/systemd-run")
@patch("subprocess.run")
def test_bypass_happy_path(mock_run, mock_which, mock_read, mock_exists, mock_euid):
    """bypass runs systemd-run and returns its exit code."""
    mock_run.return_value = MagicMock(returncode=42)
    result = runner.invoke(app, ["bypass", "curl", "http://example.com"])
    assert result.exit_code == 42
    mock_run.assert_called_once_with(
        [
            "/usr/bin/systemd-run",
            "--uid=1000",
            "--gid=1000",
            "--slice=ttp-bypass",
            "--scope",
            "--",
            "curl",
            "http://example.com",
        ],
        check=False,
    )
