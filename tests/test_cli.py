"""Tests for ttp.cli - CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

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
    with patch("ttp.cli.state.check_tmpfs_space"):
        yield


# start


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.firewall.apply_rules")
@patch(
    "ttp.cli.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.cli.tor_install.setup_selinux_if_needed")
@patch("ttp.cli.state.write_lock")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch("ttp.cli.os.geteuid", return_value=0)
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


@patch("ttp.cli.os.geteuid", return_value=1000)
def test_start_requires_root(mock_euid):
    """start without root -> exit code 1."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "root" in result.output


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.firewall.apply_rules")
@patch(
    "ttp.cli.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.cli.tor_install.setup_selinux_if_needed")
@patch("ttp.cli.state.write_lock")
@patch("ttp.cli.state.attempt_recovery")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli.state.is_orphan", return_value=True)
@patch("ttp.cli.os.geteuid", return_value=0)
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


@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_start_concurrency_error(mock_euid, mock_orphan, mock_read):
    """start with another TTP instance running (PID alive) -> error."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "concurrency error" in result.output.lower()


# stop


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch("ttp.cli.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown", return_value=True)
@patch(
    "ttp.cli.state.read_lock",
    return_value={
        "dns_backup": {"mount_target": "/etc/resolv.conf"},
    },
)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_active_session(
    mock_euid, mock_read, mock_graceful, mock_stop_tor, mock_fw, mock_dns, mock_del
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


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch("ttp.cli.tor_install.stop_tor_service")
@patch("ttp.tor_control.graceful_shutdown", return_value=False)
@patch(
    "ttp.cli.state.read_lock",
    return_value={
        "dns_backup": {"mount_target": "/etc/resolv.conf"},
    },
)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_graceful_shutdown_failure_continues(
    mock_euid, mock_read, mock_graceful, mock_stop_tor, mock_fw, mock_dns, mock_del
):
    """stop continues even if graceful_shutdown fails."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "terminated" in result.output
    mock_graceful.assert_called_once()
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()


@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_no_session(mock_euid, mock_read):
    """stop with no session -> clean exit."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "No active session" in result.output


# status


@patch("ttp.tor_control.get_exit_ip", return_value="5.6.7.8")
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch(
    "ttp.cli.state.read_lock",
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


@patch("ttp.cli.state.read_lock", return_value=None)
def test_status_inactive(mock_read):
    """status with no session -> shows INACTIVE."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "INACTIVE" in result.output


# start with --interface


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "wlan0"})
@patch("ttp.cli.firewall.apply_rules")
@patch(
    "ttp.cli.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.cli.tor_install.setup_selinux_if_needed")
@patch("ttp.cli.state.write_lock")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch("ttp.cli.os.geteuid", return_value=0)
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
    mock_apply_dns.assert_called_once_with("wlan0")


# health check warning


@patch("ttp.cli._verify_tor", return_value=(False, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.firewall.apply_rules")
@patch(
    "ttp.cli.tor_install.ensure_tor_ready",
    return_value={
        "is_installed": True,
        "is_running": True,
        "is_configured": True,
        "tor_user": "debian-tor",
        "version": "0.4.8.10",
    },
)
@patch("ttp.cli.tor_install.setup_selinux_if_needed")
@patch("ttp.cli.state.write_lock")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch("ttp.cli.os.geteuid", return_value=0)
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


@patch("ttp.cli._do_stop")
@patch("ttp.cli.tor_install.remove_selinux_module")
@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli.state.delete_star_sentinel")
@patch("ttp.cli.os.geteuid", return_value=0)
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


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.firewall.apply_rules")
@patch(
    "ttp.cli.tor_install.ensure_tor_ready",
    return_value={"is_installed": True, "version": "0.4.8.10"},
)
@patch("ttp.cli.tor_install.setup_selinux_if_needed")
@patch("ttp.cli.state.write_lock")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch("ttp.cli.os.geteuid", return_value=0)
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


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch("ttp.cli.tor_install.stop_tor_service")
@patch(
    "ttp.cli.state.read_lock",
    return_value={"dns_backup": {"mount_target": "/etc/resolv.conf"}},
)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_restore_only_with_lock(
    mock_euid, mock_read, mock_stop_tor, mock_fw, mock_dns, mock_del
):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()
    mock_dns.assert_called_once_with({"mount_target": "/etc/resolv.conf"})
    mock_del.assert_called_once()


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch("ttp.cli.tor_install.stop_tor_service")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_restore_only_no_lock(
    mock_euid,
    mock_read,
    mock_stop_tor,
    mock_fw,
    mock_dns,
    mock_del,
):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    mock_stop_tor.assert_called_once()
    mock_fw.assert_called_once()
    mock_dns.assert_called_once_with(None)
    mock_del.assert_called_once()


# restart


@patch("ttp.cli.start")
@patch("ttp.cli.time.sleep")
@patch("ttp.cli._do_stop")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli.os.geteuid", return_value=0)
def test_restart_active_session(
    mock_euid, mock_read, mock_stop, mock_sleep, mock_start
):
    result = runner.invoke(
        app, ["restart", "--interface", "wlan0", "--bootstrap-timeout", "300"]
    )
    assert result.exit_code == 0
    mock_stop.assert_called_once()
    mock_sleep.assert_called_once_with(1)
    mock_start.assert_called_once_with(interface="wlan0", bootstrap_timeout=300)


@patch("ttp.cli.start")
@patch("ttp.cli._do_stop")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_restart_inactive_session(mock_euid, mock_read, mock_stop, mock_start):
    result = runner.invoke(app, ["restart"])
    assert result.exit_code == 0
    mock_stop.assert_not_called()
    mock_start.assert_called_once_with(interface=None, bootstrap_timeout=180)


# check


@patch("ttp.tor_control.get_controller")
@patch("urllib.request.urlopen")
def test_check_success(mock_urlopen, mock_get_ctrl):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": True, "IP": "100.200.100.200"}
    ).encode()
    mock_get_ctrl.return_value = True

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "100.200.100.200" in result.output
    assert "Yes (IsTor=True)" in result.output
    assert "Yes (Controller connected)" in result.output


@patch("urllib.request.urlopen", side_effect=Exception("Connection refused"))
def test_check_failure(mock_urlopen):
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 1
    assert "Failed to reach check.torproject.org" in result.output


# check-leak


@patch("subprocess.run")
@patch("shutil.which", return_value="/usr/bin/dig")
@patch("urllib.request.urlopen")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
def test_check_leak_success(mock_read, mock_urlopen, mock_which, mock_run):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": True, "IP": "1.1.1.1"}
    ).encode()

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
@patch("urllib.request.urlopen")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
def test_check_leak_akahelp_txt_ip_not_a_leak(mock_read, mock_urlopen, mock_which, mock_run):
    """Resolver IP from Akamai TXT must not set has_leaks (regression for false positives)."""
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": True, "IP": "1.1.1.1"}
    ).encode()

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


@patch("urllib.request.urlopen")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
def test_check_leak_detected_istor_false(mock_read, mock_urlopen):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps(
        {"IsTor": False, "IP": "8.8.8.8"}
    ).encode()

    with patch("shutil.which", return_value="/usr/bin/dig"), patch(
        "subprocess.run"
    ) as mock_run:

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


@patch("urllib.request.urlopen", side_effect=OSError("network down"))
@patch("shutil.which", return_value="/usr/bin/dig")
@patch("subprocess.run")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
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
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
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
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
def test_check_leak_empty_dig_a(mock_read, mock_run, mock_which, mock_urlopen):
    import json

    mock_response = mock_urlopen.return_value.__enter__.return_value
    mock_response.read.return_value = json.dumps({"IsTor": True}).encode()

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


@patch("ttp.cli.state.read_lock", return_value=None)
def test_check_leak_inactive(mock_read):
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "INACTIVE" in result.output


# logs


@patch("ttp.cli._LOG_PATH")
def test_logs_command(mock_log_path):
    mock_log_path.exists.return_value = True
    mock_log_path.read_text.return_value = "Mock log content"

    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 0
    assert "Mock log content" in result.output
    mock_log_path.read_text.assert_called_once_with(encoding="utf-8")


@patch("ttp.cli._LOG_PATH")
def test_logs_command_no_file(mock_log_path):
    mock_log_path.exists.return_value = False

    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 1
    assert "No log file found" in result.output


# tmpfs pre-flight


@patch("ttp.cli.state.check_tmpfs_space")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_start_tmpfs_check_fails(mock_euid, mock_read, mock_check):
    """start aborts cleanly when /run has no space, without touching system state."""
    from ttp.exceptions import StateError

    mock_check.side_effect = StateError("Insufficient space on /run")

    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "Pre-flight Failed" in result.output
    assert "Insufficient space" in result.output
