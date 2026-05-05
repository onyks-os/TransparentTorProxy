"""Tests for ttp.cli — CLI entry point.

All external calls (firewall, DNS, Tor, network) are fully mocked.
Tests verify command orchestration logic, not system interactions.
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from ttp.cli import app

runner = CliRunner()


# ── start ──────────────────────────────────────────────────────────


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.dns.detect_dns_mode", return_value="resolvectl")
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
    mock_dns_mode,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with all systems go → session active."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    assert "Session active" in result.output
    mock_write.assert_called_once()
    mock_apply_fw.assert_called_once()


@patch("ttp.cli.os.geteuid", return_value=1000)
def test_start_requires_root(mock_euid):
    """start without root → exit code 1."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "root" in result.output


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.dns.detect_dns_mode", return_value="resolvectl")
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
    mock_dns_mode,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with orphaned session (PID dead) → auto-recovers and continues."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    mock_recovery.assert_called_once()
    assert "recovering" in result.output.lower()


@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli.state.is_orphan", return_value=False)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_start_concurrency_error(mock_euid, mock_orphan, mock_read):
    """start with another TTP instance running (PID alive) → error."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "concurrency error" in result.output.lower()


# ── stop ───────────────────────────────────────────────────────────


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch(
    "ttp.cli.state.read_lock",
    return_value={
        "dns_mode": "resolvectl",
        "dns_backup": {"interface": "eth0"},
    },
)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_active_session(mock_euid, mock_read, mock_fw, mock_dns, mock_del):
    """stop with active session → restores and deletes lock."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "terminated" in result.output
    mock_fw.assert_called_once()
    mock_dns.assert_called_once()
    mock_del.assert_called_once()


@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_no_session(mock_euid, mock_read):
    """stop with no session → clean exit."""
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 0
    assert "No active session" in result.output


# ── status ─────────────────────────────────────────────────────────


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
    """status with active session → shows IP and timestamp."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "ACTIVE" in result.output
    assert "5.6.7.8" in result.output


@patch("ttp.cli.state.read_lock", return_value=None)
def test_status_inactive(mock_read):
    """status with no session → shows INACTIVE."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "INACTIVE" in result.output


# ── start with --interface ─────────────────────────────────────────


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "wlan0"})
@patch("ttp.cli.dns.detect_dns_mode", return_value="resolvectl")
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
    mock_dns_mode,
    mock_apply_dns,
    mock_verify,
):
    """start --interface wlan0 → uses wlan0 instead of auto-detect."""
    result = runner.invoke(app, ["start", "--interface", "wlan0"])
    assert result.exit_code == 0
    mock_apply_dns.assert_called_once_with("resolvectl", "wlan0")


# ── health check warning ──────────────────────────────────────────


@patch("ttp.cli._verify_tor", return_value=(False, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.dns.detect_dns_mode", return_value="resolvectl")
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
    mock_dns_mode,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    """start with Tor not verified → shows warning."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    assert "verification failed" in result.output


# ── uninstall ──────────────────────────────────────────────────────


@patch("ttp.cli._do_stop")
@patch("ttp.cli.tor_install.remove_selinux_module")
@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli._LOG_PATH")
@patch("ttp.cli.state.delete_star_sentinel")
@patch("ttp.cli.os.geteuid", return_value=0)
def test_uninstall_calls_cleanup(
    mock_euid, mock_del_star, mock_log_path, mock_read, mock_is_sel, mock_rem_sel, mock_stop
):
    """uninstall -> stops session, removes SELinux, and cleans logs."""
    # Ensure log path mock behaves like a Path object
    mock_log_path.exists.return_value = True

    result = runner.invoke(app, ["uninstall"])
    assert result.exit_code == 0
    assert "Uninstallation complete" in result.output

    mock_stop.assert_called_once()
    mock_rem_sel.assert_called_once()
    mock_log_path.unlink.assert_called_once()
    mock_del_star.assert_called_once()



# ── start with --bootstrap-timeout ─────────────────────────────────


@patch("ttp.cli._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.cli.dns.apply_dns", return_value={"interface": "eth0"})
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.dns.detect_dns_mode", return_value="resolvectl")
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
    mock_dns_mode,
    mock_iface,
    mock_apply_dns,
    mock_verify,
):
    result = runner.invoke(app, ["start", "--bootstrap-timeout", "300"])
    assert result.exit_code == 0
    mock_verify.assert_called_once_with(timeout=300)


# ── stop --restore-only ────────────────────────────────────────────


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch(
    "ttp.cli.state.read_lock", return_value={"dns_mode": "resolvectl", "dns_backup": {}}
)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_restore_only_with_lock(mock_euid, mock_read, mock_fw, mock_dns, mock_del):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    mock_fw.assert_called_once()
    mock_dns.assert_called_once_with("resolvectl", {})
    mock_del.assert_called_once()


@patch("ttp.cli.state.delete_lock")
@patch("ttp.cli.dns.detect_active_interface", return_value="eth0")
@patch("ttp.cli.dns.detect_dns_mode", return_value="resolvectl")
@patch("ttp.cli.dns.restore_dns")
@patch("ttp.cli.firewall.destroy_rules")
@patch("ttp.cli.state.read_lock", return_value=None)
@patch("ttp.cli.os.geteuid", return_value=0)
def test_stop_restore_only_no_lock(
    mock_euid,
    mock_read,
    mock_fw,
    mock_dns,
    mock_detect_mode,
    mock_detect_iface,
    mock_del,
):
    result = runner.invoke(app, ["stop", "--restore-only"])
    assert result.exit_code == 0
    assert "Forcing network restoration" in result.output
    mock_fw.assert_called_once()
    mock_dns.assert_called_once_with("resolvectl", {"interface": "eth0"})
    mock_del.assert_called_once()


# ── restart ────────────────────────────────────────────────────────


@patch("ttp.cli.start")
@patch("ttp.cli.time.sleep")
@patch("ttp.cli._do_stop")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
@patch("ttp.cli.os.geteuid", return_value=0)
def test_restart_active_session(mock_euid, mock_read, mock_stop, mock_sleep, mock_start):
    result = runner.invoke(app, ["restart", "--interface", "wlan0", "--bootstrap-timeout", "300"])
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


# ── check ──────────────────────────────────────────────────────────


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


# ── check-leak ─────────────────────────────────────────────────────


@patch("subprocess.run")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
def test_check_leak_success(mock_read, mock_run):
    import json
    from unittest.mock import MagicMock

    def side_effect(cmd, *args, **kwargs):
        mock_result = MagicMock()
        if cmd[0] == "curl":
            mock_result.stdout = json.dumps({"IsTor": True, "IP": "1.1.1.1"})
        elif cmd[0] == "dig" and cmd[2] == "A":
            mock_result.stdout = "2.2.2.2"
        elif cmd[0] == "dig" and cmd[2] == "TXT":
            mock_result.stdout = ""
        return mock_result

    mock_run.side_effect = side_effect

    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 0
    assert "No leaks detected" in result.output


@patch("subprocess.run")
@patch("ttp.cli.state.read_lock", return_value={"pid": 1234})
def test_check_leak_detected(mock_read, mock_run):
    from unittest.mock import MagicMock

    def side_effect(cmd, *args, **kwargs):
        mock_result = MagicMock()
        if cmd[0] == "curl":
            mock_result.stdout = '{"IsTor": true}'
        elif cmd[0] == "dig" and cmd[2] == "A":
            mock_result.stdout = "2.2.2.2"
        elif cmd[0] == "dig" and cmd[2] == "TXT":
            mock_result.stdout = "192.168.1.1"
        return mock_result

    mock_run.side_effect = side_effect

    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "Leaks detected!" in result.output


@patch("ttp.cli.state.read_lock", return_value=None)
def test_check_leak_inactive(mock_read):
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1
    assert "INACTIVE" in result.output


# ── logs ───────────────────────────────────────────────────────────


@patch("subprocess.run")
@patch("ttp.tor_detect._get_service_name", return_value="tor@default")
def test_logs_command(mock_get_service, mock_run):
    result = runner.invoke(app, ["logs"])
    assert result.exit_code == 0
    mock_run.assert_called_once_with(
        ["journalctl", "-u", "tor@default", "-n", "50", "-f"]
    )
