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
@patch("ttp.cli.os.geteuid", return_value=0)
def test_uninstall_calls_cleanup(
    mock_euid, mock_log_path, mock_read, mock_is_sel, mock_rem_sel, mock_stop
):
    """uninstall → stops session, removes SELinux, and cleans logs."""
    # Ensure log path mock behaves like a Path object
    mock_log_path.exists.return_value = True

    result = runner.invoke(app, ["uninstall"])
    assert result.exit_code == 0
    assert "Uninstallation complete" in result.output

    mock_stop.assert_called_once()
    mock_rem_sel.assert_called_once()
    mock_log_path.unlink.assert_called_once()
