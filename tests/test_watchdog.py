"""Tests for ttp.watchdog - session integrity daemon and auto-healing.

All system interactions (systemctl, nft, state lock, dns, firewall) are fully mocked.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import watchdog as wd
from ttp.exceptions import TorError


@pytest.fixture
def temp_watchdog_path(tmp_path: Path):
    """Patch the volatile systemd unit path to point to a temporary file."""
    temp_file = tmp_path / "run" / "systemd" / "system" / "ttp-watchdog.service"
    with patch.object(wd, "WATCHDOG_SERVICE_PATH", temp_file):
        yield temp_file


# 1. _write_watchdog_service_unit
def test_write_watchdog_service_unit(temp_watchdog_path):
    """_write_watchdog_service_unit writes a valid systemd unit to the volatile directory."""
    wd._write_watchdog_service_unit()
    assert temp_watchdog_path.exists()
    content = temp_watchdog_path.read_text(encoding="utf-8")
    assert "[Unit]" in content
    assert "Description=TTP Session Watchdog & Killswitch" in content
    assert "ExecStart=" in content
    assert "ttp.cli watchdog run" in content


# 2. start_watchdog
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.watchdog.state.update_lock_keys")
def test_start_watchdog_success(mock_update, mock_run, temp_watchdog_path):
    """start_watchdog writes unit, reloads daemon, starts service, queries PID, and updates state."""
    # Mock systemctl show to return MainPID=12345
    mock_run.return_value = MagicMock(stdout="MainPID=12345\n", returncode=0)

    wd.start_watchdog()

    assert temp_watchdog_path.exists()
    # Check systemctl calls
    assert mock_run.call_count == 3
    # Check update_lock_keys
    mock_update.assert_called_once_with(watchdog_active=True, watchdog_pid=12345)


@patch("ttp.watchdog.subprocess.run", side_effect=Exception("systemd error"))
def test_start_watchdog_failure(mock_run, temp_watchdog_path):
    """start_watchdog raises TorError if any systemctl call fails."""
    with pytest.raises(TorError, match="Failed to start watchdog service"):
        wd.start_watchdog()


# 3. stop_watchdog
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.watchdog.state.update_lock_keys")
def test_stop_watchdog(mock_update, mock_run, temp_watchdog_path):
    """stop_watchdog stops service, unlinks unit file, reloads systemd daemon, and updates state."""
    # Write a dummy unit first
    temp_watchdog_path.parent.mkdir(parents=True, exist_ok=True)
    temp_watchdog_path.write_text("dummy", encoding="utf-8")
    assert temp_watchdog_path.exists()

    wd.stop_watchdog()

    assert not temp_watchdog_path.exists()
    assert mock_run.call_count == 2
    mock_update.assert_called_once_with(watchdog_active=False, watchdog_pid=None)


# 4. check_system_integrity
@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.tor_control.get_controller")
def test_check_system_integrity_healthy(mock_get_ctrl, mock_run, mock_is_mount):
    """check_system_integrity returns (None, None) when all systems are healthy."""
    # Mock nftables ruleset to contain filter_out
    mock_run.return_value = MagicMock(stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0)

    # Mock Tor controller socket to successfully connect and close
    mock_ctrl = MagicMock()
    mock_get_ctrl.return_value = mock_ctrl

    comp, err = wd.check_system_integrity()

    assert comp is None
    assert err is None
    mock_is_mount.assert_called_once()
    mock_ctrl.close.assert_called_once()


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=False)
def test_check_system_integrity_dns_failure(mock_is_mount):
    """check_system_integrity detects when DNS resolv.conf overlay is unmounted."""
    comp, err = wd.check_system_integrity()
    assert comp == "dns"
    assert "resolv.conf overlay mount has been unmounted" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.watchdog.subprocess.run")
def test_check_system_integrity_firewall_missing_table(mock_run, mock_is_mount):
    """check_system_integrity detects when the nftables 'inet ttp' table is entirely missing."""
    mock_run.return_value = MagicMock(stdout="", returncode=1)

    comp, err = wd.check_system_integrity()
    assert comp == "firewall"
    assert "table is missing" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.watchdog.subprocess.run")
def test_check_system_integrity_firewall_incomplete_table(mock_run, mock_is_mount):
    """check_system_integrity detects when 'inet ttp' table is present but incomplete."""
    mock_run.return_value = MagicMock(stdout="table inet ttp {\n  chain something_else {}\n}\n", returncode=0)

    comp, err = wd.check_system_integrity()
    assert comp == "firewall"
    assert "table is incomplete" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.tor_control.get_controller", return_value=None)
def test_check_system_integrity_tor_socket_inactive_service(mock_get_ctrl, mock_run, mock_is_mount):
    """check_system_integrity detects when Tor socket is closed and systemd service is inactive."""
    # nftables: OK
    # Tor service: inactive
    def run_side_effect(args, **kwargs):
        if args[0] == "nft":
            return MagicMock(stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0)
        elif args[0] == "systemctl" and "is-active" in args:
            return MagicMock(stdout="inactive\n", returncode=0)
        return MagicMock(returncode=0)

    mock_run.side_effect = run_side_effect

    comp, err = wd.check_system_integrity()
    assert comp == "tor"
    assert "inactive/stopped" in err


# 5. attempt_auto_healing
@patch("ttp.watchdog.state.read_lock", return_value={"transport_port": 9041, "dns_port": 9054})
@patch("ttp.dns.detect_active_interface", return_value="wlan0")
@patch("ttp.dns.apply_dns")
def test_attempt_auto_healing_dns(mock_apply_dns, mock_detect, mock_read):
    """attempt_auto_healing('dns') runs dns auto-healing functions."""
    result = wd.attempt_auto_healing("dns")
    assert result is True
    mock_detect.assert_called_once()
    mock_apply_dns.assert_called_once_with("wlan0")


@patch("ttp.watchdog.state.read_lock", return_value={"transport_port": 9080, "dns_port": 9090, "allow_root": True, "lan_bypass": False})
@patch("ttp.tor_detect.detect_tor", return_value={"tor_user": "custom-tor"})
@patch("ttp.firewall.apply_rules")
def test_attempt_auto_healing_firewall(mock_apply_fw, mock_detect_tor, mock_read):
    """attempt_auto_healing('firewall') reapplies nftables rules from state configuration."""
    result = wd.attempt_auto_healing("firewall")
    assert result is True
    mock_detect_tor.assert_called_once()
    mock_apply_fw.assert_called_once_with(
        tor_user="custom-tor",
        transport_port=9080,
        dns_port=9090,
        allow_root=True,
        lan_bypass=False,
    )


@patch("ttp.watchdog.state.read_lock", return_value={"pid": 1234})
@patch("ttp.watchdog.subprocess.run")
def test_attempt_auto_healing_tor(mock_run, mock_read):
    """attempt_auto_healing('tor') restarts the systemd 'ttp-tor' service."""
    result = wd.attempt_auto_healing("tor")
    assert result is True
    mock_run.assert_called_once_with(["systemctl", "restart", "ttp-tor"], capture_output=True, text=True, check=True)


# 6. trigger_emergency_killswitch
@patch("ttp.firewall.apply_emergency_killswitch")
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.watchdog.shutil.which", return_value="/usr/bin/notify-send")
def test_trigger_emergency_killswitch(mock_which, mock_run, mock_apply_ks):
    """trigger_emergency_killswitch isolates network, sends wall alert, and desktop notification."""
    wd.trigger_emergency_killswitch("firewall", "nftables table deleted")

    mock_apply_ks.assert_called_once()
    assert mock_run.call_count == 2
    # Ensure wall and notify-send were called
    calls = [call[0][0] for call in mock_run.call_args_list]
    assert any("wall" in cmd for cmd in calls)
    assert any("notify-send" in cmd for cmd in calls)


# 7. run_watchdog_loop
@patch("ttp.watchdog.state.read_lock", return_value=None)
@patch("ttp.watchdog.time.sleep")
def test_run_watchdog_loop_no_lock(mock_sleep, mock_read):
    """run_watchdog_loop terminates immediately if no active session lock is found."""
    # Should exit loop immediately
    wd.run_watchdog_loop(interval_seconds=1)
    mock_sleep.assert_called_once_with(2)  # Startup stabilization sleep


@patch("ttp.watchdog.state.read_lock")
@patch("ttp.watchdog.check_system_integrity")
@patch("ttp.watchdog.attempt_auto_healing", return_value=True)
@patch("ttp.watchdog.time.sleep")
def test_run_watchdog_loop_first_strike_healed(mock_sleep, mock_heal, mock_check, mock_read):
    """run_watchdog_loop detects failure, heals successfully, and continues loop."""
    # Simulate a loop that runs once then exits because lock is removed
    mock_read.side_effect = [
        {"pid": 123},  # First check: active
        None,          # Second check: exit loop
    ]
    # First check: failed on firewall
    # Second check (after healing): healthy (None, None)
    mock_check.side_effect = [
        ("firewall", "rules missing"),
        (None, None),
    ]

    wd.run_watchdog_loop(interval_seconds=1)

    mock_heal.assert_called_once_with("firewall")
    # Verify stabilizing delay (3s) and normal delay (1s) were invoked
    sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
    assert 3 in sleep_calls


@patch("ttp.watchdog.state.read_lock", return_value={"pid": 123})
@patch("ttp.watchdog.check_system_integrity")
@patch("ttp.watchdog.attempt_auto_healing", return_value=True)
@patch("ttp.watchdog.trigger_emergency_killswitch")
@patch("ttp.watchdog.time.sleep")
def test_run_watchdog_loop_second_strike_killswitch(mock_sleep, mock_ks, mock_heal, mock_check, mock_read):
    """run_watchdog_loop triggers emergency killswitch and exits if healing fails to restore integrity."""
    # First check: failed on tor
    # Second check (after healing): still failed on tor
    mock_check.side_effect = [
        ("tor", "service dead"),
        ("tor", "service dead"),
    ]

    wd.run_watchdog_loop(interval_seconds=1)

    mock_heal.assert_called_once_with("tor")
    mock_ks.assert_called_once_with("tor", "service dead")
