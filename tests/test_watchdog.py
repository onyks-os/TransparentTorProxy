"""Tests for ttp.watchdog - session integrity daemon and auto-healing.

All system interactions (systemctl, nft, state lock, dns, firewall) are fully mocked.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

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
    mock_run.return_value = MagicMock(
        stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0
    )

    # Mock Tor controller: supports context manager protocol for the 'with ctrl:' block
    mock_ctrl = MagicMock()
    mock_ctrl.__enter__ = lambda s: s
    mock_ctrl.__exit__ = MagicMock(return_value=False)
    mock_get_ctrl.return_value = mock_ctrl

    comp, err = wd.check_system_integrity()

    assert comp is None
    assert err is None
    mock_is_mount.assert_called_once()
    # Verify active Tor query was performed
    mock_ctrl.get_info.assert_called_once_with("status/bootstrap-phase")


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
    mock_run.return_value = MagicMock(
        stdout="table inet ttp {\n  chain something_else {}\n}\n", returncode=0
    )

    comp, err = wd.check_system_integrity()
    assert comp == "firewall"
    assert "table is incomplete" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.tor_control.get_controller", return_value=None)
def test_check_system_integrity_tor_socket_inactive_service(
    mock_get_ctrl, mock_run, mock_is_mount
):
    """check_system_integrity detects when Tor socket is closed and systemd service is inactive."""

    # nftables: OK
    # Tor service: inactive
    def run_side_effect(args, **kwargs):
        if args[0] == "nft":
            return MagicMock(
                stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0
            )
        elif args[0] == "systemctl" and "is-active" in args:
            return MagicMock(stdout="inactive\n", returncode=0)
        return MagicMock(returncode=0)

    mock_run.side_effect = run_side_effect

    comp, err = wd.check_system_integrity()
    assert comp == "tor"
    assert "inactive/stopped" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.watchdog.subprocess.run")
@patch("ttp.tor_control.get_controller")
def test_check_system_integrity_tor_unresponsive(
    mock_get_ctrl, mock_run, mock_is_mount
):
    """check_system_integrity detects when Tor socket exists but get_info fails (stale/dead Tor)."""
    mock_run.return_value = MagicMock(
        stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0
    )

    # Simulate a stale socket: get_info raises an exception inside the 'with' block
    mock_ctrl = MagicMock()
    mock_ctrl.__enter__ = lambda s: s
    mock_ctrl.__exit__ = MagicMock(return_value=False)
    mock_ctrl.get_info.side_effect = Exception("Socket closed")
    mock_get_ctrl.return_value = mock_ctrl

    comp, err = wd.check_system_integrity()
    assert comp == "tor"
    assert "unresponsive" in err


# 5. attempt_auto_healing
@patch(
    "ttp.watchdog.state.read_lock",
    return_value={"transport_port": 9041, "dns_port": 9054},
)
@patch("ttp.dns.detect_active_interface", return_value="wlan0")
@patch("ttp.dns.apply_dns")
def test_attempt_auto_healing_dns(mock_apply_dns, mock_detect, mock_read):
    """attempt_auto_healing('dns') runs dns auto-healing functions."""
    result = wd.attempt_auto_healing("dns")
    assert result is True
    mock_detect.assert_called_once()
    mock_apply_dns.assert_called_once_with("wlan0")


@patch(
    "ttp.watchdog.state.read_lock",
    return_value={
        "transport_port": 9080,
        "dns_port": 9090,
        "allow_root": True,
        "lan_bypass": False,
    },
)
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


@patch(
    "ttp.watchdog.state.read_lock",
    return_value={
        "pid": 1234,
        "transport_port": 9041,
        "dns_port": 9054,
        "use_bridges": True,
        "bridges": ["obfs4 192.0.2.1:1234"],
    },
)
@patch("ttp.tor_install.ensure_tor_ready")
def test_attempt_auto_healing_tor(mock_ensure, mock_read):
    """attempt_auto_healing('tor') restarts the systemd 'ttp-tor' service."""
    result = wd.attempt_auto_healing("tor")
    assert result is True
    mock_ensure.assert_called_once_with(
        transport_port=9041,
        dns_port=9054,
        use_bridges=True,
        bridges=["obfs4 192.0.2.1:1234"],
    )


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
@patch("ttp.watchdog.is_interface_online", return_value=True)
@patch("ttp.watchdog.has_default_route", return_value=True)
@patch("ttp.watchdog.time.sleep")
def test_run_watchdog_loop_first_strike_healed(
    mock_sleep, mock_has_route, mock_online, mock_heal, mock_check, mock_read
):
    """run_watchdog_loop detects failure, heals successfully, and continues loop."""
    # Simulate a loop that runs once then exits because lock is removed
    mock_read.side_effect = [
        {"pid": 123},  # First check: active
        None,  # Second check: exit loop
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
@patch("ttp.watchdog.is_interface_online", return_value=True)
@patch("ttp.watchdog.has_default_route", return_value=True)
@patch("ttp.watchdog.trigger_emergency_killswitch")
@patch("ttp.watchdog.time.sleep")
def test_run_watchdog_loop_second_strike_killswitch(
    mock_sleep, mock_ks, mock_has_route, mock_online, mock_heal, mock_check, mock_read
):
    """run_watchdog_loop triggers emergency killswitch and exits if healing runs but system stays broken."""
    # First check: failed on tor
    # Second check (after healing): still failed on tor
    mock_check.side_effect = [
        ("tor", "service dead"),
        ("tor", "service dead"),
    ]

    wd.run_watchdog_loop(interval_seconds=1)

    mock_heal.assert_called_once_with("tor")
    mock_ks.assert_called_once_with("tor", "service dead")


@patch("ttp.watchdog.state.read_lock", return_value={"pid": 123})
@patch("ttp.watchdog.check_system_integrity")
@patch("ttp.watchdog.attempt_auto_healing", return_value=False)
@patch("ttp.watchdog.is_interface_online", return_value=True)
@patch("ttp.watchdog.has_default_route", return_value=True)
@patch("ttp.watchdog.trigger_emergency_killswitch")
@patch("ttp.watchdog.time.sleep")
def test_run_watchdog_loop_healing_command_fails_immediate_killswitch(
    mock_sleep, mock_ks, mock_has_route, mock_online, mock_heal, mock_check, mock_read
):
    """run_watchdog_loop triggers emergency killswitch immediately if the healing command itself fails."""
    # Only one integrity check: healing fails immediately, no re-check should occur
    mock_check.return_value = ("firewall", "nftables apply error")

    wd.run_watchdog_loop(interval_seconds=1)

    mock_heal.assert_called_once_with("firewall")
    # Killswitch triggered without waiting for a second check
    mock_ks.assert_called_once_with("firewall", "nftables apply error")
    # Only one integrity check should have happened (no re-check after failed healing)
    assert mock_check.call_count == 1


# 8. Diagnostic helper tests and loop suspension
@patch("ttp.watchdog.Path.exists", return_value=True)
def test_is_interface_online_up(mock_exists):
    """is_interface_online returns True if operstate is up and carrier is 1."""

    def read_text_side_effect(self):
        if "operstate" in str(self):
            return "up\n"
        elif "carrier" in str(self):
            return "1\n"
        return ""

    with patch("ttp.watchdog.Path.read_text", read_text_side_effect):
        assert wd.is_interface_online("eth0") is True


@patch("ttp.watchdog.Path.exists", return_value=True)
def test_is_interface_online_down(mock_exists):
    """is_interface_online returns False if operstate is down or carrier is 0."""

    # 1. operstate down
    def read_text_down(self):
        if "operstate" in str(self):
            return "down\n"
        return "1\n"

    with patch("ttp.watchdog.Path.read_text", read_text_down):
        assert wd.is_interface_online("eth0") is False

    # 2. carrier 0
    def read_text_carrier_zero(self):
        if "operstate" in str(self):
            return "up\n"
        return "0\n"

    with patch("ttp.watchdog.Path.read_text", read_text_carrier_zero):
        assert wd.is_interface_online("eth0") is False


@patch("ttp.watchdog.Path.exists", return_value=True)
def test_has_default_route_true(mock_exists):
    """has_default_route returns True if /proc/net/route has destination 00000000 and mask 00000000."""
    mock_content = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    with patch("builtins.open", mock_open(read_data=mock_content)):
        assert wd.has_default_route() is True


@patch("ttp.watchdog.Path.exists", return_value=True)
def test_has_default_route_false(mock_exists):
    """has_default_route returns False if no default route exists."""
    mock_content = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
    )
    with patch("builtins.open", mock_open(read_data=mock_content)):
        assert wd.has_default_route() is False


@patch("ttp.watchdog.state.read_lock")
@patch("ttp.watchdog.is_interface_online")
@patch("ttp.watchdog.has_default_route")
@patch("ttp.watchdog.time.sleep")
@patch("ttp.watchdog.check_system_integrity")
def test_run_watchdog_loop_suspends_and_resumes(
    mock_check, mock_sleep, mock_has_route, mock_online, mock_read
):
    """run_watchdog_loop enters suspended state when network is offline, and resumes once online."""
    mock_read.side_effect = [
        {"interface": "eth0"},  # First iteration start
        {"interface": "eth0"},  # Inside recovery loop check
        None,  # Exit recovery loop / main loop exit
    ]

    mock_online.side_effect = [False, True]
    mock_has_route.return_value = True

    wd.run_watchdog_loop(interval_seconds=1)

    assert mock_online.call_count == 2
    mock_check.assert_not_called()
    sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
    assert 10 in sleep_calls
