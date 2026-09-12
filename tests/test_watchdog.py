# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.watchdog - session integrity daemon and auto-healing.

All system interactions (systemctl, nft, state lock, dns, firewall) are fully mocked.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from ttp import watchdog as wd
from ttp.exceptions import TorError
from ttp.paths import resolve, resolve_optional


@pytest.fixture
def temp_watchdog_path(tmp_path: Path):
    """Patch the volatile systemd unit path to point to a temporary file."""
    temp_file = tmp_path / "run" / "systemd" / "system" / "ttp-watchdog.service"
    with (
        patch("ttp.watchdog.service.WATCHDOG_SERVICE_PATH", temp_file),
        patch("ttp.watchdog.WATCHDOG_SERVICE_PATH", temp_file),
    ):
        yield temp_file


@pytest.fixture(autouse=True)
def mock_resolv_conf():
    original_read_text = Path.read_text

    def mock_read_text(self, *args, **kwargs):
        if "resolv.conf" in str(self):
            return "nameserver 127.0.0.1"
        return original_read_text(self, *args, **kwargs)

    with patch("pathlib.Path.read_text", mock_read_text):
        yield


@pytest.fixture(autouse=True)
def mock_netlink_and_inotify():
    # Mock socket.socket
    mock_sock = MagicMock()
    with (
        patch("socket.socket", return_value=mock_sock),
        patch("select.select") as mock_select,
        patch("ctypes.CDLL") as mock_cdll,
        patch("ctypes.util.find_library", return_value="libc.so.6"),
        patch("os.set_blocking"),
        patch("os.read", return_value=b""),
    ):
        mock_select.return_value = ([], [], [])

        mock_libc = MagicMock()
        mock_libc.inotify_init.return_value = 999
        mock_libc.inotify_add_watch.return_value = 1
        mock_libc.inotify_rm_watch.return_value = 0
        mock_cdll.return_value = mock_libc

        yield


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
@patch("subprocess.run")
@patch("ttp.state.update_lock_keys")
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


@patch("subprocess.run", side_effect=Exception("systemd error"))
def test_start_watchdog_failure(mock_run, temp_watchdog_path):
    """start_watchdog raises TorError if any systemctl call fails."""
    with pytest.raises(TorError, match="Failed to start watchdog service"):
        wd.start_watchdog()


# 3. stop_watchdog
@patch("subprocess.run")
@patch("ttp.state.update_lock_keys")
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
@patch("subprocess.run")
@patch("ttp.tor_control.get_controller")
def test_check_system_integrity_healthy(mock_get_ctrl, mock_run, mock_is_mount):
    """check_system_integrity returns (None, None) when all systems are healthy."""
    # Mock nftables ruleset to contain filter_out
    mock_run.return_value = MagicMock(stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0)

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
@patch("subprocess.run")
def test_check_system_integrity_firewall_missing_table(mock_run, mock_is_mount):
    """check_system_integrity detects when the nftables 'inet ttp' table is entirely missing."""
    mock_run.return_value = MagicMock(stdout="", returncode=1)

    comp, err = wd.check_system_integrity()
    assert comp == "firewall"
    assert "table is missing" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("subprocess.run")
def test_check_system_integrity_firewall_incomplete_table(mock_run, mock_is_mount):
    """check_system_integrity detects when 'inet ttp' table is present but incomplete."""
    mock_run.return_value = MagicMock(stdout="table inet ttp {\n  chain something_else {}\n}\n", returncode=0)

    comp, err = wd.check_system_integrity()
    assert comp == "firewall"
    assert "table is incomplete" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("subprocess.run")
@patch("ttp.tor_control.get_controller", return_value=None)
def test_check_system_integrity_tor_socket_inactive_service(mock_get_ctrl, mock_run, mock_is_mount):
    """check_system_integrity detects when Tor socket is closed and systemd service is inactive."""

    # nftables: OK
    # Tor service: inactive
    def run_side_effect(args, **kwargs):
        if args[0] == resolve("nft"):
            return MagicMock(stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0)
        elif args[0] == resolve("systemctl") and "is-active" in args:
            return MagicMock(stdout="inactive\n", returncode=0)
        return MagicMock(returncode=0)

    mock_run.side_effect = run_side_effect

    comp, err = wd.check_system_integrity()
    assert comp == "tor"
    assert "inactive/stopped" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("subprocess.run")
@patch("ttp.tor_control.get_controller")
def test_check_system_integrity_tor_unresponsive(mock_get_ctrl, mock_run, mock_is_mount):
    """check_system_integrity detects when Tor socket exists but get_info fails (stale/dead Tor)."""
    mock_run.return_value = MagicMock(stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0)

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
    "ttp.state.read_lock",
    return_value={"transport_port": 9041, "dns_port": 9054},
)
def test_attempt_auto_healing_dns(mock_read):
    """attempt_auto_healing('dns') returns False (fail-closed, auto-healing skipped)."""
    result = wd.attempt_auto_healing("dns")
    assert result is False


@patch(
    "ttp.state.read_lock",
    return_value={
        "transport_port": 9080,
        "dns_port": 9090,
        "allow_root": True,
        "lan_bypass": False,
    },
)
def test_attempt_auto_healing_firewall(mock_read):
    """attempt_auto_healing('firewall') returns False (fail-closed, auto-healing skipped)."""
    result = wd.attempt_auto_healing("firewall")
    assert result is False


@patch(
    "ttp.state.read_lock",
    return_value={
        "pid": 1234,
        "transport_port": 9041,
        "dns_port": 9054,
        "use_bridges": True,
        "bridges": ["obfs4 192.0.2.1:1234"],
    },
)
@patch("subprocess.run")
def test_attempt_auto_healing_tor(mock_run, mock_read):
    """attempt_auto_healing('tor') restarts the systemd 'ttp-tor.service' service."""
    mock_run.return_value = MagicMock(returncode=0)
    result = wd.attempt_auto_healing("tor")
    assert result is True
    mock_run.assert_called_once_with(
        [resolve("systemctl"), "restart", "ttp-tor.service"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


# 6. trigger_emergency_killswitch
@patch("ttp.firewall.apply_emergency_killswitch")
@patch("subprocess.run")
@patch(
    "ttp.watchdog.alerts.resolve_optional",
    side_effect=lambda b: {"wall": "/usr/bin/wall", "notify-send": "/usr/bin/notify-send"}.get(b),
)
def test_trigger_emergency_killswitch(mock_resolve, mock_run, mock_apply_ks):
    """trigger_emergency_killswitch isolates the network, broadcasts, and notifies."""
    wd.trigger_emergency_killswitch("firewall", "nftables table deleted")

    mock_apply_ks.assert_called_once()
    # resolve_optional is stubbed so this asserts the killswitch's own logic
    # rather than which notification tools this particular host happens to ship;
    # a CI runner without `wall` used to make this fail for no useful reason.
    assert mock_run.call_count == 2
    calls = [call[0][0] for call in mock_run.call_args_list]
    assert any("/usr/bin/wall" in cmd for cmd in calls)
    assert any("/usr/bin/notify-send" in cmd for cmd in calls)


@patch("ttp.firewall.apply_emergency_killswitch")
@patch("subprocess.run")
@patch("ttp.watchdog.alerts.resolve_optional", return_value=None)
def test_killswitch_still_isolates_without_notification_tools(mock_resolve, mock_run, mock_apply_ks):
    """
    The network must be isolated even on a host with no `wall` and no
    `notify-send`. Telling the user is desirable; cutting the traffic is the
    point, and it must not be conditional on a nicety being installed.
    """
    wd.trigger_emergency_killswitch("dns", "overlay unmounted")

    mock_apply_ks.assert_called_once()
    assert mock_run.call_count == 0


# 7. run_watchdog_loop
@patch("ttp.state.read_lock", return_value=None)
@patch("time.sleep")
def test_run_watchdog_loop_no_lock(mock_sleep, mock_read):
    """run_watchdog_loop terminates immediately if no active session lock is found."""
    # Should exit loop immediately
    wd.run_watchdog_loop(interval_seconds=1)
    mock_sleep.assert_called_once_with(2)  # Startup stabilization sleep


@patch("ttp.state.read_lock")
@patch("ttp.watchdog.inotify.check_system_integrity")
@patch("ttp.watchdog.fsm.attempt_auto_healing", return_value=True)
@patch("ttp.watchdog.inotify.is_interface_online", return_value=True)
@patch("ttp.watchdog.inotify.has_default_route", return_value=True)
@patch("time.sleep")
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


@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.watchdog.inotify.check_system_integrity")
@patch("ttp.watchdog.fsm.attempt_auto_healing", return_value=True)
@patch("ttp.watchdog.inotify.is_interface_online", return_value=True)
@patch("ttp.watchdog.inotify.has_default_route", return_value=True)
@patch("ttp.watchdog.fsm.trigger_emergency_killswitch")
@patch("time.sleep")
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


@patch("ttp.state.read_lock", return_value={"pid": 123})
@patch("ttp.watchdog.inotify.check_system_integrity")
@patch("ttp.watchdog.fsm.attempt_auto_healing", return_value=False)
@patch("ttp.watchdog.inotify.is_interface_online", return_value=True)
@patch("ttp.watchdog.inotify.has_default_route", return_value=True)
@patch("ttp.watchdog.fsm.trigger_emergency_killswitch")
@patch("time.sleep")
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
@patch("pathlib.Path.exists", return_value=True)
def test_is_interface_online_up(mock_exists):
    """is_interface_online returns True if operstate is up and carrier is 1."""

    def read_text_side_effect(self):
        if "operstate" in str(self):
            return "up\n"
        elif "carrier" in str(self):
            return "1\n"
        return ""

    with patch("pathlib.Path.read_text", read_text_side_effect):
        assert wd.is_interface_online("eth0") is True


@patch("pathlib.Path.exists", return_value=True)
def test_is_interface_online_down(mock_exists):
    """is_interface_online returns False if operstate is down or carrier is 0."""

    # 1. operstate down
    def read_text_down(self):
        if "operstate" in str(self):
            return "down\n"
        return "1\n"

    with patch("pathlib.Path.read_text", read_text_down):
        assert wd.is_interface_online("eth0") is False

    # 2. carrier 0
    def read_text_carrier_zero(self):
        if "operstate" in str(self):
            return "up\n"
        return "0\n"

    with patch("pathlib.Path.read_text", read_text_carrier_zero):
        assert wd.is_interface_online("eth0") is False


@patch("pathlib.Path.exists", return_value=True)
def test_has_default_route_true(mock_exists):
    """has_default_route returns True if /proc/net/route has destination 00000000 and mask 00000000."""
    mock_content = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    with patch("builtins.open", mock_open(read_data=mock_content)):
        assert wd.has_default_route() is True


@patch("pathlib.Path.exists", return_value=True)
def test_has_default_route_false(mock_exists):
    """has_default_route returns False if no default route exists."""
    mock_content = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
    )
    with patch("builtins.open", mock_open(read_data=mock_content)):
        assert wd.has_default_route() is False


@patch("ttp.state.read_lock")
@patch("ttp.watchdog.inotify.is_interface_online")
@patch("ttp.watchdog.inotify.has_default_route")
@patch("time.sleep")
@patch("ttp.watchdog.inotify.check_system_integrity")
def test_run_watchdog_loop_suspends_and_resumes(mock_check, mock_sleep, mock_has_route, mock_online, mock_read):
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


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.tor_control.get_controller")
@patch("ttp.state.read_lock")
@patch("subprocess.run")
@patch("pathlib.Path.exists")
def test_check_system_integrity_systemd_resolved_healthy(
    mock_exists, mock_run, mock_read_lock, mock_get_ctrl, mock_is_mount
):
    """check_system_integrity returns (None, None) when systemd-resolved is active, config exists, and service is active."""
    mock_read_lock.return_value = {"dns_backup": {"systemd_resolved": True}}

    # Path.exists needs to return True for /run/systemd/resolved.conf.d/ttp.conf
    mock_exists.return_value = True

    # subprocess.run needs to handle:
    # 1. nft list table inet ttp
    # 2. systemctl is-active systemd-resolved
    def mock_run_cmd(args, **kwargs):
        if resolve("nft") in args:
            return MagicMock(stdout="table inet ttp {\n  chain filter_out {}\n}\n", returncode=0)
        if "systemd-resolved" in args:
            return MagicMock(stdout="active\n", returncode=0)
        return MagicMock(returncode=0)

    mock_run.side_effect = mock_run_cmd

    mock_ctrl = MagicMock()
    mock_ctrl.__enter__ = lambda s: s
    mock_ctrl.__exit__ = MagicMock(return_value=False)
    mock_get_ctrl.return_value = mock_ctrl

    comp, err = wd.check_system_integrity()
    assert comp is None
    assert err is None


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.state.read_lock")
@patch("pathlib.Path.exists", return_value=False)
def test_check_system_integrity_systemd_resolved_missing_config(mock_exists, mock_read_lock, mock_is_mount):
    """check_system_integrity returns error if systemd-resolved was active on startup but config file is missing."""
    mock_read_lock.return_value = {"dns_backup": {"systemd_resolved": True}}

    comp, err = wd.check_system_integrity()
    assert comp == "dns"
    assert "systemd-resolved drop-in configuration file has been deleted" in err


@patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf")
@patch("ttp.dns._is_mount_point", return_value=True)
@patch("ttp.state.read_lock")
@patch("subprocess.run")
@patch("pathlib.Path.exists")
def test_check_system_integrity_systemd_resolved_inactive_service(mock_exists, mock_run, mock_read_lock, mock_is_mount):
    """check_system_integrity returns error if systemd-resolved service is inactive/stopped."""
    mock_read_lock.return_value = {"dns_backup": {"systemd_resolved": True}}
    mock_exists.return_value = True

    def mock_run_cmd(args, **kwargs):
        if "systemd-resolved" in args:
            return MagicMock(stdout="inactive\n", returncode=0)
        return MagicMock(returncode=0)

    mock_run.side_effect = mock_run_cmd

    comp, err = wd.check_system_integrity()
    assert comp == "dns"
    assert "systemd-resolved systemd service is inactive/stopped" in err


def test_sanitize_alert_text():
    """_sanitize_alert_text removes control characters and ANSI escape sequences."""
    text_with_ansi = "\x1b[31mError!\x1b[0m \n\r\tTest"
    sanitized = wd._sanitize_alert_text(text_with_ansi)
    assert sanitized == "Error! Test"


@patch("ttp.firewall.apply_emergency_killswitch")
@patch("subprocess.run")
@patch("shutil.which", return_value="notify-send")
def test_trigger_emergency_killswitch_sanitization(mock_which, mock_run, mock_killswitch):
    """trigger_emergency_killswitch sanitizes failed_component and err_msg before using them in shell commands."""
    wd.trigger_emergency_killswitch(failed_component="dns\x1b[31m", err_msg="unmounted\r\n")

    # Verify firewall killswitch called
    mock_killswitch.assert_called_once()

    # Verify subprocess.run calls (wall and notify-send)
    assert mock_run.call_count == 2

    # Check wall command arguments: first call
    wall_args = mock_run.call_args_list[0][0][0]
    assert "dns" in wall_args[1]
    assert "\x1b[31m" not in wall_args[1]
    assert "unmounted" in wall_args[1]
    assert "\r\n" not in wall_args[1]

    # Check notify-send command arguments: second call
    notify_args = mock_run.call_args_list[1][0][0]
    assert notify_args[0] == resolve_optional("notify-send")
    assert "dns" in notify_args[2]
    assert "\x1b[31m" not in notify_args[2]


# ---------------------------------------------------------------------------
# Bypass rule tampering
# ---------------------------------------------------------------------------
#
# `check_system_integrity` already checks that the `inet ttp` table exists and
# carries a `filter_out` chain. That is enough to catch a table that was flushed
# or deleted, and nothing finer.
#
# The bypass rules are the finer case, and they are the one part of the ruleset
# a session *depends on being there* rather than being absent. The lock records
# which users and groups were exempted at `start`; this block re-derives their
# UIDs and GIDs and looks for the matching `accept` in the live ruleset. A
# missing one means the ruleset in the kernel is not the ruleset the lock
# describes - someone edited it, or a reload rebuilt it from different inputs -
# and the watchdog treats that as tampering and fails closed rather than
# healing.
#
# Worth stating what this does *not* detect, since the tests below would
# otherwise imply it: an *extra* `accept` that the lock never asked for is
# invisible here. The check is one-directional by construction. That is a
# narrower guarantee than "the ruleset is unmodified", and the difference
# matters because an added bypass is the version an attacker would want.
#
# One more property of the loops, established by mutating them rather than by
# reading them: because each `except KeyError` *returns*, the first bypass entry
# that cannot be resolved ends the check, and every entry after it goes
# unexamined. Moving the `try` outside the loop is therefore indistinguishable
# from leaving it inside - both stop at the first failure. That is defensible
# (an unverifiable bypass is reported, and the watchdog fails closed on it) but
# it is not what the per-entry `try` looks like it is for, and it differs from
# `label_ports_selinux`, where the equivalent handler only warns and the loop
# genuinely continues.


def _healthy_nft(*extra_rules: str) -> str:
    """A minimal `inet ttp` listing that passes the table and chain checks."""
    rules = "\n".join(f"    {r}" for r in extra_rules)
    return f"table inet ttp {{\n  chain filter_out {{\n{rules}\n  }}\n}}\n"


def _integrity_env(nft_stdout: str, lock: dict):
    """Everything `check_system_integrity` touches before the bypass block."""
    from contextlib import ExitStack

    stack = ExitStack()
    stack.enter_context(patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf"))
    stack.enter_context(patch("ttp.dns._is_mount_point", return_value=True))
    stack.enter_context(patch("ttp.state.read_lock", return_value=lock))
    stack.enter_context(patch("subprocess.run", return_value=MagicMock(stdout=nft_stdout, returncode=0)))
    # A healthy controller, so a bypass verdict cannot be confused with a Tor one.
    mock_ctrl = MagicMock()
    mock_ctrl.__enter__ = lambda s: s
    mock_ctrl.__exit__ = MagicMock(return_value=False)
    stack.enter_context(patch("ttp.tor_control.get_controller", return_value=mock_ctrl))
    return stack


def test_integrity_accepts_a_ruleset_whose_bypass_rules_are_all_present():
    """The negative control for everything below.

    Without this, a bug that made the bypass block return a violation
    unconditionally would still satisfy every "detects a missing rule" test
    here, and the watchdog would killswitch a healthy session on every tick.
    """
    nft = _healthy_nft("meta skuid 1000 accept", "meta skgid 1000 accept")
    lock = {"bypass_users": ["alice"], "bypass_groups": ["devs"]}

    with (
        _integrity_env(nft, lock),
        patch("pwd.getpwnam", return_value=MagicMock(pw_uid=1000)),
        patch("grp.getgrnam", return_value=MagicMock(gr_gid=1000)),
    ):
        comp, err = wd.check_system_integrity()

    assert comp is None
    assert err is None


def test_integrity_detects_a_missing_user_bypass_rule():
    """A bypassed user whose `accept` is gone means the ruleset was rebuilt or edited."""
    nft = _healthy_nft("meta skgid 1000 accept")
    lock = {"bypass_users": ["alice"], "bypass_groups": []}

    with _integrity_env(nft, lock), patch("pwd.getpwnam", return_value=MagicMock(pw_uid=1000)):
        comp, err = wd.check_system_integrity()

    assert comp == "firewall"
    assert "bypass rule for user 'alice' (UID 1000) is missing" in err


def test_integrity_detects_a_missing_group_bypass_rule():
    nft = _healthy_nft("meta skuid 1000 accept")
    lock = {"bypass_users": [], "bypass_groups": ["devs"]}

    with _integrity_env(nft, lock), patch("grp.getgrnam", return_value=MagicMock(gr_gid=1000)):
        comp, err = wd.check_system_integrity()

    assert comp == "firewall"
    assert "bypass rule for group 'devs' (GID 1000) is missing" in err


def test_integrity_accepts_a_numeric_bypass_id_without_a_name_lookup():
    """A lock may record a bare UID, which must not be sent through `pwd`.

    `ttp start --bypass-user 1000` stores "1000". Resolving that as a *name*
    would raise KeyError and be reported as tampering - a healthy session
    killswitched because of how the operator spelled the flag.
    """
    nft = _healthy_nft("meta skuid 1000 accept", "meta skgid 1000 accept")
    lock = {"bypass_users": ["1000"], "bypass_groups": ["1000"]}

    with (
        _integrity_env(nft, lock),
        patch("pwd.getpwnam", side_effect=AssertionError("must not be called for a numeric id")),
        patch("grp.getgrnam", side_effect=AssertionError("must not be called for a numeric id")),
    ):
        comp, _ = wd.check_system_integrity()

    assert comp is None


def test_integrity_reports_a_bypass_user_that_no_longer_resolves():
    """A deleted account is a violation, not a crash.

    The UID cannot be re-derived, so the check cannot say whether the rule is
    correct - and an unverifiable bypass is reported rather than assumed good.
    Letting the KeyError escape would instead kill the watchdog thread, which is
    strictly worse: the session would then be unmonitored *and* nothing would
    say so.
    """
    nft = _healthy_nft("meta skuid 1000 accept")
    lock = {"bypass_users": ["ghost"], "bypass_groups": []}

    with _integrity_env(nft, lock), patch("pwd.getpwnam", side_effect=KeyError("no such user")):
        comp, err = wd.check_system_integrity()

    assert comp == "firewall"
    assert "bypass user 'ghost' cannot be resolved on system" in err


def test_integrity_reports_a_bypass_group_that_no_longer_resolves():
    nft = _healthy_nft()
    lock = {"bypass_users": [], "bypass_groups": ["ghosts"]}

    with _integrity_env(nft, lock), patch("grp.getgrnam", side_effect=KeyError("no such group")):
        comp, err = wd.check_system_integrity()

    assert comp == "firewall"
    assert "bypass group 'ghosts' cannot be resolved on system" in err


def test_integrity_checks_every_bypass_entry_not_just_the_first():
    """The loop examines every entry, not only the first.

    The first user resolves and its rule is present, so a check that stopped
    after one entry would return a clean verdict. The violation has to come
    from the *second* user, which is what makes this distinguishable from
    checking `bypass_users[0]` and returning.
    """
    nft = _healthy_nft("meta skuid 1000 accept")
    lock = {"bypass_users": ["alice", "bob"], "bypass_groups": []}

    def getpwnam(name):
        return MagicMock(pw_uid={"alice": 1000, "bob": 1001}[name])

    with _integrity_env(nft, lock), patch("pwd.getpwnam", side_effect=getpwnam):
        comp, err = wd.check_system_integrity()

    assert comp == "firewall"
    assert "'bob' (UID 1001)" in err


def test_integrity_checks_groups_even_when_every_user_rule_is_present():
    """The group loop runs after the user loop, so it needs its own evidence.

    A `return` misplaced at the end of the user loop would make this pass for
    the wrong reason, and no other test in this file would notice.
    """
    nft = _healthy_nft("meta skuid 1000 accept")
    lock = {"bypass_users": ["alice"], "bypass_groups": ["devs"]}

    with (
        _integrity_env(nft, lock),
        patch("pwd.getpwnam", return_value=MagicMock(pw_uid=1000)),
        patch("grp.getgrnam", return_value=MagicMock(gr_gid=1000)),
    ):
        comp, err = wd.check_system_integrity()

    assert comp == "firewall"
    assert "bypass rule for group 'devs'" in err


# ---------------------------------------------------------------------------
# resolv.conf content: the DNS leak the mount check cannot see
# ---------------------------------------------------------------------------
#
# The mount check above answers "is there an overlay". These answer "does the
# overlay still say what it said at `start`" - and they were uncovered, which
# left the module's only actual *leak* detector untested. A `nameserver
# 8.8.8.8` in a live session means every lookup on the host is going straight
# to Google outside Tor, while the mount is present and the ruleset is intact.


def _dns_content_env(resolv_text: str):
    from contextlib import ExitStack

    stack = ExitStack()
    stack.enter_context(patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf"))
    stack.enter_context(patch("ttp.dns._is_mount_point", return_value=True))
    stack.enter_context(patch("ttp.state.read_lock", return_value=None))

    original_read_text = Path.read_text

    def read_text(self, *args, **kwargs):
        if "resolv.conf" in str(self):
            return resolv_text
        return original_read_text(self, *args, **kwargs)

    stack.enter_context(patch("pathlib.Path.read_text", read_text))
    return stack


def test_integrity_detects_a_non_local_nameserver():
    """The DNS leak this module exists to catch, and it had no test.

    The overlay is mounted and the ruleset is intact; only the file's contents
    changed. NetworkManager rewriting resolv.conf on a DHCP renew produces
    exactly this, with no other symptom.
    """
    with _dns_content_env("nameserver 127.0.0.1\nnameserver 8.8.8.8\n"):
        comp, err = wd.check_system_integrity()

    assert comp == "dns"
    assert "points to non-local resolver: 8.8.8.8" in err


def test_integrity_accepts_both_loopback_families():
    """`::1` is as local as `127.0.0.1` and must not read as a leak.

    `apply_dns` writes both when the host supports IPv6, so rejecting `::1`
    would make every dual-stack session fail its first integrity tick.
    """
    with (
        _dns_content_env("nameserver 127.0.0.1\nnameserver ::1\n"),
        patch("subprocess.run", return_value=MagicMock(stdout=_healthy_nft(), returncode=0)),
        patch("ttp.tor_control.get_controller", return_value=None),
    ):
        comp, _ = wd.check_system_integrity()

    # Not a DNS verdict; the tor fallback decides the rest and is not the point.
    assert comp != "dns"


def test_integrity_detects_an_empty_resolv_conf():
    """A mounted overlay with no nameservers resolves nothing at all.

    Distinct from the case above and worth its own message: nothing leaks, but
    the session is broken, and the operator needs to know which of the two it
    is.
    """
    with _dns_content_env("# Generated by TTP\n"):
        comp, err = wd.check_system_integrity()

    assert comp == "dns"
    assert "no nameservers configured" in err


def test_integrity_reports_an_unreadable_resolv_conf_rather_than_assuming_it_is_fine():
    """An unreadable resolv.conf is a violation, not a pass.

    This is the #26 failure mode in miniature: the check cannot observe the
    file, and the only safe reading of that is "cannot verify", which the
    watchdog escalates. Swallowing it would let a session continue on an
    overlay nobody can inspect.
    """
    with (
        patch("ttp.dns.RESOLV_CONF", new="/etc/resolv.conf"),
        patch("ttp.dns._is_mount_point", return_value=True),
        patch("ttp.state.read_lock", return_value=None),
        patch("pathlib.Path.read_text", side_effect=PermissionError("denied")),
    ):
        comp, err = wd.check_system_integrity()

    assert comp == "dns"
    assert "Failed to read/verify resolv.conf" in err


# ---------------------------------------------------------------------------
# Auto-healing: every failure must return False
# ---------------------------------------------------------------------------
#
# The FSM turns `False` into a killswitch and `True` into "carry on". So a
# healing path that returned True after failing would leave the FSM believing a
# component it never repaired is healthy - the session stays up, unmonitored in
# practice, with Tor down. Fail-open by way of a return value.


@patch("ttp.state.read_lock", return_value=None)
def test_auto_healing_refuses_to_heal_without_a_lock(mock_read):
    """No lock means no session to repair, and nothing to repair it from.

    The healing commands are parameterised by the lock. Running them against a
    default that was never the session's configuration would apply a *different*
    ruleset than the one the operator started, which is worse than not healing.
    """
    assert wd.attempt_auto_healing("tor") is False


@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("subprocess.run")
def test_auto_healing_returns_false_when_the_tor_restart_fails(mock_run, mock_read, caplog):
    """`systemctl restart` exiting non-zero must not be reported as healed."""
    import logging

    mock_run.return_value = MagicMock(returncode=1, stderr="Job for ttp-tor.service failed")

    with caplog.at_level(logging.ERROR, logger="ttp"):
        result = wd.attempt_auto_healing("tor")

    assert result is False
    assert "Failed to restart Tor service" in caplog.text
    assert "Job for ttp-tor.service failed" in caplog.text


@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("subprocess.run")
def test_auto_healing_reports_a_nonzero_exit_with_no_stderr(mock_run, mock_read, caplog):
    """systemctl can fail silently; the exit code is then the only evidence.

    The message falls back to the exit code so the log is never just
    "Failed to restart Tor service: " with nothing after it.
    """
    import logging

    mock_run.return_value = MagicMock(returncode=5, stderr="")

    with caplog.at_level(logging.ERROR, logger="ttp"):
        assert wd.attempt_auto_healing("tor") is False

    assert "Exit code 5" in caplog.text


@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("subprocess.run", side_effect=OSError("systemctl not found"))
def test_auto_healing_returns_false_when_the_healing_command_cannot_run(mock_run, mock_read, caplog):
    """An exception from the healing attempt is a failure to heal, not a crash.

    This runs on the watchdog's own thread. An escaping exception would kill the
    monitor loop, leaving the session unwatched with no killswitch and no log
    line tying the two together - so the handler converts it into the `False`
    the FSM knows how to act on.
    """
    import logging

    with caplog.at_level(logging.ERROR, logger="ttp"):
        result = wd.attempt_auto_healing("tor")

    assert result is False
    assert "Auto-healing failed for 'tor'" in caplog.text
    assert "systemctl not found" in caplog.text


# ---------------------------------------------------------------------------
# Link state: telling "the network is down" from "TTP is broken"
# ---------------------------------------------------------------------------
#
# `inotify.py` consults both of these before acting on a violation. If they
# report a healthy link while the cable is out, the watchdog attributes an
# ordinary outage to tampering and killswitches a host whose only problem was
# Wi-Fi. The two failure paths below were the uncovered ones.


def test_is_interface_online_is_false_for_an_interface_that_no_longer_exists():
    """A renamed or removed interface is offline, not an error.

    USB tethering and `systemd`'s predictable-names churn both make
    `/sys/class/net/<iface>` vanish under a live session, and the lock still
    holds the old name.
    """
    with patch("pathlib.Path.exists", return_value=False):
        assert wd.is_interface_online("eth0") is False


@patch("pathlib.Path.exists", return_value=True)
def test_is_interface_online_is_false_when_sysfs_cannot_be_read(mock_exists):
    """Reading sysfs can fail mid-teardown; that must answer False, not raise.

    An interface being torn down exists for the `exists()` call and is gone by
    the `read_text()`. Raising here would propagate into the watchdog loop.
    """
    with patch("pathlib.Path.read_text", side_effect=OSError("no such device")):
        assert wd.is_interface_online("eth0") is False


def test_has_default_route_is_false_without_proc_net_route():
    """A kernel without /proc/net/route answers False rather than raising."""
    with patch("pathlib.Path.exists", return_value=False):
        assert wd.has_default_route() is False


@patch("pathlib.Path.exists", return_value=True)
def test_has_default_route_is_false_when_proc_cannot_be_read(mock_exists):
    """Same contract as above for an unreadable /proc."""
    with patch("builtins.open", side_effect=OSError("permission denied")):
        assert wd.has_default_route() is False
