# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for WatchdogFSM - state machine validations."""

from unittest.mock import MagicMock, patch
import pytest
from transitions import MachineError

from ttp.watchdog.fsm import WatchdogFSM


@pytest.fixture
def mock_fsm_dependencies():
    """Mock OS level dependencies (sockets, inotify, ctypes, and system calls)."""
    mock_sock = MagicMock()
    mock_libc = MagicMock()
    mock_libc.inotify_init.return_value = 99
    mock_libc.inotify_add_watch.return_value = 1
    mock_libc.inotify_rm_watch.return_value = 0

    with (
        patch("socket.socket", return_value=mock_sock),
        patch("ctypes.CDLL", return_value=mock_libc),
        patch("ctypes.util.find_library", return_value="libc.so.6"),
        patch("os.set_blocking"),
        patch("os.close"),
        patch("ttp.watchdog.fsm.trigger_emergency_killswitch") as mock_killswitch,
        patch("ttp.watchdog.fsm.attempt_auto_healing") as mock_healing,
    ):
        yield {
            "sock": mock_sock,
            "libc": mock_libc,
            "killswitch": mock_killswitch,
            "healing": mock_healing,
        }


def test_fsm_initial_state(mock_fsm_dependencies):
    """FSM starts in the 'stopped' state."""
    fsm = WatchdogFSM()
    assert fsm.state == "stopped"


def test_fsm_initialize_success(mock_fsm_dependencies):
    """FSM transitions from stopped to healthy and opens socket/inotify descriptors."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    assert fsm.state == "healthy"
    assert fsm.interface == "eth0"
    assert fsm.interval_seconds == 15
    assert fsm.netlink_socket is not None
    assert fsm.inotify_fd == 99


def test_fsm_initialize_failure(mock_fsm_dependencies):
    """FSM fails to initialize if Netlink setup fails and stays in stopped."""
    mock_fsm_dependencies["sock"].bind.side_effect = OSError("mock bind error")

    fsm = WatchdogFSM()
    with pytest.raises(OSError, match="mock bind error"):
        fsm.initialize(interface="eth0", interval_seconds=15)
    assert fsm.state == "stopped"
    # Verify emergency killswitch was triggered
    mock_fsm_dependencies["killswitch"].assert_called_once_with(
        "firewall", "Netlink setup failure: mock bind error"
    )


def test_fsm_disconnect_reconnect(mock_fsm_dependencies):
    """FSM transitions healthy -> suspended -> healthy when network status changes."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")
    assert fsm.state == "healthy"

    fsm.disconnect()
    assert fsm.state == "suspended"

    with patch("time.sleep") as mock_sleep:
        fsm.reconnect()
        mock_sleep.assert_called_once_with(10)

    assert fsm.state == "healthy"


def test_fsm_integrity_healing_success(mock_fsm_dependencies):
    """FSM transitions healthy -> healing -> healthy when auto-healing succeeds."""
    mock_fsm_dependencies["healing"].return_value = True

    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")
    assert fsm.state == "healthy"

    # Integrity fails
    fsm.integrity_fail(failed_comp="tor", err_msg="socket inactive")
    assert fsm.state == "healing"
    mock_fsm_dependencies["healing"].assert_called_once_with("tor")

    # Healing succeeds
    fsm.heal_success()
    assert fsm.state == "healthy"


def test_fsm_integrity_healing_failure(mock_fsm_dependencies):
    """FSM transitions healthy -> healing -> killswitch when auto-healing fails."""
    mock_fsm_dependencies["healing"].return_value = False

    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")
    assert fsm.state == "healthy"

    fsm.integrity_fail(failed_comp="tor", err_msg="socket inactive")
    # auto-healing returns False, which internally triggers heal_fail -> killswitch
    assert fsm.state == "killswitch"
    mock_fsm_dependencies["killswitch"].assert_called_once_with(
        "tor", "socket inactive"
    )


def test_fsm_direct_tamper(mock_fsm_dependencies):
    """FSM transitions healthy -> killswitch immediately on critical component tampering."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")
    assert fsm.state == "healthy"

    fsm.tamper(failed_comp="dns", err_msg="resolv.conf unmounted")
    assert fsm.state == "killswitch"
    mock_fsm_dependencies["killswitch"].assert_called_once_with(
        "dns", "resolv.conf unmounted"
    )


def test_fsm_shutdown_releases_resources(mock_fsm_dependencies):
    """FSM shutdown returns state to stopped and closes sockets/file descriptors."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")
    assert fsm.state == "healthy"

    sock = fsm.netlink_socket
    fsm.shutdown()
    assert fsm.state == "stopped"
    sock.close.assert_called()
    assert fsm.netlink_socket is None
    assert fsm.inotify_fd == -1


def test_fsm_invalid_transitions(mock_fsm_dependencies):
    """FSM prevents illegal transitions (e.g. reconnecting when already healthy)."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")

    with pytest.raises(MachineError):
        fsm.reconnect()

    fsm.disconnect()
    with pytest.raises(MachineError):
        fsm.integrity_fail(failed_comp="tor", err_msg="error")
