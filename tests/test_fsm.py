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
    mock_fsm_dependencies["killswitch"].assert_called_once_with("firewall", "Netlink setup failure: mock bind error")


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
    mock_fsm_dependencies["killswitch"].assert_called_once_with("tor", "socket inactive")


def test_fsm_direct_tamper(mock_fsm_dependencies):
    """FSM transitions healthy -> killswitch immediately on critical component tampering."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0")
    assert fsm.state == "healthy"

    fsm.tamper(failed_comp="dns", err_msg="resolv.conf unmounted")
    assert fsm.state == "killswitch"
    mock_fsm_dependencies["killswitch"].assert_called_once_with("dns", "resolv.conf unmounted")


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


# ---------------------------------------------------------------------------
# readd_watch and flush_event_buffers are the FSM's contact with the kernel.
# Every failure here has to degrade quietly: the watchdog losing a watch must
# not take the session down with it, and a half-drained queue must not wedge
# the loop.
# ---------------------------------------------------------------------------


def test_readd_watch_drops_the_old_watches_first(mock_fsm_dependencies):
    """Stale watch descriptors would leak on every re-add."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    libc = mock_fsm_dependencies["libc"]
    fsm.wd_real, fsm.wd_link = 7, 8
    libc.inotify_rm_watch.reset_mock()

    fsm.readd_watch()

    removed = {c.args[1] for c in libc.inotify_rm_watch.call_args_list}
    assert {7, 8} <= removed


def test_readd_watch_survives_a_watch_that_cannot_be_added(mock_fsm_dependencies):
    """A negative return is logged, not raised: the loop keeps running."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    mock_fsm_dependencies["libc"].inotify_add_watch.return_value = -1

    fsm.readd_watch()

    assert fsm.wd_real == -1
    assert fsm.wd_link == -1


def test_readd_watch_survives_an_exception_from_the_kernel(mock_fsm_dependencies):
    """inotify_add_watch raising must not escape into the monitoring loop."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    mock_fsm_dependencies["libc"].inotify_add_watch.side_effect = OSError("ENOSPC")

    fsm.readd_watch()  # must not raise

    assert fsm.wd_real == -1


def test_initialize_fires_the_killswitch_when_inotify_cannot_start(mock_fsm_dependencies):
    """Losing the DNS watch is a fail-closed event, not a silent degradation."""
    mock_fsm_dependencies["libc"].inotify_init.return_value = -1
    fsm = WatchdogFSM()

    with pytest.raises(OSError):
        fsm.initialize(interface="eth0", interval_seconds=15)

    mock_fsm_dependencies["killswitch"].assert_called_once()
    assert mock_fsm_dependencies["killswitch"].call_args.args[0] == "dns"


def test_flush_event_buffers_drains_both_queues(mock_fsm_dependencies):
    """A queue left full re-fires the same event on the next poll."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    sock = mock_fsm_dependencies["sock"]
    sock.recv.side_effect = [b"event", b""]

    with patch("os.read", side_effect=[b"event", b""]) as read:
        fsm.flush_event_buffers([sock, fsm.inotify_fd])

    assert sock.recv.call_count == 2
    assert read.call_count == 2


def test_flush_event_buffers_stops_on_would_block(mock_fsm_dependencies):
    """Non-blocking descriptors signal "empty" by raising, not by returning b''."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    sock = mock_fsm_dependencies["sock"]
    sock.recv.side_effect = BlockingIOError()

    with patch("os.read", side_effect=BlockingIOError()):
        fsm.flush_event_buffers([sock, fsm.inotify_fd])  # must not raise


def test_flush_event_buffers_swallows_an_unexpected_read_error(mock_fsm_dependencies):
    """An unexpected error must not kill the loop mid-drain."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    sock = mock_fsm_dependencies["sock"]
    sock.recv.side_effect = OSError("ECONNRESET")

    with patch("os.read", side_effect=OSError("EBADF")):
        fsm.flush_event_buffers([sock, fsm.inotify_fd])  # must not raise


def test_flush_event_buffers_ignores_descriptors_that_are_not_ready(mock_fsm_dependencies):
    """Only the descriptors select() reported are drained."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    sock = mock_fsm_dependencies["sock"]
    sock.recv.reset_mock()

    with patch("os.read") as read:
        fsm.flush_event_buffers([])

    sock.recv.assert_not_called()
    read.assert_not_called()


def test_shutdown_releases_every_descriptor(mock_fsm_dependencies):
    """A leaked watch or socket outlives the session it was monitoring."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    fsm.wd_real, fsm.wd_link = 3, 4
    libc = mock_fsm_dependencies["libc"]
    libc.inotify_rm_watch.reset_mock()

    fsm.shutdown()

    removed = {c.args[1] for c in libc.inotify_rm_watch.call_args_list}
    assert {3, 4} <= removed
    assert fsm.netlink_socket is None


def test_shutdown_survives_descriptors_that_refuse_to_close(mock_fsm_dependencies):
    """Teardown is best effort; it must not raise out of the loop's finally."""
    fsm = WatchdogFSM()
    fsm.initialize(interface="eth0", interval_seconds=15)
    fsm.wd_real = 3
    mock_fsm_dependencies["sock"].close.side_effect = OSError("EBADF")
    mock_fsm_dependencies["libc"].inotify_rm_watch.side_effect = OSError("EINVAL")

    fsm.shutdown()  # must not raise

    assert fsm.netlink_socket is None
