# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Inotify and Netlink event monitoring loop for TTP watchdog."""

import logging
import os
import select
import socket
import struct
import time

from ttp import dns, state
from ttp.watchdog.fsm import WatchdogFSM
from ttp.watchdog.integrity import (
    check_system_integrity,
    has_default_route,
    is_interface_online,
)

logger = logging.getLogger("ttp")

# inotify event masks we care about. Either one means the file we were watching
# is gone from under us - which for /etc/resolv.conf means the DNS overlay has
# been unmounted or replaced, i.e. the exact leak this watchdog exists to catch.
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800

#: struct inotify_event { int wd; uint32 mask; uint32 cookie; uint32 len; }
_INOTIFY_HEADER = "iIII"
_INOTIFY_HEADER_SIZE = 16


def inotify_watch_lost(data: bytes | bytearray) -> bool:
    """
    Return True if *data* contains an event meaning the watched file is gone.

    A read from an inotify fd returns a packed sequence of variable-length
    events, so this walks the buffer rather than decoding a single struct. It is
    a pure function so the decision can be tested against real event layouts:
    inline in the monitoring loop, it was only reachable by running the daemon.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < _INOTIFY_HEADER_SIZE:
        return False

    offset = 0
    lost = False
    while offset < len(data):
        if len(data) - offset < _INOTIFY_HEADER_SIZE:
            # A truncated trailing record. Report what we decoded rather than
            # raising: a partial read must not take the watchdog down.
            break
        _wd, mask, _cookie, name_len = struct.unpack_from(_INOTIFY_HEADER, data, offset)
        if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
            lost = True
        offset += _INOTIFY_HEADER_SIZE + name_len
    return lost


def run_watchdog_loop(interval_seconds: int = 15) -> None:
    """Run the event-driven monitoring loop, routing all events and transitions through WatchdogFSM."""
    logger.info(
        "Watchdog: Event-driven monitoring loop started. Heartbeat = %d seconds.",
        interval_seconds,
    )

    # 1. Instantiate the FSM
    fsm = WatchdogFSM()

    # 2. Initialize monitoring state and resources without reading lock at startup
    try:
        fsm.initialize(interval_seconds=interval_seconds)
    except Exception as e:
        logger.critical("Watchdog: Failed to initialize FSM: %s", e)
        return

    # Allow startup stabilization
    time.sleep(2)

    try:
        while True:
            # Check if the TTP session is still supposed to be active
            lock = state.read_lock()
            if lock is None:
                logger.info("Watchdog: No active TTP lock file found. Exiting gracefully.")
                break

            # Extract active interface from lock
            interface = lock.get("interface") or dns.detect_active_interface()
            fsm.interface = interface

            # Check if network link is online and gateway is present
            online = is_interface_online(interface)
            has_route = has_default_route()

            if not online or not has_route:
                if fsm.state == "healthy":
                    fsm.disconnect()

                # Loop here until network link comes back
                while True:
                    time.sleep(5)
                    lock = state.read_lock()
                    if lock is None:
                        break

                    interface = lock.get("interface") or dns.detect_active_interface()
                    if is_interface_online(interface) and has_default_route():
                        fsm.reconnect()
                        break

                # Re-read lock after exiting the offline loop
                lock = state.read_lock()
                if lock is None:
                    logger.info("Watchdog: No active TTP lock file found after recovery. Exiting gracefully.")
                    break

            # Run event multiplexer with heartbeat timeout (15s).
            # The FSM sources are collected defensively: a torn-down FSM leaves
            # netlink_socket at None and inotify_fd at -1, and select() would
            # raise on those instead of falling back to the heartbeat.
            watch_sources: list[socket.socket | int] = []
            if fsm.netlink_socket is not None:
                watch_sources.append(fsm.netlink_socket)
            if fsm.inotify_fd >= 0:
                watch_sources.append(fsm.inotify_fd)

            try:
                readable, _, _ = select.select(watch_sources, [], [], 15.0)
            except InterruptedError:
                # EINTR: syscall interrupted by a signal, ignore and retry
                continue

            current_time = time.time()

            # Debouncer cooldown check
            if current_time - fsm.last_heal_time < fsm.COOLDOWN_SECONDS:
                # If we're in cooldown, discard events and continue
                fsm.flush_event_buffers(readable)
                continue

            # Determine if check is needed (event occurred or 15s elapsed since last check)
            should_check = False
            if readable or current_time - fsm.last_check_time >= float(interval_seconds):
                should_check = True

            if should_check:
                # Handle inotify events & check if watch was lost
                if fsm.inotify_fd in readable:
                    try:
                        if inotify_watch_lost(os.read(fsm.inotify_fd, 4096)):
                            fsm.readd_watch()
                    except BlockingIOError:
                        pass
                    except Exception as e:
                        logger.warning("Watchdog: Error processing inotify data: %s", e)

                fsm.last_check_time = current_time
                failed_comp, err_msg = check_system_integrity()

                if failed_comp is not None:
                    # Let FSM handle the integrity failure
                    fsm.integrity_fail(failed_comp=failed_comp, err_msg=err_msg)

                    if fsm.state == "killswitch":
                        break

                    # If healing initiated, re-verify after stabilization delay
                    if fsm.state == "healing":
                        time.sleep(3)
                        re_failed, re_err = check_system_integrity()
                        if re_failed is not None:
                            fsm.heal_fail(failed_comp=re_failed, err_msg=re_err)
                            break
                        else:
                            fsm.heal_success()

    except Exception as e:
        logger.exception("Watchdog loop encountered an unexpected error: %s", e)
        if fsm.state != "killswitch":
            fsm.tamper(failed_comp="watchdog", err_msg=f"Unexpected loop exception: {e}")
    finally:
        fsm.shutdown()
