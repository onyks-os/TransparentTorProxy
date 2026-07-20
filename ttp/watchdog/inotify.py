# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Inotify and Netlink event monitoring loop for TTP watchdog."""

import logging
import os
import time
import struct
import select

from ttp import dns, state
from ttp.watchdog.fsm import WatchdogFSM
from ttp.watchdog.integrity import (
    check_system_integrity,
    is_interface_online,
    has_default_route,
)

logger = logging.getLogger("ttp")


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
                logger.info(
                    "Watchdog: No active TTP lock file found. Exiting gracefully."
                )
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
                    logger.info(
                        "Watchdog: No active TTP lock file found after recovery. Exiting gracefully."
                    )
                    break

            # Run event multiplexer with heartbeat timeout (15s)
            try:
                readable, _, _ = select.select(
                    [fsm.netlink_socket, fsm.inotify_fd], [], [], 15.0
                )
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
            if readable:
                should_check = True
            elif current_time - fsm.last_check_time >= float(interval_seconds):
                should_check = True

            if should_check:
                # Handle inotify events & check if watch was lost
                if fsm.inotify_fd in readable:
                    try:
                        data = os.read(fsm.inotify_fd, 4096)
                        if isinstance(data, (bytes, bytearray)) and len(data) >= 16:
                            offset = 0
                            lost_watch = False
                            while offset < len(data):
                                if len(data) - offset < 16:
                                    break
                                wd_val, mask, cookie, name_len = struct.unpack_from(
                                    "iIII", data, offset
                                )
                                # 0x00000400 (IN_DELETE_SELF) or 0x00000800 (IN_MOVE_SELF)
                                if mask & (0x00000400 | 0x00000800):
                                    lost_watch = True
                                offset += 16 + name_len
                            if lost_watch:
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
        logger.error(
            "Watchdog loop encountered an unexpected error: %s", e, exc_info=True
        )
        if fsm.state != "killswitch":
            fsm.tamper(
                failed_comp="watchdog", err_msg=f"Unexpected loop exception: {e}"
            )
    finally:
        fsm.shutdown()
