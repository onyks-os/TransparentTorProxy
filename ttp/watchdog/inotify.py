# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Inotify and Netlink event monitoring loop for TTP watchdog."""

import logging
import os
import time
import socket
import struct
import ctypes
import ctypes.util
import select
from typing import Any

from ttp import dns, state
from ttp.watchdog.alerts import trigger_emergency_killswitch
from ttp.watchdog.integrity import (
    check_system_integrity,
    attempt_auto_healing,
    is_interface_online,
    has_default_route,
)

logger = logging.getLogger("ttp")


def run_watchdog_loop(interval_seconds: int = 15) -> None:
    """Run the event-driven monitoring loop, reacting to Netlink and Inotify changes."""
    logger.info(
        "Watchdog: Event-driven monitoring loop started. Heartbeat = %d seconds.",
        interval_seconds,
    )

    # 1. Initialize Netlink Socket for nftables events
    NETLINK_NETFILTER = 12
    SOL_NETLINK = 270
    NETLINK_ADD_MEMBERSHIP = 1
    NFNLGRP_NFTABLES = 7

    try:
        netlink_socket = socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER
        )
        netlink_socket.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, NFNLGRP_NFTABLES)
        netlink_socket.bind((0, 0))
        netlink_socket.setblocking(False)
    except Exception as e:
        logger.critical("Watchdog failed to setup Netlink socket: %s", e)
        trigger_emergency_killswitch("firewall", f"Netlink setup failure: {e}")
        return

    # 2. Initialize Inotify for resolv.conf
    try:
        libc_name = ctypes.util.find_library("c")
        libc = ctypes.CDLL(libc_name, use_errno=True)

        libc.inotify_init.argtypes = []
        libc.inotify_init.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.inotify_rm_watch.restype = ctypes.c_int

        IN_CLOSE_WRITE = 0x00000008
        IN_ATTRIB = 0x00000004
        IN_DELETE_SELF = 0x00000400
        IN_MOVE_SELF = 0x00000800
        IN_DONT_FOLLOW = 0x02000000
        WATCH_MASK = IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF

        inotify_fd = libc.inotify_init()
        if inotify_fd < 0:
            raise OSError("inotify_init failed")
        os.set_blocking(inotify_fd, False)

        wd_real = -1
        wd_link = -1
    except Exception as e:
        logger.critical("Watchdog failed to setup Inotify: %s", e)
        try:
            netlink_socket.close()
        except Exception:
            pass
        trigger_emergency_killswitch("dns", f"Inotify setup failure: {e}")
        return

    def readd_watch() -> None:
        nonlocal wd_real, wd_link
        # Remove old watches
        for wd_val in (wd_real, wd_link):
            if wd_val >= 0:
                try:
                    libc.inotify_rm_watch(inotify_fd, wd_val)
                except Exception:
                    pass
        wd_real = -1
        wd_link = -1

        # 1. Watch the real target path of resolv.conf
        try:
            resolv_real_path = os.path.realpath("/etc/resolv.conf")
            wd_real = libc.inotify_add_watch(
                inotify_fd, resolv_real_path.encode("utf-8"), WATCH_MASK
            )
            if wd_real >= 0:
                logger.info(
                    "Watchdog: Inotify watch established on real target %s",
                    resolv_real_path,
                )
            else:
                logger.warning(
                    "Watchdog: Failed to add inotify watch on real target %s",
                    resolv_real_path,
                )
        except Exception as e:
            logger.warning(
                "Watchdog: Exception when adding watch on real target: %s", e
            )

        # 2. Watch the symlink itself (without following) to detect link target swapping
        try:
            wd_link = libc.inotify_add_watch(
                inotify_fd, b"/etc/resolv.conf", WATCH_MASK | IN_DONT_FOLLOW
            )
            if wd_link >= 0:
                logger.info(
                    "Watchdog: Inotify watch established on symlink /etc/resolv.conf"
                )
            else:
                logger.warning(
                    "Watchdog: Failed to add inotify watch on symlink /etc/resolv.conf"
                )
        except Exception as e:
            logger.warning("Watchdog: Exception when adding watch on symlink: %s", e)

    # Initial watch establishment
    readd_watch()

    def _flush_event_buffers(fds: list[Any]) -> None:
        if netlink_socket in fds:
            try:
                while True:
                    data = netlink_socket.recv(65535)
                    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
                        break
            except BlockingIOError:
                pass
            except Exception:
                pass

        if inotify_fd in fds:
            try:
                while True:
                    data = os.read(inotify_fd, 4096)
                    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
                        break
            except BlockingIOError:
                pass
            except Exception:
                pass

    # Debouncing / Loop State
    COOLDOWN_SECONDS = 2.0
    last_heal_time = 0.0
    last_check_time = 0.0

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
            interface = lock.get("interface")
            if not interface:
                interface = dns.detect_active_interface()

            # Check if network link is online and gateway is present
            online = is_interface_online(interface)
            has_route = has_default_route()

            if not online or not has_route:
                logger.warning(
                    "Watchdog: Network link is offline (Interface '%s' online=%s, DefaultRoute=%s). "
                    "Suspending integrity monitoring to prevent false positives.",
                    interface,
                    online,
                    has_route,
                )
                # Flush events before suspending
                _flush_event_buffers([netlink_socket, inotify_fd])

                # Loop here until network link comes back
                while True:
                    time.sleep(5)
                    lock = state.read_lock()
                    if lock is None:
                        break

                    interface = lock.get("interface") or dns.detect_active_interface()
                    if is_interface_online(interface) and has_default_route():
                        logger.info(
                            "Watchdog: Network link restored on '%s'. "
                            "Waiting 10 seconds for Tor circuit stabilization...",
                            interface,
                        )
                        time.sleep(10)
                        readd_watch()
                        _flush_event_buffers([netlink_socket, inotify_fd])
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
                    [netlink_socket, inotify_fd], [], [], 15.0
                )
            except InterruptedError:
                # EINTR: syscall interrupted by a signal, ignore and retry
                continue

            current_time = time.time()

            # Debouncer cooldown check
            if current_time - last_heal_time < COOLDOWN_SECONDS:
                # If we're in cooldown, discard events and continue
                _flush_event_buffers(readable)
                continue

            # Determine if check is needed (event occurred or 15s elapsed since last check)
            should_check = False
            if readable:
                should_check = True
            elif current_time - last_check_time >= float(interval_seconds):
                should_check = True

            if should_check:
                # Handle inotify events & check if watch was lost
                if inotify_fd in readable:
                    try:
                        data = os.read(inotify_fd, 4096)
                        if isinstance(data, (bytes, bytearray)) and len(data) >= 16:
                            offset = 0
                            lost_watch = False
                            while offset < len(data):
                                if len(data) - offset < 16:
                                    break
                                wd_val, mask, cookie, name_len = struct.unpack_from(
                                    "iIII", data, offset
                                )
                                if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                                    lost_watch = True
                                offset += 16 + name_len
                            if lost_watch:
                                readd_watch()
                    except BlockingIOError:
                        pass
                    except Exception as e:
                        logger.warning("Watchdog: Error processing inotify data: %s", e)

                last_check_time = current_time
                failed_comp, err_msg = check_system_integrity()

                if failed_comp is not None:
                    logger.warning(
                        "Watchdog: Integrity check failed! Component: %s. Error: %s",
                        failed_comp,
                        err_msg,
                    )

                    # First strike: attempt auto-healing
                    healed = attempt_auto_healing(failed_comp)

                    if not healed:
                        logger.error(
                            "Watchdog: Auto-healing command failed for '%s'. "
                            "Triggering emergency killswitch immediately.",
                            failed_comp,
                        )
                        trigger_emergency_killswitch(failed_comp, err_msg)
                        break

                    # Healing attempted, record heal timestamp to trigger debouncer cooldown
                    last_heal_time = time.time()

                    # Brief stabilization delay after healing attempt
                    time.sleep(3)

                    # Re-check integrity after successful healing
                    re_failed, re_err = check_system_integrity()
                    if re_failed is not None:
                        trigger_emergency_killswitch(re_failed, re_err)
                        break
                    else:
                        logger.info(
                            "Watchdog: Auto-healing was successful. Session integrity restored."
                        )

    except Exception as e:
        logger.error(
            "Watchdog loop encountered an unexpected error: %s", e, exc_info=True
        )
        trigger_emergency_killswitch("watchdog", f"Unexpected loop exception: {e}")
    finally:
        try:
            netlink_socket.close()
        except Exception:
            pass
        try:
            os.close(inotify_fd)
        except Exception:
            pass
