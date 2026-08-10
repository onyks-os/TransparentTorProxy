# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Finite State Machine (FSM) implementation for TTP watchdog."""

import ctypes
import ctypes.util
import logging
import os
import socket
import time
from typing import Any

from transitions import Machine

from ttp.watchdog.alerts import trigger_emergency_killswitch
from ttp.watchdog.integrity import (
    attempt_auto_healing,
)

logger = logging.getLogger("ttp")

# Netlink constants
NETLINK_NETFILTER = 12
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NFNLGRP_NFTABLES = 7

# Inotify constants
IN_CLOSE_WRITE = 0x00000008
IN_ATTRIB = 0x00000004
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_DONT_FOLLOW = 0x02000000
WATCH_MASK = IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF


class WatchdogFSM:
    """Watchdog Finite State Machine managing transitions, sockets, and recovery logic."""

    states = ["stopped", "healthy", "suspended", "healing", "killswitch"]

    def __init__(self) -> None:
        self.netlink_socket: socket.socket | None = None
        self.inotify_fd: int = -1
        self.wd_real: int = -1
        self.wd_link: int = -1
        self.interface: str | None = None
        self.interval_seconds: int = 15
        self.last_heal_time: float = 0.0
        self.last_check_time: float = 0.0
        self.COOLDOWN_SECONDS: float = 2.0
        self._libc: Any = None

        # Initialize Transitions Machine
        self.machine = Machine(
            model=self,
            states=WatchdogFSM.states,
            initial="stopped",
            send_event=True,
        )

        # Transition Rules
        self.machine.add_transition(
            trigger="initialize",
            source="stopped",
            dest="healthy",
            before="_on_initialize",
        )
        self.machine.add_transition(
            trigger="disconnect",
            source="healthy",
            dest="suspended",
            before="_on_disconnect",
        )
        self.machine.add_transition(
            trigger="reconnect",
            source="suspended",
            dest="healthy",
            before="_on_reconnect",
        )
        self.machine.add_transition(
            trigger="integrity_fail",
            source="healthy",
            dest="healing",
            after="_on_integrity_fail",
        )
        self.machine.add_transition(
            trigger="heal_success",
            source="healing",
            dest="healthy",
            before="_on_heal_success",
        )
        self.machine.add_transition(
            trigger="heal_fail",
            source="healing",
            dest="killswitch",
            before="_on_heal_fail",
        )
        self.machine.add_transition(
            trigger="tamper",
            source="healthy",
            dest="killswitch",
            before="_on_tamper",
        )
        self.machine.add_transition(
            trigger="shutdown",
            source="*",
            dest="stopped",
            before="_on_shutdown",
        )

    def _load_libc(self) -> None:
        """Helper to dynamically load libc for inotify functions."""
        if self._libc is None:
            libc_name = ctypes.util.find_library("c")
            self._libc = ctypes.CDLL(libc_name, use_errno=True)

            self._libc.inotify_init.argtypes = []
            self._libc.inotify_init.restype = ctypes.c_int
            self._libc.inotify_add_watch.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint32,
            ]
            self._libc.inotify_add_watch.restype = ctypes.c_int
            self._libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            self._libc.inotify_rm_watch.restype = ctypes.c_int

    def readd_watch(self) -> None:
        """Re-register inotify watches on the target file and symlink."""
        self._load_libc()
        # Remove old watches
        for wd_val in (self.wd_real, self.wd_link):
            if wd_val >= 0:
                try:
                    self._libc.inotify_rm_watch(self.inotify_fd, wd_val)
                except Exception:
                    pass
        self.wd_real = -1
        self.wd_link = -1

        # 1. Watch the real target path of resolv.conf
        try:
            resolv_real_path = os.path.realpath("/etc/resolv.conf")
            self.wd_real = self._libc.inotify_add_watch(self.inotify_fd, resolv_real_path.encode("utf-8"), WATCH_MASK)
            if self.wd_real >= 0:
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
            logger.warning("Watchdog: Exception when adding watch on real target: %s", e)

        # 2. Watch the symlink itself (without following) to detect link target swapping
        try:
            self.wd_link = self._libc.inotify_add_watch(
                self.inotify_fd, b"/etc/resolv.conf", WATCH_MASK | IN_DONT_FOLLOW
            )
            if self.wd_link >= 0:
                logger.info("Watchdog: Inotify watch established on symlink /etc/resolv.conf")
            else:
                logger.warning("Watchdog: Failed to add inotify watch on symlink /etc/resolv.conf")
        except Exception as e:
            logger.warning("Watchdog: Exception when adding watch on symlink: %s", e)

    def flush_event_buffers(self, fds: list[Any]) -> None:
        """Discard any accumulated events in netlink or inotify queues."""
        if self.netlink_socket in fds:
            try:
                while True:
                    data = self.netlink_socket.recv(65535)
                    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
                        break
            except BlockingIOError:
                pass
            except Exception:
                pass

        if self.inotify_fd in fds and self.inotify_fd >= 0:
            try:
                while True:
                    data = os.read(self.inotify_fd, 4096)
                    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
                        break
            except BlockingIOError:
                pass
            except Exception:
                pass

    # Transition Callbacks
    def _on_initialize(self, event: Any) -> None:
        self.interface = event.kwargs.get("interface")
        self.interval_seconds = event.kwargs.get("interval_seconds", 15)

        logger.info(
            "Watchdog FSM: Initializing monitoring. Interface: %s. Heartbeat: %d",
            self.interface,
            self.interval_seconds,
        )

        # Setup Netlink Socket
        try:
            self.netlink_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
            self.netlink_socket.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, NFNLGRP_NFTABLES)
            self.netlink_socket.bind((0, 0))
            self.netlink_socket.setblocking(False)
        except Exception as e:
            logger.critical("Watchdog FSM failed to setup Netlink socket: %s", e)
            trigger_emergency_killswitch("firewall", f"Netlink setup failure: {e}")
            raise e

        # Setup Inotify
        try:
            self._load_libc()
            self.inotify_fd = self._libc.inotify_init()
            if self.inotify_fd < 0:
                raise OSError("inotify_init failed")
            os.set_blocking(self.inotify_fd, False)
            self.readd_watch()
        except Exception as e:
            logger.critical("Watchdog FSM failed to setup Inotify: %s", e)
            if self.netlink_socket:
                try:
                    self.netlink_socket.close()
                except Exception:
                    pass
            trigger_emergency_killswitch("dns", f"Inotify setup failure: {e}")
            raise e

    def _on_disconnect(self, event: Any) -> None:
        logger.warning(
            "Watchdog FSM: Network link went offline. Suspending monitoring on %s.",
            self.interface,
        )
        self.flush_event_buffers([self.netlink_socket, self.inotify_fd])

    def _on_reconnect(self, event: Any) -> None:
        logger.info(
            "Watchdog FSM: Network link restored on '%s'. Waiting 10 seconds for Tor circuit stabilization...",
            self.interface,
        )
        time.sleep(10)
        self.readd_watch()
        self.flush_event_buffers([self.netlink_socket, self.inotify_fd])

    def _on_integrity_fail(self, event: Any) -> None:
        failed_comp = event.kwargs.get("failed_comp")
        err_msg = event.kwargs.get("err_msg")

        logger.warning(
            "Watchdog FSM: Integrity check failed! Component: %s. Error: %s",
            failed_comp,
            err_msg,
        )
        logger.info(
            "Watchdog FSM: Initiating auto-healing for failed component '%s'...",
            failed_comp,
        )

        healed = attempt_auto_healing(failed_comp)
        self.last_heal_time = time.time()

        if not healed:
            logger.error(
                "Watchdog FSM: Auto-healing command failed for '%s'. Triggering emergency killswitch.",
                failed_comp,
            )
            # Fail immediately by triggering state change to killswitch
            self.heal_fail(failed_comp=failed_comp, err_msg=err_msg)

    def _on_heal_success(self, event: Any) -> None:
        logger.info("Watchdog FSM: Auto-healing was successful. Session integrity restored.")

    def _on_heal_fail(self, event: Any) -> None:
        failed_comp = event.kwargs.get("failed_comp")
        err_msg = event.kwargs.get("err_msg")
        trigger_emergency_killswitch(failed_comp, err_msg)

    def _on_tamper(self, event: Any) -> None:
        failed_comp = event.kwargs.get("failed_comp")
        err_msg = event.kwargs.get("err_msg")
        logger.critical(
            "Watchdog FSM: Tampering detected on critical component '%s'! Activating emergency killswitch.",
            failed_comp,
        )
        trigger_emergency_killswitch(failed_comp, err_msg)

    def _on_shutdown(self, event: Any) -> None:
        logger.info("Watchdog FSM: Stopping watchdog. Cleaning up resources.")
        if self.netlink_socket:
            try:
                self.netlink_socket.close()
            except Exception:
                pass
            self.netlink_socket = None

        if self.inotify_fd >= 0:
            # Try to remove watches
            for wd_val in (self.wd_real, self.wd_link):
                if wd_val >= 0:
                    try:
                        self._libc.inotify_rm_watch(self.inotify_fd, wd_val)
                    except Exception:
                        pass
            try:
                os.close(self.inotify_fd)
            except Exception:
                pass
            self.inotify_fd = -1
            self.wd_real = -1
            self.wd_link = -1
