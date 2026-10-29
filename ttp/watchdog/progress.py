# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Main-loop progress signalling and bounded synchronous local observations."""

from __future__ import annotations

import os
import signal
import socket
from collections.abc import Callable
from typing import TypeVar

from ttp.exceptions import StateError

T = TypeVar("T")


class CheckDeadline(BaseException):
    """Cannot be swallowed by a check's broad ``except Exception`` fallback."""


def bounded_check(operation: Callable[[], T], timeout: float) -> T:
    """Limit an entire read-only local check, including nested fallback calls.

    Linux watchdog work runs on its main thread. No heartbeat helper thread can
    mask a blocked check. SIGALRM interrupts blocking socket/library operations;
    systemd's independent timeout is the backstop for uninterruptible work.
    """

    def expire(signum, frame):
        raise CheckDeadline()

    previous = signal.signal(signal.SIGALRM, expire)
    timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return operation()
    finally:
        signal.setitimer(signal.ITIMER_REAL, *timer)
        signal.signal(signal.SIGALRM, previous)


def notify_progress(*, ready: bool = False) -> None:
    address = os.environ.get("NOTIFY_SOCKET", "")
    if not address or address[0] not in ("/", "@"):
        raise StateError("A systemd notification socket is required for supervision")
    if address[0] == "@":
        address = "\0" + address[1:]
    message = "WATCHDOG=1\nSTATUS=Session supervision progressing"
    if ready:
        message = "READY=1\n" + message
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.connect(address)
        sock.sendall(message.encode())
