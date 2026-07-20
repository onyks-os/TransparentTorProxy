# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Port probing utilities for CLI pre-flight checks.

Provides low-level socket-based helpers to determine whether TCP/UDP ports
are in use or actively listening on localhost, and to resolve the UID of the
process owning a given port from ``/proc/net/tcp``.
"""

from __future__ import annotations


def is_port_in_use(port: int) -> bool:
    """Return True if the port is already in use (bound) on localhost (IPv4/IPv6)."""
    import errno
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
    except OSError:
        return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
    except OSError:
        return True

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("::1", port))
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    return True
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("::1", port))
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    return True
    except OSError:
        pass

    return False


def is_port_listening_tcp(port: int) -> bool:
    """Return True if a service is actively listening on localhost TCP port."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("127.0.0.1", port))
            return True
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("::1", port))
            return True
    except OSError:
        pass
    return False


def is_port_listening_udp(port: int) -> bool:
    """Return True if a service has bound the localhost UDP port."""
    import errno
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", port))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return True
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", port))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return True
    return False


def get_uid_from_port(target_port: int) -> int | None:
    """Find the socket owner UID for target_port TCP_LISTEN from /proc/net/tcp."""
    hex_port = f"{target_port:04X}"
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_file, "r") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 8:
                        local_address = parts[1]
                        if local_address.endswith(f":{hex_port}"):
                            if parts[3] == "0A":
                                return int(parts[7])
        except (FileNotFoundError, PermissionError):
            continue
    return None
