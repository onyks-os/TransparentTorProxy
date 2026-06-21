# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""State management - Volatile lock file for crash-safe operations.

This module acts as the "memory" of TTP. It tracks active sessions
using a JSON-formatted lock file stored in ``/run/ttp/`` (a ``tmpfs``
mount).  Because the lock lives on a volatile filesystem, it vanishes
on reboot, eliminating stale-lock issues after power loss.

The only persistent path is ``/var/lib/ttp/`` which holds the star
notification sentinel and the Tor cache directory.

CORE CONCEPTS:
- Lock File: Located at /run/ttp/ttp.lock (volatile - tmpfs).
- Orphans: A lock exists but the recorded PID is dead.
- Recovery: The process of reading an orphan lock and calling rollback logic.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from ttp.exceptions import StateError

LOCK_DIR = Path("/run/ttp")
LOCK_PATH = LOCK_DIR / "ttp.lock"

# Minimum required free space on /run (tmpfs): 5 MB.
MIN_TMPFS_BYTES = 5 * 1024 * 1024

# Persistent directory - survives reboots. Only non-relevant forensic data here.
PERSISTENT_DIR = Path("/var/lib/ttp")
STAR_NOTIFIED_PATH = PERSISTENT_DIR / ".starred_notified"


def ensure_runtime_dir() -> None:
    """Create ``/run/ttp`` with mode 0755 owned by root.

    Must be called early in the CLI startup before any I/O that targets
    the runtime directory (lock file, log file, torrc, etc.).

    The directory is world-readable so the Tor user can traverse it
    to reach ``/run/tor/ttp/``.
    """
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOCK_DIR, 0o755)
    os.chown(LOCK_DIR, 0, 0)


def check_tmpfs_space(min_bytes: int = MIN_TMPFS_BYTES) -> None:
    """Abort if ``/run`` (tmpfs) has insufficient free space.

    Must be called **before** any I/O to ``/run`` so that TTP
    fails fast instead of crashing mid-setup with ``ENOSPC``.

    Raises
    ------
    StateError
        If free space on ``/run`` is below *min_bytes*.
    """
    try:
        usage = shutil.disk_usage("/run")
        if usage.free < min_bytes:
            free_mb = usage.free / (1024 * 1024)
            min_mb = min_bytes / (1024 * 1024)
            raise StateError(
                f"Insufficient space on /run (tmpfs): {free_mb:.1f}MB free, "
                f"minimum {min_mb:.1f}MB required. "
                f"Free space before starting TTP."
            )
    except OSError as e:
        if isinstance(e, StateError):
            raise
        # Cannot stat /run - non-fatal, proceed with best effort
        pass


def write_lock(
    *,
    pid: int | None = None,
    dns_backup: Any = None,
    transport_port: int = 9041,
    dns_port: int = 9054,
    allow_root: bool = False,
    lan_bypass: bool = True,
    watchdog_active: bool = False,
    watchdog_pid: int | None = None,
    interface: str | None = None,
    bypass_users: list[str] | None = None,
    bypass_groups: list[str] | None = None,
    use_bridges: bool = False,
    bridge_file: str | None = None,
    bridges: list[str] | None = None,
    external_daemon: bool = False,
    no_ipv6: bool = False,
    tor_uid: int | None = None,
) -> None:
    """Write the session lock file with the current state.

    Parameters
    ----------
    pid:
        PID to record.  Defaults to the current process.
    dns_backup:
        Original DNS data (resolv.conf mount target dictionary).
    transport_port:
        The customized or default TransPort port.
    dns_port:
        The customized or default DNSPort port.
    allow_root:
        True to allow root processes to bypass Tor.
    lan_bypass:
        True to exempt LAN subnet traffic from Tor routing.
    watchdog_active:
        True if the watchdog background daemon is active.
    watchdog_pid:
        PID of the active watchdog daemon if running.
    interface:
        The name of the primary active interface being proxyed.
    bypass_users:
        List of system users bypassed from Tor routing.
    bypass_groups:
        List of system groups bypassed from Tor routing.
    use_bridges:
        True if Tor bridges support is enabled.
    bridge_file:
        Path to the bridge file, if provided.
    bridges:
        List of configured bridge lines.
    tor_uid:
        The resolved UID of the Tor daemon process.
    """
    try:
        ensure_runtime_dir()
        data = {
            "pid": pid if pid is not None else os.getpid(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dns_backup": dns_backup,
            "transport_port": transport_port,
            "dns_port": dns_port,
            "allow_root": allow_root,
            "lan_bypass": lan_bypass,
            "watchdog_active": watchdog_active,
            "watchdog_pid": watchdog_pid,
            "interface": interface,
            "bypass_users": bypass_users if bypass_users is not None else [],
            "bypass_groups": bypass_groups if bypass_groups is not None else [],
            "use_bridges": use_bridges,
            "bridge_file": bridge_file,
            "bridges": bridges if bridges is not None else [],
            "external_daemon": external_daemon,
            "no_ipv6": no_ipv6,
            "tor_uid": tor_uid,
        }
        LOCK_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.chmod(LOCK_PATH, 0o644)
    except OSError as e:
        raise StateError(f"Failed to write session lock file: {e}")


def update_lock_keys(**kwargs: Any) -> None:
    """Update specific keys in the existing lock file, preserving other keys.

    If no lock file exists, this raises a StateError.
    """
    data = read_lock()
    if data is None:
        raise StateError("No active TTP session found to update.")
    data.update(kwargs)
    try:
        ensure_runtime_dir()
        LOCK_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise StateError(f"Failed to update session lock file: {e}")


def read_lock() -> dict[str, Any] | None:
    """Read and return the lock data, or ``None`` if no lock exists."""
    if not LOCK_PATH.exists():
        return None
    try:
        return json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def delete_lock() -> None:
    """Remove the lock file if it exists."""
    LOCK_PATH.unlink(missing_ok=True)


def is_orphan() -> bool:
    """Return ``True`` if the lock file exists but its PID is dead.

    Uses ``os.kill(pid, 0)`` which sends no signal but raises
    ``OSError`` when the target process does not exist.
    """
    data = read_lock()
    if data is None:
        return False

    pid = data.get("pid")
    if pid is None:
        return True  # corrupt lock -> treat as orphan

    try:
        os.kill(pid, 0)
    except OSError:
        return True  # process not running -> orphan
    return False


def attempt_recovery(
    destroy_firewall: callable,
    restore_dns: callable,
) -> bool:
    """Attempt automatic recovery from an orphaned lock.

    Reads the lock, invokes the firewall and DNS restoration
    callbacks, then deletes the lock.  Returns ``True`` on success.

    Parameters
    ----------
    destroy_firewall:
        ``firewall.destroy_rules()``
    restore_dns:
        ``dns.restore_dns(backup)``
    """
    data = read_lock()
    if data is None:
        return False

    try:
        destroy_firewall()
        restore_dns(data.get("dns_backup"))
    finally:
        delete_lock()

    return True


def should_show_star_message() -> bool:
    """Return ``True`` if the one-time star message should be shown."""
    return not STAR_NOTIFIED_PATH.exists()


def mark_star_message_shown() -> None:
    """Mark the star message as shown by creating a sentinel file."""
    try:
        PERSISTENT_DIR.mkdir(parents=True, exist_ok=True)
        STAR_NOTIFIED_PATH.touch()
    except OSError:
        # Best effort - if we can't write, we might show it again next time.
        pass


def delete_star_sentinel() -> None:
    """Remove the star notification sentinel file."""
    STAR_NOTIFIED_PATH.unlink(missing_ok=True)
