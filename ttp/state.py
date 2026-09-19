# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""State management - Volatile lock file for crash-safe operations.

This module acts as the "memory" of TTP. It tracks active sessions
using a JSON-formatted lock file stored in ``/run/ttp/`` (a ``tmpfs``
mount).  Because the lock lives on a volatile filesystem, it vanishes
on reboot, eliminating stale-lock issues after power loss.

The only persistent path used by TTP is ``/var/lib/ttp/`` which is
managed by ``ttp.ux`` (one-time UX engagement features).

CORE CONCEPTS:
- Lock File: Located at /run/ttp/ttp.lock (volatile - tmpfs).
- Orphans: A lock exists but the recorded PID is dead.
- Recovery: The process of reading an orphan lock and calling rollback logic.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ttp.exceptions import StateError

LOCK_DIR = Path("/run/ttp")
LOCK_PATH = LOCK_DIR / "ttp.lock"

# The only part of the runtime directory the unprivileged watchdog owns.
WATCHDOG_DIR = LOCK_DIR / "watchdog"

# Minimum required free space on /run (tmpfs): 5 MB.
MIN_TMPFS_BYTES = 5 * 1024 * 1024

# Persistent directory - kept for backward compatibility (managed by ttp.ux).
PERSISTENT_DIR = Path("/var/lib/ttp")

# ---------------------------------------------------------------------------
# Backward-compatible re-exports from ttp.ux
# ---------------------------------------------------------------------------

from ttp.ux import (  # noqa: E402, F401
    STAR_NOTIFIED_PATH,
    delete_star_sentinel,
    mark_star_message_shown,
    should_show_star_message,
)


def _watchdog_gid() -> int | None:
    """Return the ttp-watchdog GID, or ``None`` when the account is absent."""
    import pwd

    try:
        return pwd.getpwnam("ttp-watchdog").pw_gid
    except KeyError:
        return None


def ensure_runtime_dir() -> None:
    """Create ``/run/ttp``, owned by root, and the watchdog's own subdirectory.

    Must be called early in the CLI startup before any I/O that targets
    the runtime directory (lock file, log file, torrc, etc.).

    The directory itself stays **root-owned**. Root creates several files in
    here by fixed name -- the lock, the log, the generated ``resolv.conf`` and
    the nftables ruleset -- and reopens them by path. Handing the directory to
    ttp-watchdog let that account unlink any of those entries and put a symlink
    in their place (the directory carries no sticky bit), which redirected a
    root-privileged create, chmod, write or bind-mount to a file of its
    choosing. Ownership of the directory is the capability; the individual
    files' 0600 modes never protected against it.

    The watchdog needs two things and gets exactly those: group search/read on
    this directory so it can read the lock, and its own subdirectory for
    anything it writes itself.
    """
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    gid = _watchdog_gid()
    os.chown(LOCK_DIR, 0, gid if gid is not None else 0)
    os.chmod(LOCK_DIR, 0o750 if gid is not None else 0o700)

    if gid is None:
        return

    # Derived from LOCK_DIR rather than the module constant so that callers
    # (and tests) which redirect LOCK_DIR move the whole tree together.
    watchdog_dir = LOCK_DIR / WATCHDOG_DIR.name
    watchdog_dir.mkdir(parents=True, exist_ok=True)
    os.chown(watchdog_dir, _watchdog_uid_or_root(), gid)
    os.chmod(watchdog_dir, 0o700)


def _watchdog_uid_or_root() -> int:
    """Return the ttp-watchdog UID, falling back to root when absent."""
    import pwd

    try:
        return pwd.getpwnam("ttp-watchdog").pw_uid
    except KeyError:
        return 0


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
        _write_lock_file(data)
    except OSError as e:
        raise StateError(f"Failed to write session lock file: {e}")


def _write_lock_file(data: dict[str, Any]) -> None:
    ensure_runtime_dir()
    fd = os.open(LOCK_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        # The watchdog reads this file to learn the session it is monitoring;
        # it never writes it. Group-read for ttp-watchdog, nothing for others.
        gid = _watchdog_gid()
        if gid is not None:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, 0o640)
        else:
            os.fchmod(fd, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    except Exception as e:
        try:
            os.close(fd)
        except OSError:
            pass
        raise e


def update_lock_keys(**kwargs: Any) -> None:
    """Update specific keys in the existing lock file, preserving other keys.

    If no lock file exists, this raises a StateError.
    """
    data = read_lock()
    if data is None:
        raise StateError("No active TTP session found to update.")
    data.update(kwargs)
    try:
        _write_lock_file(data)
    except OSError as e:
        raise StateError(f"Failed to update session lock file: {e}")


def read_lock() -> dict[str, Any] | None:
    """Read and return the lock data, or ``None`` if no lock exists."""
    if not LOCK_PATH.exists():
        return None
    try:
        data = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return None
    except (json.JSONDecodeError, OSError):
        return None


def delete_lock() -> None:
    """Remove the lock file if it exists."""
    LOCK_PATH.unlink(missing_ok=True)


# argv tokens that identify a genuine ttp process. The installed console
# script is /usr/bin/ttp; `python -m ttp.cli` is the module form.
_TTP_ARGV_TOKENS = (b"ttp", b"ttp.cli")


def _is_pid_ttp(pid: int) -> bool:
    """Check if the PID actually belongs to a TTP process (prevents PID recycling).

    /proc/<pid>/cmdline is chosen by the owner of the target process, so it is
    matched as NUL-separated argv tokens and never as a substring: the literal
    "http" contains "ttp", so a substring test treated any curl, wget, browser
    or httpd process as ours. That made a recycled PID look alive, which in
    turn made is_orphan() report a dead session as running and suppressed the
    recovery path.
    """
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = [token for token in f.read().split(b"\x00") if token]
    except (FileNotFoundError, OSError):
        return False

    for index, token in enumerate(argv):
        if token.rsplit(b"/", 1)[-1] in _TTP_ARGV_TOKENS:
            return True
        if token == b"-m" and index + 1 < len(argv) and argv[index + 1] in _TTP_ARGV_TOKENS:
            return True
    return False


def is_orphan() -> bool:
    """Return ``True`` if the lock file exists but its PID is dead or recycled.

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
        if not _is_pid_ttp(pid):
            return True  # PID is alive but not TTP -> recycled (orphan)
    except OSError:
        return True  # process not running -> orphan
    return False


def attempt_recovery(
    destroy_firewall: Callable[[], Any],
    restore_dns: Callable[[Any], Any],
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
