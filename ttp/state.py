"""State management — Persistent lock file for crash-safe operations.

This module acts as the "memory" of TTP. It tracks active sessions
using a JSON-formatted lock file. This is critical for crash-safety:
if the system loses power or the process is killed, the lock file
survives and provides the necessary backup data (firewall rules, DNS
settings) to restore the network on the next run.

CORE CONCEPTS:
- Lock File: Located at /var/lib/ttp/ttp.lock.
- Orphans: A lock exists but the recorded PID is dead.
- Recovery: The process of reading an orphan lock and calling rollback logic.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from ttp.exceptions import StateError

LOCK_DIR = Path("/var/lib/ttp")
LOCK_PATH = LOCK_DIR / "ttp.lock"


def write_lock(
    *,
    pid: int | None = None,
    dns_backup: Any = None,
    dns_mode: str = "",
) -> None:
    """Write the session lock file with the current state.

    Parameters
    ----------
    pid:
        PID to record.  Defaults to the current process.
    dns_backup:
        Original DNS data (resolv.conf contents *or* interface name).
    dns_mode:
        ``"resolvectl"`` or ``"resolv.conf"``.
    """
    try:
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "pid": pid if pid is not None else os.getpid(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dns_backup": dns_backup,
            "dns_mode": dns_mode,
        }
        LOCK_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        raise StateError(f"Failed to write session lock file: {e}")


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
        return True  # corrupt lock → treat as orphan

    try:
        os.kill(pid, 0)
    except OSError:
        return True  # process not running → orphan
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
        ``dns.restore_dns(mode, backup)``
    """
    data = read_lock()
    if data is None:
        return False

    try:
        destroy_firewall()
        restore_dns(data.get("dns_mode", ""), data.get("dns_backup"))
    finally:
        delete_lock()

    return True
