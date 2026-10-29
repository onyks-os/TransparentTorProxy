# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Atomic, bounded volatile observations and emergency latch records.

These belong to the watchdog's private directory, never to the root-owned
session lock. Readers distinguish absence/old sessions from corrupt evidence.
The directory descriptor pins all operations; writes replace directory entries
instead of following a pre-existing target or exposing a partially written JSON.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ttp.evidence import boottime
from ttp.exceptions import StateError

MAX_RECORD_BYTES = 65536
_NAMES = {"emergency", "watchdog", "verification", "notifications"}
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def boot_id() -> str:
    return str(uuid.UUID(BOOT_ID_PATH.read_text().strip()))


@dataclass(frozen=True)
class RecordStore:
    directory: Path
    owner_uid: int
    owner_gid: int

    @contextmanager
    def _directory(self) -> Iterator[int]:
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
                raise StateError("Observation directory ownership or permissions are unsafe")
            yield fd
        finally:
            os.close(fd)

    def prepare(self) -> None:
        """Root prepares the private directory before dropping service privileges."""
        try:
            self.directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            # The parent is root-owned; do not follow a substituted directory.
            if os.geteuid() == 0:
                os.fchown(fd, self.owner_uid, self.owner_gid)
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)

    @staticmethod
    def _filename(name: str, session_id: str) -> str:
        if name not in _NAMES:
            raise StateError(f"Unknown observation record: {name}")
        if not isinstance(session_id, str) or not session_id:
            raise StateError("An observation requires a session identity")
        # A late producer from a stopped session cannot replace a new session's
        # evidence. Hashing also prevents path traversal in untrusted identities.
        return f"{name}.{hashlib.sha256(session_id.encode()).hexdigest()}.json"

    def write(self, name: str, session_id: str, data: dict[str, Any]) -> None:
        filename = self._filename(name, session_id)
        try:
            payload = {
                "schema": 1,
                "session_id": session_id,
                "boot_id": boot_id(),
                "written_at": boottime(),
                "data": data,
            }
            content = (json.dumps(payload, allow_nan=False) + "\n").encode()
            if len(content) > MAX_RECORD_BYTES:
                raise StateError("Observation record exceeds its size limit")
            with self._directory() as directory_fd:
                temporary = f".{uuid.uuid4().hex}.tmp"
                fd = os.open(
                    temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd
                )
                try:
                    os.fchmod(fd, 0o600)
                    if os.geteuid() == 0:
                        os.fchown(fd, self.owner_uid, self.owner_gid)
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(content)
                        stream.flush()
                    os.rename(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                finally:
                    os.close(fd)
                    try:
                        os.unlink(temporary, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
        except (OSError, ValueError, TypeError) as exc:
            raise StateError(f"Cannot publish {name} observation: {exc}") from exc

    def read(self, name: str, session_id: str) -> dict[str, Any] | None:
        filename = self._filename(name, session_id)
        try:
            current_boot = boot_id()
        except (OSError, ValueError) as exc:
            raise StateError("Cannot determine the current boot identity") from exc
        try:
            with self._directory() as directory_fd:
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                try:
                    info = os.fstat(fd)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_uid != self.owner_uid
                        or info.st_mode & 0o077
                    ):
                        raise StateError("Observation record ownership, type or permissions are unsafe")
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        content = stream.read(MAX_RECORD_BYTES + 1)
                finally:
                    os.close(fd)
            if len(content) > MAX_RECORD_BYTES:
                raise StateError("Observation record exceeds its size limit")
            payload = json.loads(content)
            if not isinstance(payload, dict) or type(payload.get("schema")) is not int or payload["schema"] != 1:
                raise StateError("Unrecognized observation schema")
            if (
                not isinstance(payload.get("data"), dict)
                or not isinstance(payload.get("session_id"), str)
                or not payload["session_id"]
                or not isinstance(payload.get("boot_id"), str)
            ):
                raise StateError("Invalid observation payload")
            uuid.UUID(payload["boot_id"])
            written_at = payload.get("written_at")
            if (
                not isinstance(written_at, (int, float))
                or isinstance(written_at, bool)
                or not math.isfinite(written_at)
                or written_at < 0
            ):
                raise StateError("Invalid observation timestamp")
            if payload["session_id"] != session_id or payload["boot_id"] != current_boot:
                return None
            return payload
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise StateError(f"Cannot inspect {name} observation: {exc}") from exc

    @contextmanager
    def transition(self, *, timeout: float = 10) -> Iterator[None]:
        """Serialize emergency actions with explicit stop intent, with a deadline.

        The lock is in the private directory shared by root and the watchdog.
        Callers must re-read the root session intent after taking this lock.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise StateError("Transition timeout must be finite and positive")
        with self._directory() as directory_fd:
            fd = os.open(
                "transition.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory_fd
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise StateError("Invalid transition lock")
                os.fchmod(fd, 0o600)
                if os.geteuid() == 0:
                    os.fchown(fd, self.owner_uid, self.owner_gid)
                deadline = boottime() + timeout
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        remaining = deadline - boottime()
                        if remaining <= 0:
                            raise StateError("Timed out waiting for a session transition") from None
                        time.sleep(min(0.05, remaining))
                yield
            finally:
                os.close(fd)


def session_store() -> RecordStore:
    from ttp import state

    return RecordStore(state.LOCK_DIR / "watchdog", state._watchdog_uid_or_root(), state._watchdog_gid() or 0)
