"""Tests for ttp.state — lock file management.

Uses tmp_path for file I/O and mocks os.kill for orphan detection.
Corresponds to TDD §8.4.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ttp import state


@pytest.fixture(autouse=True)
def _use_tmp_lock(tmp_path: Path):
    """Redirect the lock file to a temp directory for every test."""
    lock = tmp_path / "ttp.lock"
    with (
        patch.object(state, "LOCK_DIR", tmp_path),
        patch.object(state, "LOCK_PATH", lock),
    ):
        yield lock


# ── 8.4.1 write_lock → creates JSON with correct fields ───────────


def test_write_lock(_use_tmp_lock: Path):
    """write_lock creates the lock file with correct JSON."""
    state.write_lock(
        pid=42,
        dns_backup={"interface": "eth0"},
        dns_mode="resolvectl",
    )

    assert _use_tmp_lock.exists()
    data = json.loads(_use_tmp_lock.read_text())
    assert data["pid"] == 42
    assert data["dns_mode"] == "resolvectl"
    assert data["dns_backup"] == {"interface": "eth0"}
    assert "timestamp" in data


# ── 8.4.2 read_lock with file → returns dict ──────────────────────


def test_read_lock_existing(_use_tmp_lock: Path):
    """read_lock with an existing file → returns dict with all fields."""
    state.write_lock(pid=99, dns_mode="resolv.conf")
    result = state.read_lock()

    assert result is not None
    assert result["pid"] == 99
    assert result["dns_mode"] == "resolv.conf"


# ── 8.4.3 read_lock with no file → returns None ───────────────────


def test_read_lock_missing():
    """read_lock with no file → returns None."""
    result = state.read_lock()
    assert result is None


# ── 8.4.4 is_orphan with dead PID → True ──────────────────────────


def test_is_orphan_dead_pid(_use_tmp_lock: Path):
    """is_orphan with PID not running → returns True."""
    state.write_lock(pid=999999)

    with patch("ttp.state.os.kill", side_effect=OSError("No such process")):
        assert state.is_orphan() is True


def test_is_orphan_alive_pid(_use_tmp_lock: Path):
    """is_orphan with PID still running → returns False."""
    state.write_lock(pid=1)

    with patch("ttp.state.os.kill"):  # No exception → process alive
        assert state.is_orphan() is False


# ── 8.4.5 delete_lock → removes the file ──────────────────────────


def test_delete_lock(_use_tmp_lock: Path):
    """delete_lock removes the file."""
    state.write_lock(pid=1)
    assert _use_tmp_lock.exists()

    state.delete_lock()
    assert not _use_tmp_lock.exists()
