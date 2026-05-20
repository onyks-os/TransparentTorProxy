"""Tests for ttp.state - lock file management.

Uses tmp_path for file I/O and mocks os.kill for orphan detection.
Corresponds to TDD Section 8.4.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import state


@pytest.fixture(autouse=True)
def _use_tmp_lock(tmp_path: Path):
    """Redirect the lock file and runtime/persistent dirs to a temp directory."""
    runtime_dir = tmp_path / "run"
    persistent_dir = tmp_path / "lib"
    lock = runtime_dir / "ttp.lock"

    with (
        patch.object(state, "LOCK_DIR", runtime_dir),
        patch.object(state, "LOCK_PATH", lock),
        patch.object(state, "PERSISTENT_DIR", persistent_dir),
        patch.object(state, "STAR_NOTIFIED_PATH", persistent_dir / ".starred_notified"),
        patch("ttp.state.os.chown"),
        patch("ttp.state.os.chmod"),
    ):
        yield lock, runtime_dir


# ensure_runtime_dir


def test_ensure_runtime_dir(_use_tmp_lock):
    """ensure_runtime_dir creates the directory with correct permissions."""
    _, runtime_dir = _use_tmp_lock

    with (
        patch("ttp.state.os.chmod") as mock_chmod,
        patch("ttp.state.os.chown") as mock_chown,
    ):
        state.ensure_runtime_dir()

        assert runtime_dir.exists()
        mock_chmod.assert_called_once_with(runtime_dir, 0o755)
        mock_chown.assert_called_once_with(runtime_dir, 0, 0)


# write_lock creates JSON with correct fields


def test_write_lock(_use_tmp_lock):
    """write_lock creates the lock file with correct JSON."""
    lock_path, _ = _use_tmp_lock
    state.write_lock(
        pid=42,
        dns_backup={"mount_target": "/etc/resolv.conf"},
        transport_port=9060,
        dns_port=9070,
    )

    assert lock_path.exists()
    data = json.loads(lock_path.read_text())
    assert data["pid"] == 42
    assert data["dns_backup"] == {"mount_target": "/etc/resolv.conf"}
    assert data["transport_port"] == 9060
    assert data["dns_port"] == 9070
    assert "timestamp" in data


def test_write_lock_defaults(_use_tmp_lock):
    """write_lock uses correct default ports when none are specified."""
    lock_path, _ = _use_tmp_lock
    state.write_lock(pid=42)

    assert lock_path.exists()
    data = json.loads(lock_path.read_text())
    assert data["transport_port"] == 9041
    assert data["dns_port"] == 9054


# read_lock with file returns dict


def test_read_lock_existing(_use_tmp_lock):
    """read_lock with an existing file -> returns dict with all fields."""
    state.write_lock(pid=99)
    result = state.read_lock()

    assert result is not None
    assert result["pid"] == 99


# read_lock with no file returns None


def test_read_lock_missing():
    """read_lock with no file -> returns None."""
    result = state.read_lock()
    assert result is None


# is_orphan with dead PID returns True


def test_is_orphan_dead_pid(_use_tmp_lock):
    """is_orphan with PID not running -> returns True."""
    state.write_lock(pid=999999)

    with patch("ttp.state.os.kill", side_effect=OSError("No such process")):
        assert state.is_orphan() is True


def test_is_orphan_alive_pid(_use_tmp_lock):
    """is_orphan with PID still running -> returns False."""
    state.write_lock(pid=1)

    with patch("ttp.state.os.kill"):  # No exception -> process alive
        assert state.is_orphan() is False


# delete_lock removes the file


def test_delete_lock(_use_tmp_lock):
    """delete_lock removes the file."""
    lock_path, _ = _use_tmp_lock
    state.write_lock(pid=1)
    assert lock_path.exists()

    state.delete_lock()
    assert not lock_path.exists()


# check_tmpfs_space


def test_check_tmpfs_space_sufficient():
    """check_tmpfs_space passes when /run has enough space."""
    mock_usage = MagicMock(free=100 * 1024 * 1024)  # 100 MB
    with patch("ttp.state.shutil.disk_usage", return_value=mock_usage):
        # Should not raise
        state.check_tmpfs_space()


def test_check_tmpfs_space_insufficient():
    """check_tmpfs_space raises StateError when /run is nearly full."""
    from ttp.exceptions import StateError

    mock_usage = MagicMock(free=1 * 1024 * 1024)  # 1 MB
    with patch("ttp.state.shutil.disk_usage", return_value=mock_usage):
        with pytest.raises(StateError, match="Insufficient space"):
            state.check_tmpfs_space()


def test_check_tmpfs_space_os_error():
    """check_tmpfs_space silently passes when /run cannot be stat'd."""
    with patch("ttp.state.shutil.disk_usage", side_effect=OSError("No such file")):
        # Should not raise - best-effort
        state.check_tmpfs_space()
