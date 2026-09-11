# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

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
        patch("pwd.getpwnam", side_effect=KeyError("ttp-watchdog")),
    ):
        state.ensure_runtime_dir()

        assert runtime_dir.exists()
        mock_chmod.assert_called_once_with(runtime_dir, 0o700)
        mock_chown.assert_called_once_with(runtime_dir, 0, 0)


def test_ensure_runtime_dir_watchdog_exists(_use_tmp_lock):
    """ensure_runtime_dir uses ttp-watchdog owner if the user exists."""
    _, runtime_dir = _use_tmp_lock
    mock_pw = MagicMock(pw_uid=123, pw_gid=456)

    with (
        patch("ttp.state.os.chmod") as mock_chmod,
        patch("ttp.state.os.chown") as mock_chown,
        patch("pwd.getpwnam", return_value=mock_pw),
    ):
        state.ensure_runtime_dir()

        assert runtime_dir.exists()
        mock_chmod.assert_called_once_with(runtime_dir, 0o700)
        mock_chown.assert_called_once_with(runtime_dir, 123, 456)


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

    with (
        patch("ttp.state.os.kill"),
        patch("ttp.state._is_pid_ttp", return_value=True),
    ):  # No exception -> process alive
        assert state.is_orphan() is False


def test_is_orphan_recycled_pid(_use_tmp_lock):
    """is_orphan with PID still running but recycled -> returns True."""
    state.write_lock(pid=1)

    with (
        patch("ttp.state.os.kill"),
        patch("ttp.state._is_pid_ttp", return_value=False),
    ):  # PID is alive but not TTP
        assert state.is_orphan() is True


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


def test_write_lock_with_bridges(_use_tmp_lock):
    """write_lock saves bridge metadata and read_lock returns it correctly."""
    _lock_path, _ = _use_tmp_lock
    state.write_lock(
        pid=100,
        use_bridges=True,
        bridge_file="/tmp/bridges.txt",
        bridges=["obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0"],
    )

    data = state.read_lock()
    assert data is not None
    assert data["pid"] == 100
    assert data["use_bridges"] is True
    assert data["bridge_file"] == "/tmp/bridges.txt"
    assert data["bridges"] == ["obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0"]


# ---------------------------------------------------------------------------
# update_lock_keys
# ---------------------------------------------------------------------------


def test_update_lock_keys_preserves_untouched_fields(_use_tmp_lock):
    """A partial update must not silently drop the rest of the session state."""
    state.write_lock(pid=4242, transport_port=9041, dns_port=9054, bypass_users=["alice"])
    state.update_lock_keys(watchdog_active=True, watchdog_pid=777)

    data = state.read_lock()
    assert data["watchdog_active"] is True
    assert data["watchdog_pid"] == 777
    # Everything the caller did not mention survives.
    assert data["pid"] == 4242
    assert data["transport_port"] == 9041
    assert data["bypass_users"] == ["alice"]


def test_update_lock_keys_can_add_new_fields(_use_tmp_lock):
    state.write_lock(pid=1)
    state.update_lock_keys(some_future_field="value")
    assert state.read_lock()["some_future_field"] == "value"


def test_update_lock_keys_without_a_session_raises(_use_tmp_lock):
    """Updating a session that does not exist must fail loudly, not create one."""
    with pytest.raises(state.StateError, match="No active TTP session"):
        state.update_lock_keys(watchdog_active=True)
    assert state.read_lock() is None


def test_update_lock_keys_reports_a_write_failure(_use_tmp_lock):
    state.write_lock(pid=1)
    with (
        patch.object(state, "_write_lock_file", side_effect=OSError("read-only fs")),
        pytest.raises(state.StateError, match="Failed to update session lock file"),
    ):
        state.update_lock_keys(watchdog_active=True)


# ---------------------------------------------------------------------------
# read_lock — a corrupt lock must never be mistaken for a valid session
# ---------------------------------------------------------------------------


def test_read_lock_returns_none_for_invalid_json(_use_tmp_lock):
    state.LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    state.LOCK_PATH.write_text("{not json at all", encoding="utf-8")
    assert state.read_lock() is None


def test_read_lock_returns_none_for_a_json_list(_use_tmp_lock):
    """Valid JSON of the wrong shape is still not a session."""
    state.LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    state.LOCK_PATH.write_text('["pid", 1]', encoding="utf-8")
    assert state.read_lock() is None


def test_read_lock_returns_none_when_unreadable(_use_tmp_lock):
    state.write_lock(pid=1)
    with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
        assert state.read_lock() is None


def test_write_lock_reports_an_os_error_as_state_error(_use_tmp_lock):
    with (
        patch.object(state, "_write_lock_file", side_effect=OSError("disk full")),
        pytest.raises(state.StateError, match="Failed to write session lock file"),
    ):
        state.write_lock(pid=1)


def test_lock_file_is_not_world_readable(_use_tmp_lock):
    """
    The lock records the interface, bypassed users and Tor UID of a live privacy
    session. It is created 0600 and this asserts it stays that way.
    """
    state.write_lock(pid=1)
    assert state.LOCK_PATH.stat().st_mode & 0o077 == 0


def test_write_lock_file_closes_the_descriptor_on_failure(_use_tmp_lock):
    """A leaked fd on every failed write would exhaust the process over time."""
    state.LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with (
        patch("json.dump", side_effect=ValueError("not serialisable")),
        pytest.raises(ValueError),
    ):
        state._write_lock_file({"pid": 1})


# ---------------------------------------------------------------------------
# _is_pid_ttp — the guard against PID recycling
# ---------------------------------------------------------------------------


def test_is_pid_ttp_recognises_a_ttp_process(tmp_path: Path):
    cmdline = tmp_path / "cmdline"
    cmdline.write_bytes(b"/usr/bin/python3\x00/usr/local/bin/ttp\x00start\x00")
    real_open = open
    with patch("builtins.open", lambda p, *a, **k: real_open(cmdline, *a, **k)):
        assert state._is_pid_ttp(4242) is True


def test_is_pid_ttp_rejects_an_unrelated_process(tmp_path: Path):
    cmdline = tmp_path / "cmdline"
    cmdline.write_bytes(b"/usr/bin/nginx\x00-g\x00daemon off;\x00")
    real_open = open
    with patch("builtins.open", lambda p, *a, **k: real_open(cmdline, *a, **k)):
        assert state._is_pid_ttp(4242) is False


def test_is_pid_ttp_is_false_for_a_dead_pid():
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert state._is_pid_ttp(999999) is False


def test_is_pid_ttp_is_false_when_proc_is_unreadable():
    with patch("builtins.open", side_effect=PermissionError):
        assert state._is_pid_ttp(1) is False


# ---------------------------------------------------------------------------
# is_orphan
# ---------------------------------------------------------------------------


def test_is_orphan_false_without_a_lock(_use_tmp_lock):
    assert state.is_orphan() is False


def test_is_orphan_true_for_a_lock_without_a_pid(_use_tmp_lock):
    """A corrupt lock is an orphan: leaving it would block every future session."""
    state.LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    state.LOCK_PATH.write_text(json.dumps({"transport_port": 9041}), encoding="utf-8")
    assert state.is_orphan() is True


# ---------------------------------------------------------------------------
# attempt_recovery — the path that runs after a crash, on a machine that may
# still be routing traffic through a half-torn-down firewall
# ---------------------------------------------------------------------------


def test_attempt_recovery_restores_and_clears_the_lock(_use_tmp_lock):
    state.write_lock(pid=1, dns_backup={"mounted": True})
    destroy_firewall = MagicMock()
    restore_dns = MagicMock()

    assert state.attempt_recovery(destroy_firewall, restore_dns) is True

    destroy_firewall.assert_called_once_with()
    restore_dns.assert_called_once_with({"mounted": True})
    assert state.read_lock() is None


def test_attempt_recovery_without_a_lock_does_nothing(_use_tmp_lock):
    destroy_firewall = MagicMock()
    restore_dns = MagicMock()

    assert state.attempt_recovery(destroy_firewall, restore_dns) is False

    destroy_firewall.assert_not_called()
    restore_dns.assert_not_called()


def test_attempt_recovery_deletes_the_lock_even_when_teardown_fails(_use_tmp_lock):
    """
    The lock must go even if the firewall teardown raises. Leaving it behind
    makes every subsequent `ttp start` refuse to run, on a machine whose network
    is already in an unknown state.
    """
    state.write_lock(pid=1, dns_backup=None)
    destroy_firewall = MagicMock(side_effect=RuntimeError("nft is gone"))
    restore_dns = MagicMock()

    with pytest.raises(RuntimeError):
        state.attempt_recovery(destroy_firewall, restore_dns)

    assert state.read_lock() is None
    restore_dns.assert_not_called()


def test_attempt_recovery_deletes_the_lock_when_dns_restore_fails(_use_tmp_lock):
    state.write_lock(pid=1, dns_backup={"mounted": True})
    destroy_firewall = MagicMock()
    restore_dns = MagicMock(side_effect=OSError("resolv.conf is busy"))

    with pytest.raises(OSError):
        state.attempt_recovery(destroy_firewall, restore_dns)

    destroy_firewall.assert_called_once()
    assert state.read_lock() is None


def test_attempt_recovery_passes_a_missing_dns_backup_as_none(_use_tmp_lock):
    state.LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    state.LOCK_PATH.write_text(json.dumps({"pid": 1}), encoding="utf-8")
    restore_dns = MagicMock()

    state.attempt_recovery(MagicMock(), restore_dns)

    restore_dns.assert_called_once_with(None)


# ---------------------------------------------------------------------------
# delete_lock
# ---------------------------------------------------------------------------


def test_delete_lock_is_idempotent(_use_tmp_lock):
    state.delete_lock()
    state.delete_lock()  # must not raise on a lock that is already gone
