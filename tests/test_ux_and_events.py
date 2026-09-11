# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for the smaller load-bearing helpers: UX sentinel, cgroup probing, and
inotify event decoding.

``inotify_watch_lost`` is the one that matters. It is how the watchdog notices
that ``/etc/resolv.conf`` has been unmounted or replaced under the DNS overlay -
the moment a leak becomes possible. It used to be a block inline in the daemon's
``while True`` loop, so it was only reachable by running the daemon, which is why
none of it was tested.
"""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import ux
from ttp.firewall.builder import _has_cgroup_bypass_support
from ttp.paths import resolve
from ttp.watchdog.inotify import (
    IN_DELETE_SELF,
    IN_MOVE_SELF,
    inotify_watch_lost,
)

# Masks that are not "the file went away".
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_IGNORED = 0x00008000


def event(mask: int, name: bytes = b"") -> bytes:
    """Pack one struct inotify_event, padded like the kernel does."""
    padded = name + b"\x00" * ((4 - len(name) % 4) % 4) if name else b""
    return struct.pack("iIII", 1, mask, 0, len(padded)) + padded


# ---------------------------------------------------------------------------
# inotify_watch_lost
# ---------------------------------------------------------------------------


def test_delete_self_means_the_watch_is_lost() -> None:
    assert inotify_watch_lost(event(IN_DELETE_SELF)) is True


def test_move_self_means_the_watch_is_lost() -> None:
    """`mv resolv.conf resolv.conf.bak` is a silent overlay removal."""
    assert inotify_watch_lost(event(IN_MOVE_SELF)) is True


def test_a_plain_modification_is_not_a_lost_watch() -> None:
    """NetworkManager rewrites resolv.conf constantly; that is not a leak."""
    assert inotify_watch_lost(event(IN_MODIFY)) is False


def test_attribute_changes_are_not_a_lost_watch() -> None:
    assert inotify_watch_lost(event(IN_ATTRIB)) is False


def test_a_lost_watch_anywhere_in_the_batch_is_detected() -> None:
    """Several events arrive in one read; the important one may not be first."""
    data = event(IN_MODIFY) + event(IN_ATTRIB) + event(IN_DELETE_SELF)
    assert inotify_watch_lost(data) is True


def test_a_lost_watch_first_in_the_batch_is_detected() -> None:
    data = event(IN_DELETE_SELF) + event(IN_MODIFY)
    assert inotify_watch_lost(data) is True


def test_named_events_are_walked_correctly() -> None:
    """
    The name field is variable-length. Getting the stride wrong desynchronises
    the walk and every later event is decoded from the middle of a record.
    """
    data = event(IN_MODIFY, b"resolv.conf") + event(IN_DELETE_SELF, b"resolv.conf")
    assert inotify_watch_lost(data) is True


def test_combined_masks_are_detected() -> None:
    assert inotify_watch_lost(event(IN_DELETE_SELF | IN_IGNORED)) is True


@pytest.mark.parametrize("data", [b"", b"\x00" * 15, bytearray(b"short")])
def test_short_reads_are_not_a_lost_watch(data: bytes | bytearray) -> None:
    """A partial read must be ignored, not decoded as an event."""
    assert inotify_watch_lost(data) is False


def test_a_truncated_trailing_record_does_not_raise() -> None:
    """
    struct.unpack_from would raise on a partial record and take the watchdog
    down. What it decoded before the truncation still counts.
    """
    data = event(IN_DELETE_SELF) + b"\x00" * 7
    assert inotify_watch_lost(data) is True


def test_a_truncated_record_alone_is_not_a_lost_watch() -> None:
    data = event(IN_MODIFY) + b"\x00" * 7
    assert inotify_watch_lost(data) is False


def test_non_bytes_input_is_rejected() -> None:
    assert inotify_watch_lost(None) is False  # type: ignore[arg-type]


def test_bytearray_is_accepted() -> None:
    assert inotify_watch_lost(bytearray(event(IN_MOVE_SELF))) is True


# ---------------------------------------------------------------------------
# ux — the one-time star message sentinel
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_ux(tmp_path: Path):
    sentinel = tmp_path / "lib" / ".starred_notified"
    with (
        patch.object(ux, "PERSISTENT_DIR", tmp_path / "lib"),
        patch.object(ux, "STAR_NOTIFIED_PATH", sentinel),
    ):
        yield sentinel


def test_message_is_shown_before_it_has_been_marked(tmp_ux: Path) -> None:
    assert ux.should_show_star_message() is True


def test_message_is_not_shown_again_after_marking(tmp_ux: Path) -> None:
    ux.mark_star_message_shown()
    assert tmp_ux.exists()
    assert ux.should_show_star_message() is False


def test_marking_creates_the_persistent_directory(tmp_ux: Path) -> None:
    assert not tmp_ux.parent.exists()
    ux.mark_star_message_shown()
    assert tmp_ux.parent.is_dir()


def test_marking_twice_is_harmless(tmp_ux: Path) -> None:
    ux.mark_star_message_shown()
    ux.mark_star_message_shown()
    assert ux.should_show_star_message() is False


def test_an_unwritable_persistent_dir_does_not_crash_the_cli(tmp_ux: Path) -> None:
    """
    Best effort by design: failing to record a cosmetic message must never take
    down a command that is about to reroute the user's traffic.
    """
    with patch.object(Path, "mkdir", side_effect=PermissionError("read-only")):
        ux.mark_star_message_shown()
    assert ux.should_show_star_message() is True


def test_a_touch_failure_does_not_crash_the_cli(tmp_ux: Path) -> None:
    with patch.object(Path, "touch", side_effect=OSError("disk full")):
        ux.mark_star_message_shown()


def test_deleting_the_sentinel_restores_the_message(tmp_ux: Path) -> None:
    ux.mark_star_message_shown()
    ux.delete_star_sentinel()
    assert ux.should_show_star_message() is True


def test_deleting_a_missing_sentinel_is_harmless(tmp_ux: Path) -> None:
    ux.delete_star_sentinel()


# ---------------------------------------------------------------------------
# _has_cgroup_bypass_support — decides whether `ttp bypass` gets cgroup rules
# ---------------------------------------------------------------------------


def test_cgroup_support_detected_when_nft_accepts_the_rule() -> None:
    with (
        patch("subprocess.run", return_value=MagicMock(returncode=0)) as run,
        patch("pathlib.Path.mkdir"),
    ):
        assert _has_cgroup_bypass_support() is True
    assert run.call_args[0][0][:2] == [resolve("nft"), "--check"]
    assert "socket cgroupv2" in run.call_args.kwargs["input"]


def test_cgroup_support_absent_when_nft_rejects_the_rule() -> None:
    """An old kernel has no cgroupv2 socket matching; the ruleset must not use it."""
    with (
        patch("subprocess.run", return_value=MagicMock(returncode=1)),
        patch("pathlib.Path.mkdir"),
    ):
        assert _has_cgroup_bypass_support() is False


def test_cgroup_support_absent_when_nft_is_missing() -> None:
    with (
        patch("subprocess.run", side_effect=FileNotFoundError("nft")),
        patch("pathlib.Path.mkdir"),
    ):
        assert _has_cgroup_bypass_support() is False


def test_cgroup_probe_survives_a_timeout() -> None:
    import subprocess

    with (
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired("nft", 10)),
        patch("pathlib.Path.mkdir"),
    ):
        assert _has_cgroup_bypass_support() is False


def test_cgroup_probe_survives_an_unwritable_cgroup_root() -> None:
    """A read-only /sys/fs/cgroup must not stop the probe from answering."""
    with (
        patch("pathlib.Path.mkdir", side_effect=PermissionError("read-only")),
        patch("subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        assert _has_cgroup_bypass_support() is True
