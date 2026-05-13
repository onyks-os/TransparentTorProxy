"""Tests for ttp.dns - DNS management logic.

All tests mock subprocess.run and file I/O.
Corresponds to TDD Section 8.3.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import dns
from ttp.exceptions import DNSError


@pytest.fixture(autouse=True)
def _mock_resolv_conf(tmp_path: Path):
    """Redirect /etc/resolv.conf to a temp file for every test."""
    fake_resolv = tmp_path / "resolv.conf"
    fake_runtime = tmp_path / "runtime_resolv.conf"
    fake_resolv.write_text("nameserver 8.8.8.8\n")
    with (
        patch.object(dns, "RESOLV_CONF", fake_resolv),
        patch.object(dns, "RUNTIME_RESOLV", fake_runtime),
    ):
        yield fake_resolv, fake_runtime


# Application


def test_apply_dns_overlay(_mock_resolv_conf):
    """apply_dns uses mount --bind overlay."""
    fake_resolv, fake_runtime = _mock_resolv_conf

    with (
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns.os.path.islink", return_value=False),
    ):
        mock_run.return_value = MagicMock(returncode=0)

        backup = dns.apply_dns("eth0")

        assert backup["mode"] == "overlay"
        assert backup["mount_target"] == str(fake_resolv)

        # Check that runtime file was written
        assert "nameserver 127.0.0.1" in fake_runtime.read_text()

        # Check mount command
        mock_run.assert_called_once_with(
            ["mount", "--bind", str(fake_runtime), str(fake_resolv)],
            capture_output=True,
            text=True,
            check=True,
        )


def test_apply_dns_symlink_overlay(_mock_resolv_conf):
    """apply_dns with resolv.conf symlink uses realpath for mount --bind."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_target = fake_resolv.parent / "real_resolv.conf"

    with (
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns.os.path.islink", return_value=True),
        patch("ttp.dns.os.path.realpath", return_value=str(fake_target)),
    ):
        mock_run.return_value = MagicMock(returncode=0)

        backup = dns.apply_dns("eth0")

        assert backup["mode"] == "overlay"
        assert backup["mount_target"] == str(fake_target)

        mock_run.assert_called_once_with(
            ["mount", "--bind", str(fake_runtime), str(fake_target)],
            capture_output=True,
            text=True,
            check=True,
        )


# Restoration


def test_restore_dns_overlay(_mock_resolv_conf):
    """restore_dns triggers lazy umount and cleanup."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        dns.restore_dns({"mount_target": str(fake_resolv)})

        # Check umount -l
        mock_run.assert_called_once_with(
            ["umount", "-l", str(fake_resolv)],
            capture_output=True,
            text=True,
            check=True,
        )

        # Check file cleanup
        assert not fake_runtime.exists()


# Error Handling


def test_apply_dns_failure():
    """apply_dns raises DNSError if mount fails."""
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, "mount", stderr="error")
        with pytest.raises(DNSError, match="mount --bind failed"):
            dns.apply_dns("eth0")


# Mount Stacking Prevention


def test_is_mount_point_found():
    """_is_mount_point returns True when target is listed in /proc/mounts."""
    proc_mounts = "tmpfs /run tmpfs rw 0 0\n/dev/sda1 /etc/resolv.conf ext4 rw 0 0\n"
    with patch(
        "builtins.open", MagicMock(return_value=__import__("io").StringIO(proc_mounts))
    ):
        assert dns._is_mount_point("/etc/resolv.conf") is True


def test_is_mount_point_not_found():
    """_is_mount_point returns False when target is not in /proc/mounts."""
    proc_mounts = "tmpfs /run tmpfs rw 0 0\n"
    with patch(
        "builtins.open", MagicMock(return_value=__import__("io").StringIO(proc_mounts))
    ):
        assert dns._is_mount_point("/etc/resolv.conf") is False


def test_is_mount_point_os_error():
    """_is_mount_point returns False when /proc/mounts is unreadable."""
    with patch("builtins.open", side_effect=OSError("Permission denied")):
        assert dns._is_mount_point("/etc/resolv.conf") is False


def test_clear_stale_mounts_removes_layers():
    """_clear_stale_mounts calls umount iteratively until target is clean."""
    # Returns True, True, False → umount called exactly 2 times
    with (
        patch("ttp.dns._is_mount_point", side_effect=[True, True, False]),
        patch("ttp.dns.subprocess.run") as mock_run,
    ):
        dns._clear_stale_mounts("/etc/resolv.conf")

        assert mock_run.call_count == 2
        mock_run.assert_called_with(
            ["umount", "-l", "/etc/resolv.conf"],
            capture_output=True,
            text=True,
            check=False,
        )


def test_clear_stale_mounts_noop_when_clean():
    """_clear_stale_mounts is a no-op when target is not a mount point."""
    with (
        patch("ttp.dns._is_mount_point", return_value=False),
        patch("ttp.dns.subprocess.run") as mock_run,
    ):
        dns._clear_stale_mounts("/etc/resolv.conf")
        mock_run.assert_not_called()


def test_apply_dns_clears_stale_before_mount(_mock_resolv_conf):
    """apply_dns calls _clear_stale_mounts before mount --bind."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    call_order = []

    def track_clear(target):
        call_order.append("clear")

    original_run = MagicMock(returncode=0)

    def track_mount(*args, **kwargs):
        call_order.append("mount")
        return original_run

    with (
        patch("ttp.dns._clear_stale_mounts", side_effect=track_clear) as mock_clear,
        patch("ttp.dns.subprocess.run", side_effect=track_mount),
        patch("ttp.dns.os.path.islink", return_value=False),
    ):
        dns.apply_dns("eth0")

        mock_clear.assert_called_once_with(str(fake_resolv))
        assert call_order == ["clear", "mount"]
