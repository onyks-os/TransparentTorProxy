# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.dns and ttp.dns_resolved - DNS management logic.

All tests mock subprocess.run and file I/O.
Corresponds to TDD Section 8.3.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import dns, dns_resolved
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
        patch("ttp.dns_resolved.apply_resolved", return_value=False),
    ):
        mock_run.return_value = MagicMock(returncode=0)

        backup = dns.apply_dns("eth0")

        assert backup["mode"] == "overlay"
        assert backup["mount_target"] == str(fake_resolv)

        # Check that runtime file was written
        assert "nameserver 127.0.0.1" in fake_runtime.read_text()

        # Check mount command
        mock_run.assert_any_call(
            ["mount", "--bind", str(fake_runtime), str(fake_resolv)],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )


def test_apply_dns_symlink_overlay(_mock_resolv_conf):
    """apply_dns with resolv.conf symlink uses realpath for mount --bind."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_target = fake_resolv.parent / "real_resolv.conf"

    with (
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns.os.path.islink", return_value=True),
        patch("ttp.dns.os.path.realpath", return_value=str(fake_target)),
        patch("ttp.dns_resolved.apply_resolved", return_value=False),
    ):
        mock_run.return_value = MagicMock(returncode=0)

        backup = dns.apply_dns("eth0")

        assert backup["mode"] == "overlay"
        assert backup["mount_target"] == str(fake_target)

        mock_run.assert_any_call(
            ["mount", "--bind", str(fake_runtime), str(fake_target)],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )


# Restoration


def test_restore_dns_overlay(_mock_resolv_conf):
    """restore_dns triggers lazy umount and cleanup."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    with (
        patch("ttp.dns._is_ttp_mount", return_value=True),
        patch("ttp.dns._is_mount_point", return_value=True),
        patch("ttp.dns.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)

        dns.restore_dns({"mount_target": str(fake_resolv)})

        # Check umount -l
        mock_run.assert_called_once_with(
            ["umount", "-l", str(fake_resolv)],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        # Check file cleanup
        assert not fake_runtime.exists()


# Error Handling


def test_apply_dns_failure():
    """apply_dns raises DNSError if mount fails."""

    def mock_run(args, **kwargs):
        if "mount" in args:
            raise subprocess.CalledProcessError(1, "mount", stderr="error")
        return MagicMock(returncode=0)

    with (
        patch("ttp.dns.subprocess.run", side_effect=mock_run),
        patch("ttp.dns_resolved.apply_resolved", return_value=False),
    ):
        with pytest.raises(DNSError, match="Command failed: mount -> error"):
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
        patch("ttp.dns._is_ttp_mount", side_effect=[True, True, False]),
        patch("ttp.dns.subprocess.run") as mock_run,
    ):
        dns._clear_stale_mounts("/etc/resolv.conf")

        assert mock_run.call_count == 2
        mock_run.assert_called_with(
            ["umount", "-l", "/etc/resolv.conf"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
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

    def track_run(args, *extra_args, **kwargs):
        if "mount" in args:
            call_order.append("mount")
        return original_run

    with (
        patch("ttp.dns._clear_stale_mounts", side_effect=track_clear) as mock_clear,
        patch("ttp.dns.subprocess.run", side_effect=track_run),
        patch("ttp.dns.os.path.islink", return_value=False),
        patch("ttp.dns_resolved.apply_resolved", return_value=False),
    ):
        dns.apply_dns("eth0")

        mock_clear.assert_called_once_with(str(fake_resolv))
        assert call_order == ["clear", "mount"]


def test_apply_dns_systemd_resolved_active(_mock_resolv_conf):
    """apply_dns propagates active resolved config from apply_resolved."""
    with (
        patch("ttp.dns_resolved.apply_resolved", return_value=True) as mock_resolved,
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns.os.path.islink", return_value=False),
    ):
        mock_run.return_value = MagicMock(returncode=0)
        backup = dns.apply_dns("eth0", disable_ipv6=False, dns_port=9054)

        assert backup["systemd_resolved"] is True
        mock_resolved.assert_called_once_with(dns_port=9054, disable_ipv6=False)


def test_apply_dns_systemd_resolved_inactive(_mock_resolv_conf):
    """apply_dns propagates inactive resolved config from apply_resolved."""
    with (
        patch("ttp.dns_resolved.apply_resolved", return_value=False) as mock_resolved,
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns.os.path.islink", return_value=False),
    ):
        mock_run.return_value = MagicMock(returncode=0)
        backup = dns.apply_dns("eth0", disable_ipv6=False, dns_port=9054)

        assert backup["systemd_resolved"] is False
        mock_resolved.assert_called_once_with(dns_port=9054, disable_ipv6=False)


def test_restore_dns_systemd_resolved():
    """restore_dns re-delegates systemd-resolved restore to dns_resolved module."""
    with (
        patch("ttp.dns_resolved.restore_resolved") as mock_restore,
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns._is_ttp_mount", return_value=True),
        patch("ttp.dns._is_mount_point", return_value=True),
    ):
        mock_run.return_value = MagicMock(returncode=0)
        dns.restore_dns({"mount_target": "/etc/resolv.conf", "systemd_resolved": True})

        mock_restore.assert_called_once()


# ---------------------------------------------------------------------------
# dns_resolved module Unit Tests
# ---------------------------------------------------------------------------


class TestDnsResolved:
    """Unit tests for dns_resolved.py module."""

    @patch("ttp.dns_resolved.subprocess.run")
    def test_is_resolved_active_true(self, mock_run):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        assert dns_resolved.is_resolved_active() is True

    @patch("ttp.dns_resolved.subprocess.run")
    def test_is_resolved_active_false(self, mock_run):
        mock_run.return_value = MagicMock(stdout="inactive\n", returncode=0)
        assert dns_resolved.is_resolved_active() is False

    @patch("ttp.dns_resolved.subprocess.run", side_effect=Exception("error"))
    def test_is_resolved_active_exception(self, mock_run):
        assert dns_resolved.is_resolved_active() is False

    @patch("ttp.dns_resolved.is_resolved_active", return_value=False)
    def test_apply_resolved_inactive(self, mock_active):
        assert dns_resolved.apply_resolved(9054) is False

    @patch("ttp.dns_resolved.is_resolved_active", return_value=True)
    @patch("ttp.dns_resolved.RESOLVED_CONF_FILE")
    @patch("ttp.dns_resolved.RESOLVED_CONF_DIR")
    @patch("ttp.dns_resolved.subprocess.run")
    @patch("ttp.system_info.is_ipv6_supported", return_value=True)
    def test_apply_resolved_active_success(
        self, mock_ipv6, mock_run, mock_dir, mock_file, mock_active
    ):
        mock_run.return_value = MagicMock(returncode=0)

        res = dns_resolved.apply_resolved(dns_port=9054, disable_ipv6=False)

        assert res is True
        mock_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        # Verify writing configuration with IPv6
        content = mock_file.write_text.call_args[0][0]
        assert "DNS=127.0.0.1:9054 [::1]:9054" in content
        assert "Cache=no-negative" in content

        # Check restart and flush commands
        calls = mock_run.call_args_list
        assert ["systemctl", "restart", "systemd-resolved"] in [
            c.args[0] for c in calls
        ]
        assert ["resolvectl", "flush-caches"] in [c.args[0] for c in calls]

    @patch("ttp.dns_resolved.is_resolved_active", return_value=True)
    @patch("ttp.dns_resolved.RESOLVED_CONF_FILE")
    @patch("ttp.dns_resolved.RESOLVED_CONF_DIR")
    @patch("ttp.dns_resolved.subprocess.run")
    @patch("ttp.system_info.is_ipv6_supported", return_value=True)
    def test_apply_resolved_active_success_no_ipv6(
        self, mock_ipv6, mock_run, mock_dir, mock_file, mock_active
    ):
        mock_run.return_value = MagicMock(returncode=0)

        res = dns_resolved.apply_resolved(dns_port=9054, disable_ipv6=True)

        assert res is True
        content = mock_file.write_text.call_args[0][0]
        assert "DNS=127.0.0.1:9054" in content
        assert "[::1]" not in content

    @patch("ttp.dns_resolved.is_resolved_active", return_value=True)
    @patch("ttp.dns_resolved.RESOLVED_CONF_FILE")
    @patch("ttp.dns_resolved.RESOLVED_CONF_DIR")
    @patch("ttp.dns_resolved.restore_resolved")
    @patch("ttp.dns_resolved.subprocess.run", side_effect=Exception("restart failed"))
    def test_apply_resolved_failure_restores(
        self, mock_run, mock_restore, mock_dir, mock_file, mock_active
    ):
        with pytest.raises(Exception, match="restart failed"):
            dns_resolved.apply_resolved(9054)
        mock_restore.assert_called_once()

    @patch("ttp.dns_resolved.RESOLVED_CONF_FILE")
    @patch("ttp.dns_resolved.subprocess.run")
    def test_restore_resolved(self, mock_run, mock_file):
        mock_file.exists.return_value = True
        mock_run.return_value = MagicMock(returncode=0)

        dns_resolved.restore_resolved()

        mock_file.unlink.assert_called_once()
        calls = mock_run.call_args_list
        assert ["systemctl", "restart", "systemd-resolved"] in [
            c.args[0] for c in calls
        ]
        assert ["resolvectl", "flush-caches"] in [c.args[0] for c in calls]
