# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.dns and ttp.dns_resolved - DNS management logic.

All tests mock subprocess.run and file I/O.
Corresponds to TDD Section 8.3.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from ttp import dns, dns_resolved
from ttp.exceptions import DNSError
from ttp.paths import resolve


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
            [resolve("mount"), "--bind", str(fake_runtime), str(fake_resolv)],
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
            [resolve("mount"), "--bind", str(fake_runtime), str(fake_target)],
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
            [resolve("umount"), "-l", str(fake_resolv)],
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
        if resolve("mount") in args:
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
    with patch("builtins.open", MagicMock(return_value=__import__("io").StringIO(proc_mounts))):
        assert dns._is_mount_point("/etc/resolv.conf") is True


def test_is_mount_point_not_found():
    """_is_mount_point returns False when target is not in /proc/mounts."""
    proc_mounts = "tmpfs /run tmpfs rw 0 0\n"
    with patch("builtins.open", MagicMock(return_value=__import__("io").StringIO(proc_mounts))):
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
            [resolve("umount"), "-l", "/etc/resolv.conf"],
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
    fake_resolv, _fake_runtime = _mock_resolv_conf
    call_order = []

    def track_clear(target):
        call_order.append("clear")

    original_run = MagicMock(returncode=0)

    def track_run(args, *extra_args, **kwargs):
        if resolve("mount") in args:
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
# Teardown: every step must run even when an earlier one fails
# ---------------------------------------------------------------------------
#
# `restore_dns` performs three things in a fixed order - unmount the overlay,
# hand systemd-resolved back its configuration, delete the volatile file - and
# swallows a failure in each with a `logger.warning`. Swallowing is right: it is
# called from `stop` and from `start`'s rollback, and raising would abort the
# rest of the teardown over a step that is already lost.
#
# What matters is that swallowing does not become *stopping*. The order is not
# arbitrary: the unmount has to happen first so systemd-resolved reads the
# restored base file. A teardown that gives up after a failed unmount therefore
# leaves `/etc/resolv.conf` still bind-mounted onto a Tor DNSPort that `stop` is
# about to kill - every lookup on the host failing, with no session and no
# warning to connect it to.
#
# So each test below breaks one step and asserts the *later* ones still ran.


def test_restore_dns_continues_after_a_failed_unmount(_mock_resolv_conf, caplog):
    """A failed umount must not strand systemd-resolved or the volatile file."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    unmount_failed = subprocess.CalledProcessError(1, "umount", stderr="target is busy")
    with (
        patch("ttp.dns._is_ttp_mount", return_value=True),
        patch("ttp.dns.subprocess.run", side_effect=unmount_failed),
        patch("ttp.dns_resolved.restore_resolved") as mock_restore,
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        dns.restore_dns({"mount_target": str(fake_resolv), "systemd_resolved": True})

    # Steps 2 and 3 ran regardless.
    assert mock_restore.call_count == 1
    assert not fake_runtime.exists()
    assert "Failed to unmount DNS overlay" in caplog.text
    assert "target is busy" in caplog.text


def test_restore_dns_continues_after_a_failed_resolved_restore(_mock_resolv_conf, caplog):
    """A systemd-resolved failure must not leak the volatile file into tmpfs."""
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    with (
        patch("ttp.dns._is_ttp_mount", return_value=True),
        patch("ttp.dns.subprocess.run", return_value=MagicMock(returncode=0)),
        patch("ttp.dns_resolved.restore_resolved", side_effect=RuntimeError("dbus timeout")),
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        dns.restore_dns({"mount_target": str(fake_resolv), "systemd_resolved": True})

    assert not fake_runtime.exists()
    assert "Failed to restore systemd-resolved" in caplog.text


def test_restore_dns_does_not_raise_when_the_volatile_file_cannot_be_removed(_mock_resolv_conf):
    """The last step is cosmetic, and must not turn a teardown into an exception.

    `restore_dns` is called from `start`'s StateError rollback, where an
    exception escaping here would replace the error the operator needs to see
    with an OSError about a file in tmpfs.
    """
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    with (
        patch("ttp.dns._is_ttp_mount", return_value=True),
        patch("ttp.dns.subprocess.run", return_value=MagicMock(returncode=0)),
        patch.object(Path, "unlink", side_effect=OSError("read-only file system")),
    ):
        dns.restore_dns({"mount_target": str(fake_resolv)})  # must not raise


def test_restore_dns_skips_the_unmount_when_nothing_is_mounted(_mock_resolv_conf):
    """No overlay to remove is the normal case after a crash, not an error.

    The watchdog's `dns` violation is precisely "resolv.conf unmounted", so
    `stop` routinely runs against a target that is already clear. It must skip
    the umount rather than attempt one, and still complete steps 2 and 3.
    """
    fake_resolv, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    with (
        patch("ttp.dns._is_ttp_mount", return_value=False),
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns_resolved.restore_resolved") as mock_restore,
    ):
        dns.restore_dns({"mount_target": str(fake_resolv), "systemd_resolved": True})

    assert mock_run.call_count == 0
    assert mock_restore.call_count == 1
    assert not fake_runtime.exists()


# ---------------------------------------------------------------------------
# apply_dns rolls back its own partial state
# ---------------------------------------------------------------------------
#
# This is the property `ttp start`'s rollback branches are built on: neither the
# DNSError branch nor the unexpected-DNS branch calls `restore_dns`, because
# `apply_dns` is expected to have already undone whatever it managed to do. That
# expectation was asserted in a docstring and nowhere else (#31); these tests
# are what make it a contract.


def test_apply_dns_rolls_back_its_resolved_dropin_when_the_mount_fails(_mock_resolv_conf):
    """A drop-in written before a failed mount must not outlive the failure.

    `apply_resolved` runs first and restarts systemd-resolved pointed at Tor's
    DNSPort. If the bind mount then fails, `start` gives up - and if the drop-in
    survived, the host would resolve through a DNSPort with no session behind it
    and nothing in the lock file to explain it.
    """

    def run(args, **kwargs):
        if resolve("mount") in args:
            raise subprocess.CalledProcessError(1, "mount", stderr="not a directory")
        return MagicMock(returncode=0)

    with (
        patch("ttp.dns.subprocess.run", side_effect=run),
        patch("ttp.dns_resolved.apply_resolved", return_value=True),
        patch("ttp.dns_resolved.restore_resolved") as mock_restore,
        pytest.raises(DNSError),
    ):
        dns.apply_dns("eth0")

    assert mock_restore.call_count == 1


def test_apply_dns_does_not_roll_back_a_dropin_it_never_wrote(_mock_resolv_conf):
    """`apply_resolved` returning False means there is nothing to undo.

    Calling `restore_resolved` anyway would restart systemd-resolved on a host
    where TTP never touched it - a side effect from a command that failed.
    """

    def run(args, **kwargs):
        if resolve("mount") in args:
            raise subprocess.CalledProcessError(1, "mount", stderr="not a directory")
        return MagicMock(returncode=0)

    with (
        patch("ttp.dns.subprocess.run", side_effect=run),
        patch("ttp.dns_resolved.apply_resolved", return_value=False),
        patch("ttp.dns_resolved.restore_resolved") as mock_restore,
        pytest.raises(DNSError),
    ):
        dns.apply_dns("eth0")

    assert mock_restore.call_count == 0


def test_apply_dns_reports_the_mount_failure_even_if_its_own_rollback_fails(_mock_resolv_conf):
    """The rollback's own failure must not replace the error that caused it.

    `apply_dns` wraps its cleanup in a bare `except Exception: pass` for exactly
    this reason. The caller is `start`, which needs the DNS failure to report;
    a dbus error from the cleanup would tell it nothing useful and hide the
    cause.
    """

    def run(args, **kwargs):
        if resolve("mount") in args:
            raise subprocess.CalledProcessError(1, "mount", stderr="not a directory")
        return MagicMock(returncode=0)

    with (
        patch("ttp.dns.subprocess.run", side_effect=run),
        patch("ttp.dns_resolved.apply_resolved", return_value=True),
        patch("ttp.dns_resolved.restore_resolved", side_effect=RuntimeError("dbus timeout")),
        pytest.raises(DNSError, match="Command failed: mount"),
    ):
        dns.apply_dns("eth0")


def test_apply_dns_wraps_an_unexpected_failure_as_dnserror(_mock_resolv_conf):
    """Anything that is not a CalledProcessError still arrives as DNSError.

    `start` catches `DNSError` and a generic `Exception` in two separate
    branches that happen to tear down identically today. They are only
    guaranteed to stay identical for failures that reach the generic one, so
    everything `apply_dns` can foresee is converted here rather than left to
    chance.
    """
    with (
        patch("ttp.dns_resolved.apply_resolved", return_value=False),
        patch.object(Path, "write_text", side_effect=PermissionError("read-only /run")),
        pytest.raises(DNSError, match="Failed to apply DNS configuration"),
    ):
        dns.apply_dns("eth0")


def test_restore_dns_with_no_backup_is_a_no_op(_mock_resolv_conf):
    """A falsy backup means there was never a session, so there is nothing to undo.

    This is the guard that makes `restore_dns(None)` silent, and the reason
    `start`'s StateError rollback has to pass the real backup dict rather than
    `None` - a detail that is otherwise invisible and is asserted from the other
    side in `tests/test_cli_start.py`.
    """
    _, fake_runtime = _mock_resolv_conf
    fake_runtime.touch()

    with (
        patch("ttp.dns._is_ttp_mount") as mock_is_mount,
        patch("ttp.dns.subprocess.run") as mock_run,
        patch("ttp.dns_resolved.restore_resolved") as mock_restore,
    ):
        dns.restore_dns(None)
        dns.restore_dns({})

    assert mock_is_mount.call_count == 0
    assert mock_run.call_count == 0
    assert mock_restore.call_count == 0
    # Notably it does *not* clean up the volatile file either.
    assert fake_runtime.exists()


# Interface detection


def test_detect_active_interface_reads_the_default_route():
    """The interface name comes from `ip route show default`, not a guess.

    It decides which interface `apply_dns` configures, so the fallback below is
    a last resort rather than an equivalent outcome.
    """
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="default via 192.168.1.1 dev wlp3s0 proto dhcp metric 600",
        )
        assert dns.detect_active_interface() == "wlp3s0"

    assert mock_run.call_args.args[0][:4] == [resolve("ip"), "route", "show", "default"]


def test_detect_active_interface_falls_back_when_there_is_no_default_route():
    """No route, or `ip` failing outright, must not raise - `start` would abort.

    "eth0" is a guess, and a wrong guess means the DNS overlay is applied to an
    interface that is not carrying the traffic. That is a real limitation, but
    an exception here would be worse: it would fail the session before any rule
    is applied, which is the one start path that leaves the host in cleartext.
    """
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        assert dns.detect_active_interface() == "eth0"

    with patch("ttp.dns.subprocess.run", side_effect=subprocess.CalledProcessError(2, "ip")):
        assert dns.detect_active_interface() == "eth0"


# Mount introspection


def test_is_ttp_mount_recognises_a_ttp_overlay(tmp_path: Path):
    """Only a mount whose line mentions ttp counts, so foreign mounts are left alone.

    `restore_dns` unmounts whatever this returns True for. Matching on the mount
    point alone would make TTP unmount a resolv.conf overlay installed by
    something else - a VPN client, a container runtime - on teardown.
    """
    mountinfo = (
        "25 30 0:22 / /proc rw,nosuid shared:5 - proc proc rw\n"
        "31 30 0:24 /ttp/resolv.conf /etc/resolv.conf rw - tmpfs ttp-run rw\n"
    )
    with patch("builtins.open", mock_open(read_data=mountinfo)):
        assert dns._is_ttp_mount("/etc/resolv.conf") is True
        assert dns._is_ttp_mount("/proc") is False
        assert dns._is_ttp_mount("/etc/nsswitch.conf") is False


def test_is_ttp_mount_is_false_when_mountinfo_cannot_be_read():
    """An unreadable /proc must answer "not mounted", never raise.

    Both callers treat True as "there is an overlay to remove". Answering False
    means `restore_dns` skips an unmount it might have needed, which is a
    leftover; raising would abort the whole teardown, which is worse.
    """
    with patch("builtins.open", side_effect=PermissionError("no /proc")):
        assert dns._is_ttp_mount("/etc/resolv.conf") is False


def test_clear_stale_mounts_warns_when_the_stack_will_not_clear(caplog):
    """A mount stack that survives 100 unmounts is reported, not silently accepted.

    `apply_dns` calls this before mounting its own overlay. If the stack is
    still there afterwards, the new mount goes on top of unknown layers and the
    matching unmount on teardown will expose one of them rather than the
    original file - so the operator has to be told.
    """
    with (
        patch("ttp.dns._is_ttp_mount", return_value=True),
        patch("ttp.dns.subprocess.run") as mock_run,
        caplog.at_level(logging.WARNING, logger="ttp"),
    ):
        dns._clear_stale_mounts("/etc/resolv.conf")

    assert mock_run.call_count == 100
    assert "Could not fully clear stale TTP mounts" in caplog.text


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
    def test_apply_resolved_active_success(self, mock_ipv6, mock_run, mock_dir, mock_file, mock_active):
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
        assert [resolve("systemctl"), "restart", "systemd-resolved"] in [c.args[0] for c in calls]
        assert [resolve("resolvectl"), "flush-caches"] in [c.args[0] for c in calls]

    @patch("ttp.dns_resolved.is_resolved_active", return_value=True)
    @patch("ttp.dns_resolved.RESOLVED_CONF_FILE")
    @patch("ttp.dns_resolved.RESOLVED_CONF_DIR")
    @patch("ttp.dns_resolved.subprocess.run")
    @patch("ttp.system_info.is_ipv6_supported", return_value=True)
    def test_apply_resolved_active_success_no_ipv6(self, mock_ipv6, mock_run, mock_dir, mock_file, mock_active):
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
    def test_apply_resolved_failure_restores(self, mock_run, mock_restore, mock_dir, mock_file, mock_active):
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
        assert [resolve("systemctl"), "restart", "systemd-resolved"] in [c.args[0] for c in calls]
        assert [resolve("resolvectl"), "flush-caches"] in [c.args[0] for c in calls]
