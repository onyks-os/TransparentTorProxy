# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The branches that run when something has already gone wrong.

Each test here covers a path the coverage report showed no test ever executed,
and each one is a path where the host's security state is decided: the
killswitch failing to apply, teardown with no usable Tor UID, the firewall
unreadable, Tor's control socket refusing us, the watchdog crashing. A branch
that is only reached in an emergency is the last place to find out it raises.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import stem
import stem.connection
import typer

from ttp import state, tor_control
from ttp.commands import lifecycle
from ttp.exceptions import FirewallError, TorError
from ttp.firewall import runner
from ttp.watchdog import alerts, fsm

# ---------------------------------------------------------------------------
# The emergency killswitch
# ---------------------------------------------------------------------------


def test_a_killswitch_that_fails_to_apply_is_still_announced():
    """The broadcast is the operator's only signal that the network is in an
    undefined state; a firewall error must not swallow it."""
    with (
        patch.object(alerts.firewall, "apply_emergency_killswitch", side_effect=FirewallError("nft died")),
        patch.object(alerts, "resolve_optional", side_effect=lambda name: f"/usr/bin/{name}"),
        patch.object(alerts.subprocess, "run") as run,
        patch.object(alerts.logger, "critical") as critical,
    ):
        alerts.trigger_emergency_killswitch("firewall", "table vanished")

    assert any("Failed to apply firewall emergency killswitch" in str(c) for c in critical.call_args_list)
    assert run.call_args_list[0].args[0][0] == "/usr/bin/wall"


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------


def _stop_with(lock: dict, *, port_uid: int | None, known_users: dict[str, int]):
    def getpwnam(name: str):
        if name not in known_users:
            raise KeyError(name)
        return MagicMock(pw_uid=known_users[name])

    with (
        patch("ttp.state.read_lock", return_value=lock),
        patch("ttp.commands.lifecycle.firewall") as firewall,
        patch("ttp.commands.lifecycle.tor_install"),
        patch("ttp.commands.lifecycle.dns"),
        patch("ttp.commands.lifecycle.get_uid_from_port", return_value=port_uid),
        patch("ttp.commands.lifecycle.resolve_optional", return_value=None),
        patch("pwd.getpwnam", side_effect=getpwnam),
        patch("ttp.state.delete_lock") as delete_lock,
    ):
        lifecycle.do_stop()
    return firewall, delete_lock


def test_a_negative_tor_uid_in_the_lock_is_not_trusted():
    firewall, _ = _stop_with({"pid": 1, "tor_uid": -5}, port_uid=None, known_users={"debian-tor": 107})
    firewall.apply_teardown_lockdown.assert_called_once_with(107)


def test_teardown_locks_everything_down_when_no_tor_uid_can_be_found():
    """No lock value, no socket owner, no known Tor account: the lockdown is
    applied without a Tor exemption - Tor loses its circuits, nothing leaks -
    and teardown still completes."""
    firewall, delete_lock = _stop_with({"pid": 1}, port_uid=None, known_users={})
    firewall.apply_teardown_lockdown.assert_called_once_with(None)
    firewall.destroy_rules.assert_called_once()
    delete_lock.assert_called_once()


def test_a_conntrack_flush_that_fails_does_not_stop_teardown():
    with (
        patch("ttp.state.read_lock", return_value={"pid": 1, "tor_uid": 107}),
        patch("ttp.commands.lifecycle.firewall") as firewall,
        patch("ttp.commands.lifecycle.tor_install"),
        patch("ttp.commands.lifecycle.dns"),
        patch("ttp.commands.lifecycle.resolve_optional", return_value="/usr/sbin/conntrack"),
        patch(
            "ttp.commands.lifecycle.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "conntrack", stderr="table busy"),
        ),
        patch("ttp.commands.lifecycle.time.sleep"),
        patch("ttp.state.delete_lock") as delete_lock,
    ):
        lifecycle.do_stop()

    firewall.destroy_rules.assert_called_once()
    delete_lock.assert_called_once()


# ---------------------------------------------------------------------------
# The firewall runner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error", [OSError("nft missing"), subprocess.TimeoutExpired("nft", 10)])
def test_an_unreadable_table_listing_reads_as_absent(error):
    """The watchdog holds the killswitch by comparing listings; an unreadable
    one must read as "not the killswitch", which makes it re-apply."""
    with patch.object(runner.subprocess, "run", side_effect=error):
        assert runner.read_table_listing() is None


def test_a_failed_listing_reads_as_absent():
    with patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, stdout="partial")):
        assert runner.read_table_listing() is None


def test_a_firewall_error_during_apply_is_rolled_back_and_raised_unchanged():
    original = FirewallError("syntax error in ruleset")
    with (
        patch.object(runner, "_apply_table_atomically", side_effect=original),
        patch.object(runner, "destroy_rules") as destroy,
        patch.object(runner, "_build_ruleset", return_value="table inet ttp {}"),
        patch.object(runner, "_has_cgroup_bypass_support", return_value=False),
        patch("ttp.tor_detect.is_ipv6_supported", return_value=False),
        pytest.raises(FirewallError) as raised,
    ):
        runner.apply_rules("107")
    destroy.assert_called_once()
    assert raised.value is original


# ---------------------------------------------------------------------------
# The watchdog
# ---------------------------------------------------------------------------


def test_the_bundled_transitions_is_used_when_the_system_has_none(tmp_path, monkeypatch):
    """In-process twin of the subprocess test in test_watchdog_dependency.py,
    so the fallback is measured by coverage."""
    vendor = tmp_path / "vendor"
    (vendor / "transitions").mkdir(parents=True)
    (vendor / "transitions" / "__init__.py").write_text("class Machine:\n    pass\n", encoding="utf-8")

    class OnlyTheVendoredCopy:
        def find_spec(self, name, path=None, target=None):
            if name != "transitions":
                return None
            import importlib.machinery

            spec = importlib.machinery.PathFinder.find_spec(name, [p for p in sys.path if p == str(vendor)])
            if spec is None:
                raise ModuleNotFoundError(name=name)
            return spec

    monkeypatch.delitem(sys.modules, "transitions", raising=False)
    monkeypatch.setattr(sys, "meta_path", [OnlyTheVendoredCopy(), *sys.meta_path])
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(fsm, "VENDOR_DIR", vendor)
    try:
        machine = fsm.load_machine()
        assert Path(sys.modules[machine.__module__].__file__).is_relative_to(vendor)
    finally:
        sys.modules.pop("transitions", None)


def test_an_unusable_bundled_copy_is_reported_as_such(tmp_path, monkeypatch):
    vendor = tmp_path / "vendor"
    (vendor / "transitions").mkdir(parents=True)
    monkeypatch.setitem(sys.modules, "transitions", None)  # every import of it fails
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(fsm, "VENDOR_DIR", vendor)
    with pytest.raises(fsm.WatchdogUnavailableError, match="bundled copy unusable"):
        fsm.load_machine()


@pytest.fixture
def machine_deps():
    libc = MagicMock()
    libc.inotify_init.return_value = 99
    libc.inotify_add_watch.return_value = 1
    with (
        patch("socket.socket") as sock,
        patch("ctypes.CDLL", return_value=libc),
        patch("ctypes.util.find_library", return_value="libc.so.6"),
        patch("os.set_blocking"),
        patch("os.close"),
        patch("ttp.watchdog.fsm.trigger_emergency_killswitch") as killswitch,
        patch("ttp.watchdog.fsm.attempt_auto_healing"),
    ):
        yield {"sock": sock.return_value, "libc": libc, "killswitch": killswitch}


def test_shutdown_survives_a_watch_the_kernel_refuses_to_remove(machine_deps):
    watchdog = fsm.WatchdogFSM()
    watchdog.initialize(interval_seconds=15)
    machine_deps["libc"].inotify_rm_watch.side_effect = OSError("EINVAL")
    watchdog.shutdown()
    assert watchdog.state == "stopped"
    assert watchdog.inotify_fd == -1


def test_inotify_failure_fires_the_killswitch_even_if_the_netlink_socket_will_not_close(machine_deps):
    machine_deps["libc"].inotify_init.return_value = -1
    machine_deps["sock"].close.side_effect = OSError("EBADF")
    watchdog = fsm.WatchdogFSM()
    with pytest.raises(OSError, match="inotify_init failed"):
        watchdog.initialize(interval_seconds=15)
    machine_deps["killswitch"].assert_called_once()
    assert machine_deps["killswitch"].call_args.args[0] == "dns"


def test_a_crashed_watchdog_loop_exits_non_zero_so_systemd_restarts_it():
    from ttp.commands import watchdog as watchdog_cmd

    with (
        patch.object(watchdog_cmd, "_require_root_or_watchdog_user"),
        patch("ttp.watchdog.run_watchdog_loop", side_effect=RuntimeError("select() blew up")),
        pytest.raises(typer.Exit) as exited,
    ):
        watchdog_cmd.watchdog_run(interval=15)
    assert exited.value.exit_code == 1


# ---------------------------------------------------------------------------
# Tor's control socket
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        OSError("connection refused"),
        stem.SocketError("socket closed"),
        stem.connection.AuthenticationFailure("bad cookie"),
        stem.ControllerError("protocol error"),
    ],
    ids=["os", "socket", "auth", "controller"],
)
def test_a_control_socket_that_refuses_us_reads_as_no_controller(error):
    with (
        patch.object(tor_control.os.path, "exists", return_value=True),
        patch.object(tor_control.Controller, "from_socket_file", side_effect=error),
    ):
        assert tor_control.get_controller() is None


def test_a_control_socket_that_dies_mid_bootstrap_is_a_tor_error():
    controller = MagicMock()
    controller.__enter__.return_value = controller
    controller.get_info.side_effect = stem.ControllerError("closed")
    with (
        patch.object(tor_control, "get_controller", return_value=controller),
        pytest.raises(TorError, match="communication failed during bootstrap"),
    ):
        tor_control.wait_for_bootstrap(timeout=5)


def test_graceful_shutdown_without_stem_reports_nothing_sent(monkeypatch):
    monkeypatch.setattr(tor_control, "Signal", None)
    assert tor_control.graceful_shutdown() is False


def test_graceful_shutdown_waits_out_a_tor_that_keeps_answering():
    """The signal was sent, which is what True means; a Tor still answering
    after the timeout is left to the teardown lockdown, and a controller that
    errors while being closed must not end the wait early."""
    first = MagicMock()
    first.__enter__.return_value = first
    lingering = MagicMock()
    lingering.close.side_effect = stem.ControllerError("already closed")
    with (
        patch.object(tor_control, "get_controller", side_effect=[first, lingering, lingering, lingering]),
        patch.object(tor_control.time, "sleep") as sleep,
    ):
        assert tor_control.graceful_shutdown(timeout=3) is True
    assert sleep.call_count == 3


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------


def test_without_the_watchdog_account_its_files_belong_to_root():
    with patch("pwd.getpwnam", side_effect=KeyError("ttp-watchdog")):
        assert state._watchdog_uid_or_root() == 0


def test_without_the_watchdog_group_the_lock_is_root_only(tmp_path):
    lock = tmp_path / "ttp.lock"
    with (
        patch.object(state, "LOCK_DIR", tmp_path),
        patch.object(state, "LOCK_PATH", lock),
        patch.object(state, "_watchdog_gid", return_value=None),
        patch.object(state, "ensure_runtime_dir"),
    ):
        state._write_lock_file({"pid": 1})
    assert lock.stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Substitution checks: a file swapped between being written and being used
# ---------------------------------------------------------------------------


def test_a_resolver_file_that_disappeared_is_refused(tmp_path):
    from ttp import dns
    from ttp.exceptions import DNSError

    path = tmp_path / "resolv.conf"
    path.write_text("nameserver 127.0.0.1\n")
    expected = path.lstat()
    path.unlink()
    with pytest.raises(DNSError, match="disappeared"):
        dns._assert_is(path, expected)


def test_a_resolver_file_replaced_by_another_inode_is_refused(tmp_path):
    from ttp import dns
    from ttp.exceptions import DNSError

    path = tmp_path / "resolv.conf"
    path.write_text("nameserver 127.0.0.1\n")
    expected = path.lstat()
    replacement = tmp_path / "other"
    replacement.write_text("nameserver 203.0.113.1\n")
    replacement.replace(path)
    with pytest.raises(DNSError, match="was replaced"):
        dns._assert_is(path, expected)


def test_a_resolver_file_that_gained_a_second_link_is_refused(tmp_path):
    """A hard link elsewhere is a handle on the same inode that TTP does not control."""
    from ttp import dns
    from ttp.exceptions import DNSError

    path = tmp_path / "resolv.conf"
    path.write_text("nameserver 127.0.0.1\n")
    expected = path.lstat()
    (tmp_path / "handle").hardlink_to(path)
    with pytest.raises(DNSError, match="no longer a private regular file"):
        dns._assert_is(path, expected)


def test_apply_dns_refuses_a_runtime_resolver_with_a_second_link(tmp_path, monkeypatch):
    from ttp import dns, dns_resolved
    from ttp.exceptions import DNSError

    runtime = tmp_path / "resolv.conf"
    runtime.write_text("")
    (tmp_path / "planted").hardlink_to(runtime)
    monkeypatch.setattr(dns, "RUNTIME_RESOLV", runtime)
    with (
        patch.object(dns_resolved, "apply_resolved", return_value=False),
        patch("ttp.system_info.is_ipv6_supported", return_value=False),
        pytest.raises(DNSError, match="not a private regular file"),
    ):
        dns.apply_dns("eth0")
    assert runtime.read_text() == "", "nothing may be written through the planted link"


def _fake_stat(uid: int, mode: int):
    return MagicMock(st_uid=uid, st_mode=mode)


@pytest.mark.parametrize(
    ("file_stat", "dir_stat", "trusted"),
    [
        ((0, 0o100755), (0, 0o040755), True),
        ((1000, 0o100755), (0, 0o040755), False),  # file not root's
        ((0, 0o100775), (0, 0o040755), False),  # file group-writable
        ((0, 0o100757), (0, 0o040755), False),  # file world-writable
        ((0, 0o100755), (0, 0o040775), False),  # directory group-writable: replace by rename
        ((0, 0o100755), (1000, 0o040755), False),  # directory not root's
    ],
)
def test_a_binary_is_trusted_only_if_root_alone_can_replace_it(file_stat, dir_stat, trusted):
    from ttp import paths

    binary = Path("/usr/sbin/nft")
    stats = {binary: _fake_stat(*file_stat), binary.parent: _fake_stat(*dir_stat)}
    with patch.object(Path, "stat", lambda self, **kw: stats[self]):
        assert paths._is_safely_owned(binary) is trusted


def test_a_binary_that_cannot_be_inspected_is_not_trusted(tmp_path):
    from ttp import paths

    assert paths._is_safely_owned(tmp_path / "missing" / "nft") is False


def test_an_unexpected_error_during_apply_is_rolled_back_as_a_firewall_error():
    with (
        patch.object(runner, "_apply_table_atomically", side_effect=RuntimeError("nft segfault")),
        patch.object(runner, "destroy_rules") as destroy,
        patch.object(runner, "_build_ruleset", return_value="table inet ttp {}"),
        patch.object(runner, "_has_cgroup_bypass_support", return_value=False),
        patch("ttp.tor_detect.is_ipv6_supported", return_value=False),
        pytest.raises(FirewallError, match="Failed to apply stateless rules"),
    ):
        runner.apply_rules("107")
    destroy.assert_called_once()


def test_without_transitions_or_a_bundle_the_watchdog_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "transitions", None)
    monkeypatch.setattr(fsm, "VENDOR_DIR", tmp_path / "no-bundle")
    with pytest.raises(fsm.WatchdogUnavailableError, match="python3-transitions"):
        fsm.load_machine()
    assert fsm.watchdog_dependency_available() is False


def test_readd_watch_survives_a_watch_the_kernel_refuses_to_remove(machine_deps):
    watchdog = fsm.WatchdogFSM()
    watchdog.initialize(interval_seconds=15)
    machine_deps["libc"].inotify_rm_watch.side_effect = OSError("EINVAL")
    watchdog.readd_watch()
    assert watchdog.wd_real >= 0 or watchdog.wd_link >= 0


def test_restore_dns_follows_a_symlinked_resolv_conf_to_its_target(tmp_path, monkeypatch):
    """On systemd-resolved hosts /etc/resolv.conf is a symlink; the overlay was
    mounted on its target, so that is what must be unmounted."""
    from ttp import dns

    real = tmp_path / "stub-resolv.conf"
    real.write_text("nameserver 127.0.0.53\n")
    link = tmp_path / "resolv.conf"
    link.symlink_to(real)
    monkeypatch.setattr(dns, "RESOLV_CONF", link)
    monkeypatch.setattr(dns, "RUNTIME_RESOLV", tmp_path / "runtime-resolv.conf")
    with (
        patch.object(dns, "_is_ttp_mount", return_value=False) as is_mounted,
        patch("ttp.dns_resolved.restore_resolved"),
    ):
        dns.restore_dns(None)
    is_mounted.assert_any_call(str(real))
