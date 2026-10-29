# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

import json
import os
import signal
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ttp import state
from ttp.exceptions import StateError
from ttp.runtime_records import RecordStore
from ttp.settings import Settings
from ttp.watchdog import progress, service, supervisor

INSTANCE = "a" * 32


@pytest.fixture
def supervised(tmp_path, monkeypatch):
    store = RecordStore(tmp_path / "records", os.getuid(), os.getgid())
    store.prepare()
    lock = {"session_id": "s", "phase": "running", "watchdog_requested": True, "settings": Settings().snapshot()}
    path = tmp_path / "session"
    path.write_text(json.dumps(lock))
    monkeypatch.setattr(state, "LOCK_PATH", path)
    monkeypatch.setenv("INVOCATION_ID", INSTANCE)
    monkeypatch.setattr(supervisor, "session_store", lambda: store)
    monkeypatch.setattr(service, "session_store", lambda: store)
    fsm = Mock(netlink_socket=object(), inotify_fd=5, wd_real=1, wd_link=2)
    monkeypatch.setattr(supervisor, "WatchdogFSM", lambda: fsm)
    monkeypatch.setattr(supervisor, "check_system_integrity", Mock(return_value=(None, None)))
    monkeypatch.setattr(supervisor, "notify_progress", Mock())

    def end_after_evaluation(*args):
        path.unlink()
        return [], [], []

    monkeypatch.setattr(supervisor.select, "select", Mock(side_effect=end_after_evaluation))
    return store, lock, fsm


def test_ready_requires_subscriptions_and_completed_initial_evaluation(supervised):
    store, _, fsm = supervised
    order = []
    fsm.initialize.side_effect = lambda **kwargs: order.append("subscribed")
    supervisor.check_system_integrity.side_effect = lambda: (order.append("evaluated") and None, None)

    def notify(**kwargs):
        assert store.read("watchdog", "s")["data"]["value"] == "healthy"
        assert kwargs == {"ready": True}
        order.append("ready")

    supervisor.notify_progress.side_effect = notify
    supervisor.run_supervisor()
    assert order == ["subscribed", "evaluated", "ready"]
    fsm.shutdown.assert_called_once()


def test_readiness_never_sent_for_failed_subscription(supervised, monkeypatch):
    _, _, fsm = supervised
    fsm.wd_real = -1
    emergency = Mock()
    monkeypatch.setattr(supervisor, "request_emergency", emergency)
    with pytest.raises(StateError, match="subscriptions"):
        supervisor.run_supervisor()
    supervisor.notify_progress.assert_not_called()
    emergency.assert_called_once()


def test_check_deadline_is_not_swallowed_by_library_fallback():
    previous = signal.getsignal(signal.SIGALRM)

    def hanging_read():
        try:
            time.sleep(1)
        except Exception:
            return "false success"

    started = time.monotonic()
    with pytest.raises(progress.CheckDeadline):
        progress.bounded_check(hanging_read, 0.01)
    assert time.monotonic() - started < 0.5
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


def test_check_success_and_failure_restore_alarm():
    assert progress.bounded_check(lambda: 42, 1) == 42

    def failed():
        raise ValueError("bad observation")

    with pytest.raises(ValueError):
        progress.bounded_check(failed, 1)
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


def test_no_background_heartbeat_masks_a_timed_out_check(supervised, monkeypatch):
    store, _, _ = supervised
    supervisor.check_system_integrity.side_effect = progress.CheckDeadline()
    result = SimpleNamespace(as_dict=lambda: {"exit_code": 8})
    emergency = Mock(return_value=result)
    monkeypatch.setattr(supervisor, "request_emergency", emergency)
    supervisor.run_supervisor()
    assert emergency.call_args.args[1].reason == "watchdog.check_timeout"
    assert store.read("watchdog", "s")["data"]["value"] == "emergency"


def test_restart_does_not_heal_or_probe_tor_when_emergency_is_latched(supervised, monkeypatch):
    store, _, _ = supervised
    store.write("emergency", "s", {"requested": True})
    monkeypatch.setattr(
        supervisor, "request_emergency", Mock(return_value=SimpleNamespace(as_dict=lambda: {"exit_code": 7}))
    )
    heal = Mock()
    monkeypatch.setattr(supervisor, "attempt_auto_healing", heal)
    supervisor.run_supervisor()
    supervisor.check_system_integrity.assert_not_called()
    heal.assert_not_called()
    assert store.read("watchdog", "s")["data"]["value"] == "emergency"


def test_event_immediately_invalidates_previous_health_before_recheck(supervised, monkeypatch):
    store, _, fsm = supervised
    calls = 0

    def select_event(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [fsm.netlink_socket], [], []
        state.LOCK_PATH.unlink()
        return [], [], []

    monkeypatch.setattr(supervisor.select, "select", select_event)

    def drain(sources):
        data = store.read("watchdog", "s")["data"]
        assert data["value"] == "unknown" and data["observed_at"] is None

    fsm.flush_event_buffers.side_effect = drain
    supervisor.run_supervisor()
    assert supervisor.check_system_integrity.call_count == 2
    assert supervisor.notify_progress.call_args_list[0].kwargs == {"ready": True}
    assert supervisor.notify_progress.call_args_list[1].kwargs == {"ready": False}


@pytest.mark.parametrize("invocation", ["", "not-an-id"])
def test_supervisor_rejects_missing_or_invalid_service_identity(supervised, monkeypatch, invocation):
    monkeypatch.setenv("INVOCATION_ID", invocation)
    with pytest.raises((StateError, ValueError)):
        supervisor.run_supervisor()


def test_no_session_requires_no_subscriptions(supervised):
    _, _, fsm = supervised
    state.LOCK_PATH.unlink()
    supervisor.run_supervisor()
    fsm.initialize.assert_not_called()


def _unit(monkeypatch, invocation=INSTANCE, active="active"):
    monkeypatch.setattr(
        service.subprocess,
        "run",
        Mock(
            return_value=SimpleNamespace(
                stdout=f"ActiveState={active}\nMainPID=123\nInvocationID={invocation}\n",
            )
        ),
    )


def _observation(store, **values):
    store.write(
        "watchdog", "s", {"value": "healthy", "instance_id": INSTANCE, "observed_at": service.boottime(), **values}
    )


def test_pid_and_active_unit_alone_do_not_establish_supervision(supervised, monkeypatch):
    _unit(monkeypatch)
    assert service.watchdog_liveness() == (False, None)


def test_live_observation_matches_current_invocation_and_never_writes_intent(supervised, monkeypatch):
    store, _, _ = supervised
    _unit(monkeypatch)
    _observation(store)
    update = Mock()
    monkeypatch.setattr(state, "update_lock_keys", update)
    assert service.watchdog_liveness() == (True, 123)
    update.assert_not_called()
    _unit(monkeypatch, invocation="b" * 32)
    assert service.watchdog_observation()["reason"] == "watchdog.progress_stale"


@pytest.mark.parametrize(
    "values,reason",
    [
        ({"observed_at": 0}, "watchdog.integrity_stale"),
        ({"observed_at": None, "reason": "event"}, "event"),
        ({"observed_at": True}, "watchdog.evaluation_pending"),
    ],
)
def test_pending_or_expired_observations_are_unknown(supervised, monkeypatch, values, reason):
    store, _, _ = supervised
    _unit(monkeypatch)
    _observation(store, **values)
    monkeypatch.setattr(service, "boottime", lambda: store.read("watchdog", "s")["written_at"] + 1)
    assert service.watchdog_observation()["reason"] == reason


def test_unit_inactive_or_unqueryable_is_never_reported_healthy(supervised, monkeypatch):
    _unit(monkeypatch, active="activating")
    assert service.watchdog_observation()["value"] == "unavailable"
    service.subprocess.run.side_effect = OSError("cannot query systemd")
    assert service.watchdog_observation()["value"] == "unknown"


def test_generated_unit_requires_readiness_progress_and_independent_handler(tmp_path, monkeypatch):
    path = tmp_path / "watchdog.service"
    monkeypatch.setattr(service, "WATCHDOG_SERVICE_PATH", path)
    service._write_watchdog_service_unit()
    content = path.read_text()
    for line in (
        "Type=notify",
        "NotifyAccess=main",
        "WatchdogSec=30",
        "TimeoutStartSec=30",
        "RestartSec=3",
        "StartLimitBurst=5",
    ):
        assert line in content
    assert "ExecStopPost=" in content and "watchdog terminated" in content


@pytest.mark.parametrize("address", [None, "relative/path"])
def test_progress_refuses_missing_or_invalid_notify_socket(monkeypatch, address):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    if address:
        monkeypatch.setenv("NOTIFY_SOCKET", address)
    with pytest.raises(StateError, match="notification socket"):
        progress.notify_progress()


@pytest.mark.parametrize(
    "address,expected", [("/tmp/systemd-notify", "/tmp/systemd-notify"), ("@abstract", "\0abstract")]
)
def test_main_process_sends_notify_protocol(monkeypatch, address, expected):
    monkeypatch.setenv("NOTIFY_SOCKET", address)
    sock = Mock()
    context = Mock()
    context.__enter__ = Mock(return_value=sock)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(progress.socket, "socket", Mock(return_value=context))
    progress.notify_progress(ready=True)
    sock.connect.assert_called_once_with(expected)
    assert sock.sendall.call_args.args[0].startswith(b"READY=1\nWATCHDOG=1\n")


@pytest.mark.parametrize("outcome", ["recovered", "failed", "timeout"])
def test_tor_healing_is_bounded_and_only_successful_recheck_is_healthy(supervised, monkeypatch, outcome):
    store, _, _ = supervised
    from ttp.evidence import Result

    monkeypatch.setattr(supervisor, "request_emergency", Mock(return_value=Result()))
    supervisor.check_system_integrity.side_effect = [("tor", "unavailable"), (None, None)]
    heal = Mock(return_value=outcome == "recovered")
    if outcome == "timeout":
        heal.side_effect = progress.CheckDeadline()
    monkeypatch.setattr(supervisor, "attempt_auto_healing", heal)
    supervisor.run_supervisor()
    assert store.read("watchdog", "s")["data"]["value"] == ("healthy" if outcome == "recovered" else "emergency")
    assert heal.call_args.args == ("tor",)


def test_missing_session_identity_is_refused(supervised):
    _, lock, _ = supervised
    del lock["session_id"]
    state.LOCK_PATH.write_text(json.dumps(lock))
    with pytest.raises(StateError, match="identity"):
        supervisor.run_supervisor()


def test_corrupt_latch_contained_before_integrity_checks(supervised, monkeypatch):
    store, _, _ = supervised
    from ttp.evidence import Result

    store.write("emergency", "s", {"requested": False})
    monkeypatch.setattr(supervisor, "request_emergency", Mock(return_value=Result()))
    supervisor.run_supervisor()
    assert supervisor.request_emergency.call_args_list[0].args[1].reason == "session.evidence_invalid"
    supervisor.check_system_integrity.assert_not_called()


@pytest.mark.parametrize("watch_lost", [False, True, "unreadable", "failed"])
def test_inotify_only_readds_lost_watches_and_refuses_failed_resubscription(supervised, monkeypatch, watch_lost):
    _, _, fsm = supervised
    import struct

    from ttp.evidence import Result

    monkeypatch.setattr(supervisor, "request_emergency", Mock(return_value=Result()))
    original = supervisor.select.select.side_effect
    supervisor.select.select.side_effect = [([5], [], []), InterruptedError(), ([], [], [])]
    calls = [0]

    def select_once(*args):
        calls[0] += 1
        if calls[0] == 1:
            return [5], [], []
        if calls[0] == 2:
            raise InterruptedError()
        return original(*args)

    supervisor.select.select.side_effect = select_once
    read = Mock(return_value=struct.pack("iIII", 1, 0x400 if watch_lost in (True, "failed") else 2, 0, 0))
    if watch_lost == "unreadable":
        read.side_effect = BlockingIOError()
    monkeypatch.setattr(supervisor.os, "read", read)
    if watch_lost == "failed":
        fsm.readd_watch.side_effect = lambda: setattr(fsm, "wd_real", -1)
        with pytest.raises(StateError, match="subscription was lost"):
            supervisor.run_supervisor()
    else:
        supervisor.run_supervisor()
        assert fsm.readd_watch.call_count == int(watch_lost is True)
