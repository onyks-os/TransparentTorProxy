# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""A single sample taken while a live supervisor evaluates is not its absence.

The supervisor publishes "unknown" while it runs each periodic check and after
every netlink/inotify event until it has re-evaluated. `ttp check` sampled once
and, when it hit one of those windows, latched emergency containment on a
healthy session (2 of ~56 VPN VM runs in CI; the watchdog then reported the
emergency table as a firewall integrity failure).
"""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from ttp import session_report as report
from ttp import state
from ttp.evidence import Verification, VerificationState
from ttp.settings import Settings, WatchdogSettings
from ttp.watchdog import service

PENDING = {"value": "unknown", "reason": "watchdog.evaluation_pending", "pid": 7}
INVALIDATED = {"value": "unknown", "reason": "watchdog.event_invalidated", "pid": 7}
HEALING = {"value": "unknown", "reason": "watchdog.tor_healing", "pid": 7}
HEALTHY = {"value": "healthy", "reason": "watchdog.local_integrity_verified", "pid": 7}


class Clock:
    def __init__(self):
        self.now = 0.0

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    value = Clock()
    monkeypatch.setattr(service.time, "monotonic", lambda: value.now)
    monkeypatch.setattr(service.time, "sleep", value.sleep)
    return value


def observations(monkeypatch, *values, then=None):
    sequence = list(values)

    def observe():
        return sequence.pop(0) if sequence else (then or values[-1])

    monkeypatch.setattr(service, "watchdog_observation", observe)


@pytest.mark.parametrize("transient", [PENDING, INVALIDATED, HEALING])
def test_an_in_progress_supervisor_is_waited_for(monkeypatch, clock, transient):
    observations(monkeypatch, transient, transient, HEALTHY)
    assert service.settled_watchdog_observation(WatchdogSettings())["value"] == "healthy"
    assert 0 < clock.now < 1


def test_the_wait_is_bounded_by_the_supervisor_contract(monkeypatch, clock):
    settings = WatchdogSettings(check_timeout=10, heartbeat_interval=5)
    observations(monkeypatch, PENDING)
    assert service.settled_watchdog_observation(settings) == PENDING
    assert 25 <= clock.now < 26  # 2 * check_timeout + heartbeat_interval


@pytest.mark.parametrize(
    "observed",
    [
        {"value": "unknown", "reason": "watchdog.progress_stale", "pid": None},
        {"value": "unknown", "reason": "watchdog.observation_unavailable", "pid": None},
        {"value": "unknown", "reason": "watchdog.integrity_stale", "pid": 7},
        {"value": "unavailable", "reason": "watchdog.unit_not_active", "pid": None},
        {"value": "emergency", "reason": "watchdog.emergency_latched", "pid": 7},
        HEALTHY,
    ],
)
def test_settled_or_absent_evidence_is_returned_without_waiting(monkeypatch, clock, observed):
    observations(monkeypatch, observed, then={"value": "healthy"})
    assert service.settled_watchdog_observation(WatchdogSettings()) == observed
    assert clock.now == 0


@pytest.fixture
def supervised(tmp_path, monkeypatch):
    from ttp.runtime_records import RecordStore

    store = RecordStore(tmp_path / "observations", *_ids())
    store.prepare()
    path = tmp_path / "session"
    lock = {"session_id": "s", "phase": "running", "settings": Settings().snapshot(), "watchdog_requested": True}
    path.write_text(json.dumps(lock))
    monkeypatch.setattr(state, "LOCK_PATH", path)
    monkeypatch.setattr(report, "session_store", lambda: store)
    monkeypatch.setattr("ttp.session_safety.session_store", lambda: store)
    monkeypatch.setattr("ttp.firewall.read_counters", dict)
    monkeypatch.setattr(
        "ttp.probe.verify_session", lambda **kwargs: Verification(VerificationState.CONFIRMED, "probe.tor_confirmed")
    )
    contain = Mock()
    monkeypatch.setattr(report, "request_emergency", contain)
    return contain


def _ids():
    import os

    return os.getuid(), os.getgid()


def test_check_on_a_healthy_session_mid_evaluation_requests_no_emergency(supervised, monkeypatch, clock):
    observations(monkeypatch, PENDING, INVALIDATED, HEALTHY)
    verification, result = report.check_session()
    assert verification.confirmed and result.exit_code == 0
    supervised.assert_not_called()


def test_check_still_contains_a_supervisor_that_never_completes(supervised, monkeypatch, clock):
    from ttp.evidence import Result

    supervised.return_value = Result()
    observations(monkeypatch, PENDING)
    report.check_session()
    assert supervised.call_args.args[1].reason == "watchdog.unavailable"
    assert clock.now >= 25


def test_watchdog_start_tolerates_an_event_right_after_readiness(monkeypatch, clock, tmp_path):
    lock = {"session_id": "s", "settings": Settings().snapshot()}
    monkeypatch.setattr(state, "read_lock", lambda **kwargs: dict(lock))
    monkeypatch.setattr(state, "update_lock_keys", Mock())
    monkeypatch.setattr(service, "session_store", lambda: Mock())
    monkeypatch.setattr(service, "_write_watchdog_service_unit", Mock())
    monkeypatch.setattr(service.subprocess, "run", Mock())
    monkeypatch.setattr("ttp.session_safety.emergency_latched", lambda *a, **k: False)
    observations(monkeypatch, INVALIDATED, HEALTHY)
    service.start_watchdog()
    state.update_lock_keys.assert_called_with(watchdog_active=True, watchdog_pid=7)
