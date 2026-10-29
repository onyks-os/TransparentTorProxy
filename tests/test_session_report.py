# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

import json
import os
from unittest.mock import Mock

import pytest

from ttp import session_report as report
from ttp import state
from ttp.evidence import Diagnostic, ExitCode, Result, Verification, VerificationState
from ttp.exceptions import StateError
from ttp.firewall.verification import KernelCheck
from ttp.runtime_records import RecordStore
from ttp.settings import Settings


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    store = RecordStore(tmp_path / "observations", os.getuid(), os.getgid())
    store.prepare()
    path = tmp_path / "session"
    lock = {"session_id": "s", "phase": "running", "settings": Settings().snapshot(), "watchdog_requested": False}
    path.write_text(json.dumps(lock))
    monkeypatch.setattr(state, "LOCK_PATH", path)
    monkeypatch.setattr(report, "session_store", lambda: store)
    monkeypatch.setattr("ttp.session_safety.session_store", lambda: store)
    monkeypatch.setattr("ttp.firewall.read_counters", dict)
    monkeypatch.setattr(
        "ttp.watchdog.service.watchdog_observation", lambda: {"value": "unknown", "reason": "watchdog.stale"}
    )
    return store, lock


def test_status_preserves_measurement_age_and_all_emergency_causes(recorded, monkeypatch):
    store, _ = recorded
    store.write("verification", "s", {"state": "inconclusive", "reason": "probe.timeout"})
    cause = Diagnostic(ExitCode.WATCHDOG_UNAVAILABLE, "watchdog.terminated", "watchdog", "terminate", "Stopped")
    store.write("emergency", "s", {"requested": True, "applied": True, "causes": [cause.as_dict()]})
    monkeypatch.setattr(
        report, "inspect_emergency_rules", lambda **kwargs: KernelCheck(True, "firewall.emergency_verified", "Verified")
    )
    value = report.observe_session()
    assert value["health"] == "emergency_verified" and value["session_exit_code"] == 7
    assert {item["code"] for item in value["diagnostics"]} == {5, 7}
    assert value["verification"]["scope"] == "recorded_measurement"
    assert value["verification"]["age_seconds"] >= 0


def test_corrupt_emergency_causes_are_unknown_not_healthy(recorded):
    store, _ = recorded
    store.write("emergency", "s", {"requested": True, "causes": ["not a diagnostic"]})
    value = report.observe_session()
    assert value["session_exit_code"] == 8 and value["health"] == "unknown"


def test_required_watchdog_with_no_fresh_observation_is_reported_separately(recorded):
    _, lock = recorded
    lock["watchdog_requested"] = True
    state.LOCK_PATH.write_text(json.dumps(lock))
    value = report.observe_session()
    assert value["session_exit_code"] == 5
    assert value["diagnostics"][0]["reason"] == "watchdog.stale"


@pytest.mark.parametrize("failure", [False, True])
def test_status_reports_optional_agent_response_without_changing_network(recorded, monkeypatch, failure):
    _, lock = recorded
    lock["settings"] = Settings().select(notifications=True).snapshot()
    state.LOCK_PATH.write_text(json.dumps(lock))
    rpc = Mock(return_value={"state": "accepted", "notification_id": 42})
    if failure:
        rpc.side_effect = OSError()
    monkeypatch.setattr("ttp.notifications.service.rpc", rpc)
    value = report.observe_session()
    assert value["notifications"]["state"] == ("unconfirmed" if failure else "accepted")
    assert value["session_exit_code"] == (9 if failure else 0)


def test_valid_negative_requests_emergency_even_when_evidence_write_fails(recorded, monkeypatch):
    _, lock = recorded
    monkeypatch.setattr(RecordStore, "write", Mock(side_effect=StateError("disk full")))
    contain = Mock(
        return_value=Result().add(
            Diagnostic(ExitCode.EMERGENCY_VERIFIED, "verified", "firewall", "contain", "Verified")
        )
    )
    monkeypatch.setattr(report, "request_emergency", contain)
    result = report.record_verification(
        lock, Verification(VerificationState.NEGATIVE, "tor.valid_negative", "192.0.2.1")
    )
    assert result.exit_code == 7
    assert {d.code for d in result.diagnostics} == {1, 6, 7}
    contain.assert_called_once()


def test_latched_emergency_check_never_probes_or_reopens_network(recorded, monkeypatch):
    store, _ = recorded
    store.write("emergency", "s", {"requested": True})
    monkeypatch.setattr(
        report, "inspect_emergency_rules", lambda **kwargs: KernelCheck(False, "firewall.read_failed", "Unknown")
    )
    probe = Mock()
    monkeypatch.setattr("ttp.probe.verify_session", probe)
    verification, result = report.check_session()
    assert verification.state is VerificationState.NOT_RUN and result.exit_code == 8
    probe.assert_not_called()


@pytest.mark.parametrize("contained", [7, 8])
def test_check_retains_watchdog_and_notification_failure_alongside_containment(recorded, monkeypatch, contained):
    _, lock = recorded
    lock.update(watchdog_requested=True, settings=Settings().select(notifications=True).snapshot())
    state.LOCK_PATH.write_text(json.dumps(lock))
    monkeypatch.setattr(
        "ttp.probe.verify_session", lambda **kwargs: Verification(VerificationState.CONFIRMED, "tor.confirmed")
    )
    result = Result().add(Diagnostic(ExitCode(contained), "firewall.result", "firewall", "contain", "Outcome"))
    contain = Mock(return_value=result)
    monkeypatch.setattr(report, "request_emergency", contain)
    emit = Mock(
        return_value=Result().add(
            Diagnostic(ExitCode.NOTIFICATION_FAILED, "notifications.failed", "notifications", "deliver", "Failed")
        )
    )
    monkeypatch.setattr("ttp.notifications.service.emit", emit)
    _, observed = report.check_session()
    assert observed.exit_code == contained
    assert contain.call_args.args[1].code == 5
    assert {d.code for d in observed.diagnostics} == {contained, 9}
    assert emit.call_args.args[1] == ("emergency_verified" if contained == 7 else "containment_unconfirmed")


def test_confirmed_check_emits_recovery_only_after_inconclusive_measurement(recorded, monkeypatch):
    store, lock = recorded
    lock["settings"] = Settings().select(notifications=True).snapshot()
    state.LOCK_PATH.write_text(json.dumps(lock))
    store.write("verification", "s", {"state": "inconclusive"})
    monkeypatch.setattr(
        "ttp.probe.verify_session", lambda **kwargs: Verification(VerificationState.CONFIRMED, "confirmed")
    )
    emit = Mock(return_value=Result())
    monkeypatch.setattr("ttp.notifications.service.emit", emit)
    assert report.check_session()[1].exit_code == 0
    assert emit.call_args.args[1] == "recovered"
    emit.reset_mock()
    report.check_session()
    emit.assert_not_called()
