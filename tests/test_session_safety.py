# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

import json
import os
from unittest.mock import Mock

import pytest

from ttp import session_safety as safety
from ttp import state
from ttp.evidence import Diagnostic, ExitCode
from ttp.exceptions import StateError
from ttp.firewall.verification import KernelCheck
from ttp.runtime_records import RecordStore

CAUSE = Diagnostic(ExitCode.WATCHDOG_UNAVAILABLE, "watchdog.terminated", "watchdog", "terminate", "Supervisor lost")
VERIFIED = KernelCheck(True, "firewall.emergency_verified", "Verified")
UNKNOWN = KernelCheck(False, "firewall.emergency_read_failed", "Unknown")


@pytest.fixture
def session(tmp_path, monkeypatch):
    store = RecordStore(tmp_path / "evidence", os.getuid(), os.getgid())
    store.prepare()
    path = tmp_path / "lock"
    lock = {"session_id": "session", "phase": "running", "watchdog_requested": True}
    path.write_text(json.dumps(lock))
    monkeypatch.setattr(state, "LOCK_PATH", path)
    monkeypatch.setattr(state, "LOCK_DIR", tmp_path)
    monkeypatch.setattr(safety, "session_store", lambda: store)
    monkeypatch.setattr(
        state, "_write_lock_file", lambda data, **kwargs: kwargs.get("path", path).write_text(json.dumps(data))
    )
    monkeypatch.setattr(safety, "inspect_emergency_rules", Mock(return_value=VERIFIED))
    monkeypatch.setattr(safety.firewall, "apply_emergency_killswitch", Mock())
    return store, lock


def test_latch_precedes_application_and_verification_is_independent(session):
    store, lock = session

    def apply(*, timeout):
        assert timeout == 10
        record = store.read("emergency", "session")["data"]
        assert record["requested"] and not record["verified"] and not record["applied"]

    safety.firewall.apply_emergency_killswitch.side_effect = apply
    result = safety.request_emergency(lock, CAUSE)
    assert result.exit_code == 7
    assert {d.code for d in result.diagnostics} == {5, 7}
    data = store.read("emergency", "session")["data"]
    assert data["requested"] and data["applied"] and data["verified"]
    assert safety.emergency_latched(lock)


def test_failed_application_never_announces_isolation_without_evidence(session, caplog):
    _, lock = session
    safety.firewall.apply_emergency_killswitch.side_effect = RuntimeError("failure")
    safety.inspect_emergency_rules.return_value = UNKNOWN
    result = safety.request_emergency(lock, CAUSE)
    assert result.exit_code == 8
    assert "CONTAINMENT UNCONFIRMED" in caplog.text
    assert "Emergency rules verified" not in caplog.text
    assert {d.reason for d in result.diagnostics} >= {"watchdog.terminated", "firewall.emergency_apply_failed"}


def test_existing_verified_rules_survive_failed_reapplication(session):
    store, lock = session
    safety.firewall.apply_emergency_killswitch.side_effect = RuntimeError("failure")
    assert safety.request_emergency(lock, CAUSE).exit_code == 7
    data = store.read("emergency", "session")["data"]
    assert not data["applied"] and data["verified"]


def test_restart_keeps_latch_and_does_not_rewrite_valid_emergency_rules(session):
    store, lock = session
    safety.request_emergency(lock, CAUSE)
    safety.firewall.apply_emergency_killswitch.reset_mock()
    result = safety.supervision_terminated()
    assert result.exit_code == 7
    safety.firewall.apply_emergency_killswitch.assert_not_called()
    assert len(store.read("emergency", "session")["data"]["causes"]) == 1


def test_restart_repairs_tampered_emergency_rules(session):
    _, lock = session
    safety.request_emergency(lock, CAUSE)
    safety.inspect_emergency_rules.side_effect = [UNKNOWN, VERIFIED]
    safety.firewall.apply_emergency_killswitch.reset_mock()
    assert safety.supervision_terminated().exit_code == 7
    safety.firewall.apply_emergency_killswitch.assert_called_once()


@pytest.mark.parametrize(
    "new_lock", [None, {"session_id": "replacement"}, {"session_id": "session", "phase": "stopping"}]
)
def test_delayed_emergency_cannot_rearm_after_stop_or_touch_replacement(session, new_lock):
    store, lock = session
    if new_lock is None:
        state.LOCK_PATH.unlink()
    else:
        state.LOCK_PATH.write_text(json.dumps(new_lock))
    assert safety.request_emergency(lock, CAUSE).exit_code == 0
    safety.firewall.apply_emergency_killswitch.assert_not_called()
    assert store.read("emergency", "session") is None


def test_explicit_stop_marks_intent_before_service_termination(session):
    _, lock = session
    safety.mark_stopping(lock)
    assert state.read_lock()["phase"] == "stopping"
    assert safety.supervision_terminated().exit_code == 0
    safety.firewall.apply_emergency_killswitch.assert_not_called()


@pytest.mark.parametrize("corrupt", [False, True])
def test_independent_handler_uses_unit_identity_if_active_lock_is_lost(session, corrupt):
    store, _ = session
    if corrupt:
        state.LOCK_PATH.write_text("{")
    else:
        state.LOCK_PATH.unlink()
    safety.inspect_emergency_rules.side_effect = [UNKNOWN, VERIFIED]
    result = safety.supervision_terminated("session")
    assert result.exit_code == 7
    safety.firewall.apply_emergency_killswitch.assert_called_once()
    assert store.read("emergency", "session")["data"]["requested"]


def test_stop_marker_prevents_late_handler_rearming_after_lock_removal(session):
    _, lock = session
    safety.mark_stopping(lock)
    state.LOCK_PATH.unlink()
    assert safety.supervision_terminated("session").exit_code == 0
    safety.firewall.apply_emergency_killswitch.assert_not_called()


def test_old_service_handler_never_touches_replacement_session(session):
    assert safety.supervision_terminated("previous-session").exit_code == 0
    safety.firewall.apply_emergency_killswitch.assert_not_called()


def test_concurrent_transition_prevents_unsafe_stop(session, monkeypatch):
    store, lock = session
    original = RecordStore.transition
    monkeypatch.setattr(RecordStore, "transition", lambda self: original(self, timeout=0.01))
    with original(store):
        with pytest.raises(StateError, match="Timed out"):
            safety.mark_stopping(lock)
    assert state.read_lock()["phase"] == "running"


def test_stop_rejects_changed_session(session):
    _, lock = session
    state.LOCK_PATH.unlink()
    with pytest.raises(StateError, match="Session changed"):
        safety.mark_stopping(lock)


def test_failed_latch_storage_attempts_containment_but_cannot_claim_restart_safety(session, monkeypatch):
    _, lock = session
    monkeypatch.setattr(RecordStore, "write", Mock(side_effect=StateError("disk full")))
    result = safety.request_emergency(lock, CAUSE)
    assert result.exit_code == 8
    safety.firewall.apply_emergency_killswitch.assert_called_once()
    assert {d.reason for d in result.diagnostics} >= {"session.latch_write_failed", "session.evidence_write_failed"}


def test_corrupt_latch_requests_emergency_instead_of_silent_recovery(session):
    store, lock = session
    store.write("emergency", "session", {"requested": True, "causes": ["bad"]})
    assert safety.request_emergency(lock, CAUSE).exit_code == 8
    assert safety.emergency_latched(lock)


def test_unreadable_intent_is_unknown_not_success_or_cleartext_recovery(session):
    _, lock = session
    state.LOCK_PATH.write_text("{")
    assert safety.supervision_terminated().exit_code == 8
    assert safety.request_emergency(lock, CAUSE).exit_code == 8
    safety.firewall.apply_emergency_killswitch.assert_not_called()


def test_missing_identity_is_not_accepted(session):
    with pytest.raises(StateError, match="identity"):
        safety.emergency_latched({})
    assert safety.request_emergency({}, CAUSE).exit_code == 8


def test_invalid_latch_is_not_absent(session):
    store, lock = session
    assert not safety.emergency_latched(lock)
    store.write("emergency", "session", {"requested": False})
    with pytest.raises(StateError, match="latch"):
        safety.emergency_latched(lock)


def test_multiple_incident_causes_are_retained(session):
    store, lock = session
    safety.request_emergency(lock, CAUSE)
    other = Diagnostic(ExitCode.TOR_NEGATIVE, "tor.negative", "tor", "verify", "Valid negative")
    safety.request_emergency(lock, other)
    assert {d["reason"] for d in store.read("emergency", "session")["data"]["causes"]} == {CAUSE.reason, other.reason}


@pytest.mark.parametrize("lock", [None, {"watchdog_requested": False}])
def test_termination_without_supervision_requirement_does_not_touch_network(session, lock):
    if lock is None:
        state.LOCK_PATH.unlink()
    else:
        state.LOCK_PATH.write_text(json.dumps(lock))
    assert safety.supervision_terminated().exit_code == 0
    safety.firewall.apply_emergency_killswitch.assert_not_called()


def test_optional_emergency_publication_failure_does_not_undo_containment(session, monkeypatch, caplog):
    _, lock = session
    from ttp.settings import Settings

    lock["settings"] = Settings().select(notifications=True).snapshot()
    monkeypatch.setattr("ttp.notifications.service.emit", Mock(side_effect=OSError("IPC failed")))
    assert safety.request_emergency(lock, CAUSE).exit_code == 7
    assert "notifications.enqueue_failed" in caplog.text


def test_corrupt_policy_does_not_prevent_bounded_containment_attempt(session, monkeypatch):
    _, lock = session
    lock["settings"] = {"invalid": True}
    monkeypatch.setattr(
        "ttp.notifications.service.emit", Mock(return_value=__import__("ttp.evidence", fromlist=["Result"]).Result())
    )
    result = safety.request_emergency(lock, CAUSE)
    assert result.exit_code == 8
    assert any(d.reason == "session.policy_invalid" for d in result.diagnostics)
    safety.firewall.apply_emergency_killswitch.assert_called_once_with(timeout=10)
