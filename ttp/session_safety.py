# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Serialized emergency containment and explicit termination intent.

The root-owned session lock expresses intent. The watchdog-owned record latches
an emergency but cannot clear root intent. Every network mutation rechecks that
intent under the same lock used by explicit stop, including ExecStopPost.
"""

from __future__ import annotations

import logging
from typing import Any

from ttp import firewall, state
from ttp.evidence import Diagnostic, ExitCode, Result
from ttp.exceptions import StateError
from ttp.firewall.verification import inspect_emergency_rules
from ttp.runtime_records import RecordStore, session_store

logger = logging.getLogger("ttp")
STOP_ADVICE = "Close sensitive applications before running 'sudo ttp stop'; they may reconnect outside Tor."


def _failure(reason: str, message: str) -> Diagnostic:
    return Diagnostic(ExitCode.CONTAINMENT_UNCONFIRMED, reason, "session", "contain", message)


def emergency_latched(lock: dict[str, Any], *, store: RecordStore | None = None) -> bool:
    session_id = lock.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise StateError("Session identity is missing")
    record = (store or session_store()).read("emergency", session_id)
    if record is None:
        return False
    if record["data"].get("requested") is not True:
        raise StateError("Invalid emergency latch")
    return True


def request_emergency(
    lock: dict[str, Any],
    cause: Diagnostic,
    *,
    store: RecordStore | None = None,
    repair: bool = False,
    require_despite_missing_lock: bool = False,
) -> Result:
    """Latch first, apply if necessary, then independently inspect kernel rules.

    Never clear the latch on recovery. A failed application and an independently
    verified existing ruleset are distinct observations. Failure to retain the
    latch means containment across a restart remains unconfirmed.
    """
    result = Result().add(cause)
    record_store = store or session_store()
    session_id = lock.get("session_id")
    new_cause = True
    if not isinstance(session_id, str) or not session_id:
        return result.add(_failure("session.identity_missing", "Cannot associate containment with a session"))
    from ttp.settings import Settings, SettingsError

    try:
        timeout = Settings.from_snapshot(lock["settings"]).watchdog.check_timeout if lock.get("settings") else 10
    except SettingsError:
        timeout = 10
        result = result.add(
            _failure("session.policy_invalid", "Cannot recover containment timing; using bounded defaults")
        )
    try:
        with record_store.transition(timeout=timeout):
            if state.stop_was_requested(session_id):
                return Result()
            try:
                current = state.read_lock(strict=True)
            except StateError:
                if not require_despite_missing_lock:
                    raise
                current = None
            if (current is None and not require_despite_missing_lock) or (
                current is not None and (current.get("session_id") != session_id or current.get("phase") == "stopping")
            ):
                # A stale worker must not re-arm after explicit stop or touch a
                # replacement session. Its old cause is not a current result.
                return Result()
            causes = [cause.as_dict()]
            previous_applied = None
            try:
                previous = record_store.read("emergency", session_id)
                if previous:
                    previous_applied = previous["data"].get("applied")
                    old = previous["data"].get("causes", [])
                    if not isinstance(old, list) or any(not isinstance(item, dict) for item in old):
                        raise StateError("Invalid emergency causes")
                    causes = [item for item in old if item.get("reason") != cause.reason] + causes
                    new_cause = all(item.get("reason") != cause.reason for item in old)
                    result = result.add(
                        *(Diagnostic.from_dict(item) for item in old if item.get("reason") != cause.reason)
                    )
            except (StateError, ValueError):
                result = result.add(_failure("session.evidence_invalid", "Previous emergency evidence is unreadable"))
            data: dict[str, Any] = {
                "requested": True,
                "applied": previous_applied if repair else False,
                "verified": False,
                "causes": causes,
            }
            try:
                record_store.write("emergency", session_id, data)
            except StateError:
                result = result.add(_failure("session.latch_write_failed", "Could not persist the emergency latch"))

            check = inspect_emergency_rules(timeout=timeout) if repair else None
            if check is None or not check.verified:
                data["applied"] = False
                try:
                    firewall.apply_emergency_killswitch(timeout=timeout)
                    data["applied"] = True
                except Exception as exc:
                    result = result.add(
                        Diagnostic(
                            ExitCode.ERROR,
                            "firewall.emergency_apply_failed",
                            "firewall",
                            "apply_emergency",
                            f"Emergency application failed ({type(exc).__name__})",
                        )
                    )
                check = inspect_emergency_rules(timeout=timeout)
            data["verified"] = check.verified
            result = result.add(check.diagnostic)
            data["result"] = result.as_dict()
            try:
                record_store.write("emergency", session_id, data)
            except StateError:
                result = result.add(_failure("session.evidence_write_failed", "Could not publish containment evidence"))
    except (OSError, StateError) as exc:
        result = result.add(
            _failure("session.transition_failed", f"Containment could not be serialized ({type(exc).__name__})")
        )
    if result.exit_code == ExitCode.EMERGENCY_VERIFIED:
        logger.critical("Emergency rules verified in the kernel. %s", STOP_ADVICE)
    else:
        logger.critical("CONTAINMENT UNCONFIRMED. Inspect 'ttp status' and the journal. %s", STOP_ADVICE)
    if lock.get("settings"):
        # The action and its independent verification are complete before any
        # desktop IPC. The loop never waits for desktop delivery here.
        from ttp.notifications.service import emit

        event = "emergency_verified" if result.exit_code == ExitCode.EMERGENCY_VERIFIED else "containment_unconfirmed"
        try:
            if new_cause and cause.code in (ExitCode.WATCHDOG_UNAVAILABLE, ExitCode.TOR_NEGATIVE):
                cause_event = "tor_negative" if cause.code == ExitCode.TOR_NEGATIVE else "watchdog_unavailable"
                if cause.reason != "watchdog.emergency_latched":
                    result = Result(result.diagnostics + emit(lock, cause_event, wait=False).diagnostics)
            result = Result(result.diagnostics + emit(lock, event, wait=False).diagnostics)
        except Exception:
            logger.error("notifications.enqueue_failed: optional desktop agent could not be contacted")
    return result


def mark_stopping(lock: dict[str, Any], *, store: RecordStore | None = None) -> None:
    """Publish explicit root termination intent before stopping any service."""
    record_store = store or session_store()
    record_store.prepare()
    with record_store.transition():
        current = state.read_lock(strict=True)
        if current is None or current.get("session_id") != lock.get("session_id"):
            raise StateError("Session changed before termination")
        state.update_lock_keys(phase="stopping")
        state.write_stop_marker(lock["session_id"])


def supervision_terminated(expected_session: str | None = None) -> Result:
    """Independent systemd ExecStopPost entry; never trusts cached active flags."""
    try:
        lock = state.read_lock(strict=True)
    except StateError:
        # No reliable intent means no safe serialization against explicit stop.
        # Report unknown loudly; do not advertise successful containment.
        diagnostic = _failure("session.intent_unreadable", "Cannot read supervision intent in termination handler")
        logger.critical(diagnostic.message)
        if expected_session is None:
            return Result().add(diagnostic)
        lock = None
    if expected_session is not None:
        if lock and lock.get("session_id") != expected_session:
            return Result()
        if lock is None:
            lock = {"session_id": expected_session, "watchdog_requested": True}
    if not lock or not lock.get("watchdog_requested") or lock.get("phase") == "stopping":
        return Result()
    return request_emergency(
        lock,
        Diagnostic(
            ExitCode.WATCHDOG_UNAVAILABLE,
            "watchdog.terminated",
            "watchdog",
            "terminate",
            "Required supervisor terminated; containment requested",
        ),
        repair=True,
        require_despite_missing_lock=expected_session is not None,
    )
