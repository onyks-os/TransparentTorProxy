# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Shared observation model for CLI readers and explicitly requested checks."""

from __future__ import annotations

from typing import Any

from ttp import state
from ttp.evidence import Diagnostic, ExitCode, Result, Verification, VerificationState, boottime
from ttp.exceptions import StateError
from ttp.firewall.verification import inspect_emergency_rules
from ttp.runtime_records import session_store
from ttp.session_safety import emergency_latched, request_emergency
from ttp.settings import Settings, load_settings


def session_settings(lock: dict[str, Any] | None) -> Settings:
    # A legacy session has no frozen policy. Observe it conservatively using
    # defaults; never import changed administrator policy into a running session.
    return Settings.from_snapshot(lock["settings"]) if lock and lock.get("settings") is not None else Settings()


def record_verification(lock: dict[str, Any], verification: Verification) -> Result:
    result = verification.result
    try:
        session_store().write(
            "verification",
            lock["session_id"],
            {
                "state": verification.state.value,
                "reason": verification.reason,
                "observed_at": verification.observed_at,
                "ip": verification.ip,
                "result": result.as_dict(),
            },
        )
    except (StateError, KeyError):
        result = result.add(
            Diagnostic(
                ExitCode.ERROR,
                "session.verification_write_failed",
                "session",
                "verify",
                "Could not retain verification evidence",
            )
        )
    if verification.state is VerificationState.NEGATIVE:
        result = Result(
            result.diagnostics
            + request_emergency(
                lock,
                Diagnostic(
                    ExitCode.TOR_NEGATIVE,
                    "tor.valid_negative",
                    "tor",
                    "verify",
                    "A non-exempt verification request returned IsTor=false",
                ),
            ).diagnostics
        )
    return result


def observe_session() -> dict[str, Any]:
    """Read-only: no network request, healing, teardown or intent rewriting."""
    lock = state.read_lock(strict=True)
    if lock is None:
        from ttp.vpn_guard import INTENT

        if INTENT.exists():
            return {
                "phase": "protection_retained",
                "health": "unknown",
                "session_exit_code": 10,
                "vpn": {"required": True, "state": "unknown", "guard_verified": False},
                "diagnostics": [
                    Diagnostic(
                        ExitCode.VPN_UNAVAILABLE,
                        "vpn.startup_retained",
                        "vpn",
                        "observe",
                        "VPN startup protection may remain; inspect and use ttp stop --restore-only",
                    ).as_dict()
                ],
            }
        return {"phase": "absent", "health": "unknown", "diagnostics": [], "session_exit_code": 0}
    from ttp.watchdog.service import watchdog_observation

    settings = session_settings(lock)
    from ttp import firewall
    from ttp.tor_detect import is_ipv6_supported

    report: dict[str, Any] = {
        "phase": lock.get("phase", "recorded"),
        "health": "unknown",
        "session_id": lock.get("session_id"),
        "started": lock.get("timestamp"),
        "transport_port": lock.get("transport_port", 9041),
        "dns_port": lock.get("dns_port", 9054),
        "watchdog_requested": lock.get("watchdog_requested", False),
        "watchdog": watchdog_observation(),
        "verification": {"state": "not_run"},
        "emergency": {"requested": False, "applied": None, "verified": None},
        "notifications_requested": settings.notifications.enabled,
        "lan_bypass": lock.get("lan_bypass", True),
        "allow_root": lock.get("allow_root", False),
        "ipv6": "Disabled (Force Dropped)"
        if lock.get("no_ipv6")
        else ("Enabled (Redirect configured)" if is_ipv6_supported() else "Not supported by host"),
        "rejected_packets": firewall.read_counters().get("cleartext_rejected"),
    }
    result = Result()
    session_id = lock.get("session_id")
    if not session_id:
        report["reason"] = "session.legacy_observations_unavailable"
    else:
        store = session_store()
        try:
            record = store.read("verification", session_id)
            if record:
                data = dict(record["data"])
                data["age_seconds"] = max(0, boottime() - record["written_at"])
                data["scope"] = "recorded_measurement"
                report["verification"] = data
            if emergency_latched(lock, store=store):
                emergency = store.read("emergency", session_id)
                assert emergency is not None
                try:
                    result = result.add(*(Diagnostic.from_dict(item) for item in emergency["data"].get("causes", [])))
                except (TypeError, ValueError) as exc:
                    raise StateError("Emergency causes are invalid") from exc
                check = inspect_emergency_rules(timeout=settings.watchdog.check_timeout)
                report["emergency"] = {**emergency["data"], "verified": check.verified, "reason": check.reason}
                result = result.add(check.diagnostic)
                report["health"] = "emergency_verified" if check.verified else "containment_unconfirmed"
        except StateError:
            result = result.add(
                Diagnostic(
                    ExitCode.CONTAINMENT_UNCONFIRMED,
                    "session.evidence_invalid",
                    "session",
                    "observe",
                    "Emergency or verification evidence is unreadable",
                )
            )
            report["health"] = "unknown"
    if lock.get("watchdog_requested") and report["watchdog"]["value"] not in ("healthy", "emergency"):
        result = result.add(
            Diagnostic(
                ExitCode.WATCHDOG_UNAVAILABLE,
                report["watchdog"]["reason"],
                "watchdog",
                "observe",
                "Required supervision has no current operational evidence",
            )
        )
    report["notifications"] = {"state": "disabled"}
    if settings.notifications.enabled:
        from ttp.notifications.service import rpc

        try:
            report["notifications"] = rpc(lock, "status", timeout=1)
        except Exception:
            report["notifications"] = {"state": "unconfirmed", "reason": "notifications.agent_unavailable"}
            result = result.add(
                Diagnostic(
                    ExitCode.NOTIFICATION_FAILED,
                    "notifications.agent_unavailable",
                    "notifications",
                    "observe",
                    "No current notification agent response",
                )
            )
    report["diagnostics"] = result.as_dict()["diagnostics"]
    if lock.get("apparmor") is not None:
        from ttp.apparmor import observe as observe_apparmor

        report["apparmor"] = observe_apparmor(lock["apparmor"], lock.get("tor_uid"))
        if report["apparmor"]["state"] != "enforced":
            result = result.add(
                Diagnostic(
                    ExitCode.ERROR,
                    report["apparmor"]["reason"],
                    "apparmor",
                    "observe",
                    "Required Tor AppArmor confinement has no current evidence",
                )
            )
        report["diagnostics"] = result.as_dict()["diagnostics"]
    if lock.get("vpn") is not None:
        from ttp.vpn import VPNPolicy, observe

        try:
            policy = VPNPolicy.from_snapshot(lock["vpn"])
            report["vpn"] = {
                "required": True,
                "uuid": policy.uuid,
                "interface": policy.interface,
                **observe(policy, lock["tor_uid"]),
            }
        except Exception:
            report["vpn"] = {
                "required": True,
                "state": "unknown",
                "reason": "vpn.evidence_invalid",
                "guard_verified": False,
            }
        if report["vpn"]["state"] != "constrained":
            result = result.add(
                Diagnostic(
                    ExitCode.VPN_UNAVAILABLE,
                    report["vpn"]["reason"],
                    "vpn",
                    "observe",
                    "Required VPN path has no current evidence",
                )
            )
        report["diagnostics"] = result.as_dict()["diagnostics"]
    report["session_exit_code"] = int(result.exit_code)
    return report


def check_session() -> tuple[Verification, Result]:
    from ttp.probe import verify_session

    lock = state.read_lock(strict=True)
    if lock is None:
        from ttp.vpn_guard import INTENT

        if INTENT.exists():
            cause = Diagnostic(
                ExitCode.VPN_UNAVAILABLE,
                "vpn.startup_retained",
                "vpn",
                "check",
                "Recover retained VPN startup protection before requesting a probe",
            )
            return Verification(VerificationState.NOT_RUN, cause.reason), Result((cause,))
    settings = session_settings(lock) if lock else load_settings().settings
    if lock and lock.get("session_id") and emergency_latched(lock):
        verification = Verification(VerificationState.NOT_RUN, "session.emergency_latched")
        report = observe_session()
        return verification, Result(tuple(Diagnostic.from_dict(item) for item in report["diagnostics"]))
    if lock and lock.get("apparmor") is not None:
        from ttp.apparmor import observe as observe_apparmor

        if observe_apparmor(lock["apparmor"], lock.get("tor_uid"))["state"] != "enforced":
            cause = Diagnostic(
                ExitCode.ERROR,
                "apparmor.confinement_unverified",
                "apparmor",
                "check",
                "Required Tor AppArmor confinement is unavailable",
            )
            return Verification(VerificationState.NOT_RUN, cause.reason), request_emergency(lock, cause)
    if lock and lock.get("vpn") is not None:
        report = observe_session()
        if report["vpn"]["state"] != "constrained":
            cause = Diagnostic(
                ExitCode.VPN_UNAVAILABLE,
                "vpn.required_path_unavailable",
                "vpn",
                "check",
                "Required VPN path is unavailable",
            )
            return Verification(VerificationState.NOT_RUN, cause.reason), request_emergency(lock, cause)
    previous = session_store().read("verification", lock["session_id"]) if lock and lock.get("session_id") else None
    verification = verify_session(timeout=settings.verification.timeout, lock=lock)
    result = record_verification(lock, verification) if lock else verification.result
    if lock and lock.get("watchdog_requested"):
        from ttp.watchdog.service import watchdog_observation

        if watchdog_observation()["value"] not in ("healthy", "emergency"):
            result = Result(
                result.diagnostics
                + request_emergency(
                    lock,
                    Diagnostic(
                        ExitCode.WATCHDOG_UNAVAILABLE,
                        "watchdog.unavailable",
                        "watchdog",
                        "check",
                        "Required supervisor has no current operational evidence",
                    ),
                ).diagnostics
            )
    if lock and settings.notifications.enabled:
        from ttp.notifications.service import emit

        event = "inconclusive" if not verification.confirmed else None
        if verification.confirmed and previous and previous["data"].get("state") == "inconclusive":
            event = "recovered"
        if result.exit_code == ExitCode.EMERGENCY_VERIFIED:
            event = "emergency_verified"
        elif result.exit_code == ExitCode.CONTAINMENT_UNCONFIRMED:
            event = "containment_unconfirmed"
        if event:
            result = Result(result.diagnostics + emit(lock, event).diagnostics)
    return verification, result
