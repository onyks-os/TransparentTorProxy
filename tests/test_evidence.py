# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

import itertools
import json
import math
from dataclasses import replace

import pytest

from ttp.evidence import Diagnostic, ExitCode, Observation, Result, Verification, VerificationState, boottime


def test_all_simultaneous_errors_survive_principal_result_selection():
    watchdog = Diagnostic(ExitCode.WATCHDOG_UNAVAILABLE, "watchdog.readiness_timeout", "watchdog", "start", "not ready")
    isolation = Diagnostic(ExitCode.CONTAINMENT_UNCONFIRMED, "firewall.apply_denied", "firewall", "apply", "denied")
    notification = Diagnostic(
        ExitCode.NOTIFICATION_FAILED, "notification.no_server", "notification", "send", "no server"
    )
    for order in itertools.permutations((watchdog, isolation, notification)):
        result = Result().add(*order)
        assert result.exit_code == 8
        assert result.diagnostics == order
        encoded = json.loads(json.dumps(result.as_dict()))
        assert len(encoded["diagnostics"]) == 3
        assert encoded["exit_code"] == 8


@pytest.mark.parametrize("stronger,weaker", [(8, 7), (7, 6), (6, 5), (5, 9), (9, 3), (3, 0)])
def test_session_precedence_is_explicit_not_numeric(stronger, weaker):
    result = Result(tuple(Diagnostic(ExitCode(code), str(code), "test", "check", "") for code in (weaker, stronger)))
    assert result.exit_code == stronger


def test_empty_report_is_success_and_extension_preserves_previous_report():
    initial = Result()
    updated = initial.add(Diagnostic(ExitCode.ERROR, "config.invalid", "config", "load", "unknown key"))
    assert initial.exit_code == 0
    assert initial.diagnostics == ()
    assert updated.exit_code == 1


@pytest.mark.parametrize(
    "state,code",
    [
        (VerificationState.CONFIRMED, 0),
        (VerificationState.NEGATIVE, 6),
        (VerificationState.INCONCLUSIVE, 3),
        (VerificationState.NOT_RUN, 3),
    ],
)
def test_verification_uncertainty_is_not_a_negative_verdict(state, code):
    observed = Verification(state, "tor.example", observed_at=12)
    assert observed.confirmed is (state is VerificationState.CONFIRMED)
    assert observed.result.exit_code == code


@pytest.mark.parametrize("field,new", [("session_id", "old"), ("boot_id", "old"), ("instance_id", "old")])
def test_previous_process_session_or_boot_never_attests_current_health(field, new):
    observation = replace(Observation("ready", "session", "boot", "instance", 100), **{field: new})
    assert not observation.is_current(session_id="session", boot_id="boot", instance_id="instance", now=101, max_age=30)


@pytest.mark.parametrize("now,valid", [(99, False), (100, True), (129.9, True), (130, False), (math.nan, False)])
def test_stale_future_or_invalid_observations_do_not_attest_health(now, valid):
    observed = Observation("ready", "session", "boot", "instance", 100)
    assert (
        observed.is_current(session_id="session", boot_id="boot", instance_id="instance", now=now, max_age=30) is valid
    )


@pytest.mark.parametrize("max_age", [0, -1, math.inf])
def test_age_budget_must_be_valid(max_age):
    observed = Observation("ready", "session", "boot", "instance", 100)
    assert not observed.is_current(
        session_id="session", boot_id="boot", instance_id="instance", now=101, max_age=max_age
    )


def test_unidentified_service_does_not_attest_health():
    assert not Observation("ready", "", "", "", 100).is_current(
        session_id="", boot_id="", instance_id="", now=101, max_age=30
    )


def test_observation_clock_is_suspend_aware(monkeypatch):
    calls = []
    monkeypatch.setattr("ttp.evidence.time.clock_gettime", lambda clock: calls.append(clock) or 123.5)
    import time

    assert boottime() == 123.5
    assert calls == [time.CLOCK_BOOTTIME]


@pytest.mark.parametrize("mutation", [{"operation": None}, {"active": "true"}])
def test_diagnostic_decode_refuses_malformed_fields(mutation):
    from ttp.evidence import Diagnostic, ExitCode

    value = Diagnostic(ExitCode.WATCHDOG_UNAVAILABLE, "missing", "watchdog", "start", "Unavailable").as_dict()
    with pytest.raises(ValueError):
        Diagnostic.from_dict({**value, **mutation})
    assert value["phase"] == "startup"
