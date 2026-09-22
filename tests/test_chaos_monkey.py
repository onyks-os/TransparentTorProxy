# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Tests for the chaos monkey's audit oracle.

The script had no tests because it could not be imported: the root check was an
unconditional ``sys.exit`` at module scope, so every test collecting this module
died on import. Moving it into :func:`require_root` is what makes the rest of
this file possible, and the reason the defects below survived as long as they
did.

The defect under test: every path through the old ``run_connectivity_audit``
that could not measure returned ``True``, and ``True`` meant "no leak". The
worst one was the baseline - ``get_real_public_ip`` returns ``None`` on failure
and the leak test was ``current_ip == real_ip``, which is false for every
possible answer when ``real_ip`` is ``None``. A genuine cleartext leak was then
printed as "Traffic is successfully proxied through Tor".
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tests.chaos_monkey import (
    INJECTIONS,
    AuditResult,
    classify_audit,
    plan_injections,
    run_connectivity_audit,
    verdict,
)

_REAL_IP = "203.0.113.7"


@pytest.mark.parametrize(
    ("real_ip", "returncode", "stdout", "expected"),
    [
        pytest.param(_REAL_IP, 0, f"OK {_REAL_IP}", AuditResult.LEAK, id="our-own-address-on-the-wan-is-a-leak"),
        pytest.param(_REAL_IP, 0, "OK 198.51.100.4", AuditResult.CONTAINED, id="a-different-address-is-an-exit-node"),
        pytest.param(_REAL_IP, 0, "NETFAIL URLError", AuditResult.CONTAINED, id="a-refused-request-is-the-killswitch"),
        pytest.param(None, 0, f"OK {_REAL_IP}", AuditResult.INCONCLUSIVE, id="no-baseline-cannot-see-its-own-address"),
        pytest.param(_REAL_IP, 127, "", AuditResult.INCONCLUSIVE, id="a-child-that-did-not-run-proves-nothing"),
        pytest.param(_REAL_IP, 0, "OK not-an-ip", AuditResult.INCONCLUSIVE, id="a-non-ip-answer-is-not-evidence"),
        pytest.param(_REAL_IP, 0, "", AuditResult.INCONCLUSIVE, id="silence-is-not-evidence"),
        pytest.param(
            _REAL_IP, 0, "Traceback (most recent call last)", AuditResult.INCONCLUSIVE, id="a-crash-is-not-evidence"
        ),
    ],
)
def test_the_audit_reports_what_it_measured_and_not_what_it_hoped(real_ip, returncode, stdout, expected) -> None:
    assert classify_audit(real_ip, returncode, stdout)[0] is expected


def test_a_missing_baseline_never_reads_as_containment() -> None:
    """The case the old code got wrong in the most dangerous direction: with no
    baseline it reported every possible answer, including the host's own
    address, as 'successfully proxied through Tor'."""
    for stdout in (f"OK {_REAL_IP}", "OK 198.51.100.4", "NETFAIL URLError", ""):
        assert classify_audit(None, 0, stdout)[0] is AuditResult.INCONCLUSIVE


def test_a_missing_baseline_does_not_even_spawn_the_child() -> None:
    """There is nothing to compare against, so there is nothing to ask."""
    with patch("tests.chaos_monkey.subprocess.run") as mock_run:
        assert run_connectivity_audit(None) is AuditResult.INCONCLUSIVE
    assert mock_run.call_count == 0


def test_an_audit_that_cannot_be_launched_is_not_a_clean_run() -> None:
    """A missing test user or a missing interpreter is a broken harness, which
    the old code caught and reported as True."""
    with patch("tests.chaos_monkey.subprocess.run", side_effect=OSError("No such file")):
        assert run_connectivity_audit(_REAL_IP) is AuditResult.INCONCLUSIVE


def test_a_leak_is_reported_through_the_public_entry_point() -> None:
    with patch("tests.chaos_monkey.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=f"OK {_REAL_IP}\n", stderr="")
        assert run_connectivity_audit(_REAL_IP) is AuditResult.LEAK


@pytest.mark.parametrize(
    ("urlopen_effect", "expected_prefix"),
    [
        pytest.param(OSError("Network is unreachable"), "NETFAIL", id="blocked-request"),
        pytest.param(None, "OK", id="successful-request"),
    ],
)
def test_the_child_reports_both_answers_on_stdout_and_exits_cleanly(urlopen_effect, expected_prefix, capsys) -> None:
    """The exit code must mean one thing only: whether the audit ran. If the
    child exited non-zero on a blocked request, the killswitch working and the
    harness breaking would be the same observation, and classify_audit could
    not separate them."""
    from tests.chaos_monkey import _AUDIT_SCRIPT

    response = MagicMock()
    response.read.return_value = b"198.51.100.4"
    kwargs = {"side_effect": urlopen_effect} if urlopen_effect else {"return_value": response}

    with patch("urllib.request.urlopen", **kwargs):
        exec(_AUDIT_SCRIPT, {})

    out = capsys.readouterr().out.strip()
    assert out.startswith(expected_prefix), out
    assert classify_audit(_REAL_IP, 0, out)[0] is not AuditResult.INCONCLUSIVE


def test_the_root_guard_is_callable_rather_than_executed_on_import() -> None:
    """The change that made every test above reachable."""
    from tests.chaos_monkey import require_root

    with patch("tests.chaos_monkey.os.geteuid", return_value=1000), pytest.raises(SystemExit) as exc:
        require_root()
    assert exc.value.code == 1

    with patch("tests.chaos_monkey.os.geteuid", return_value=0):
        assert require_root() is None


# ---------------------------------------------------------------------------
# The sweep: which faults a run actually injects
# ---------------------------------------------------------------------------


def test_the_default_plan_covers_every_injection_exactly_once() -> None:
    """`random.choice` over five faults for 60s exercised about four of them."""
    assert sorted(plan_injections()) == sorted(INJECTIONS)
    assert len(plan_injections()) == len(INJECTIONS)


def test_a_single_injection_can_be_reproduced_on_its_own() -> None:
    assert plan_injections("unmount_dns") == ["unmount_dns"]


def test_an_unknown_injection_is_refused_rather_than_silently_skipped() -> None:
    """A typo that plans nothing would report a clean run having tested nothing."""
    with pytest.raises(ValueError, match="no_such_fault"):
        plan_injections("no_such_fault")


def test_a_sweep_cut_short_is_not_a_pass() -> None:
    """The budget running out means the remaining faults were never tried."""
    code, message = verdict(planned=5, executed=3, leaks=0, inconclusive=0)
    assert code != 0
    assert "3" in message and "5" in message


def test_a_complete_clean_sweep_passes() -> None:
    code, message = verdict(planned=5, executed=5, leaks=0, inconclusive=0)
    assert code == 0
    assert "5" in message


def test_a_leak_outranks_a_complete_sweep() -> None:
    code, _ = verdict(planned=5, executed=5, leaks=1, inconclusive=0)
    assert code != 0


def test_an_audit_that_could_not_measure_outranks_a_complete_sweep() -> None:
    code, _ = verdict(planned=5, executed=5, leaks=0, inconclusive=1)
    assert code != 0


def test_a_run_that_injected_nothing_is_not_a_pass() -> None:
    code, _ = verdict(planned=5, executed=0, leaks=0, inconclusive=0)
    assert code != 0
