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
    CANARY_USER,
    INJECTIONS,
    TEST_USER,
    AuditResult,
    classify_audit,
    inject_sigkill_tor,
    is_killswitch_table,
    judge_pass,
    parse_main_pid,
    plan_injections,
    run_connectivity_audit,
    ttp_start_command,
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
        assert run_connectivity_audit(_REAL_IP, TEST_USER, "192.0.2.10") is AuditResult.INCONCLUSIVE


def test_a_leak_is_reported_through_the_public_entry_point() -> None:
    with patch("tests.chaos_monkey.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=f"OK {_REAL_IP}\n", stderr="")
        assert run_connectivity_audit(_REAL_IP, TEST_USER, "192.0.2.10") is AuditResult.LEAK


def _run_child(connect_effect=None, reply: bytes = b"HTTP/1.1 200 OK\r\n\r\n198.51.100.4"):
    """Execute the audit child in-process with its network calls stubbed; return (stdout, connect mock)."""
    import io
    import sys
    from contextlib import redirect_stdout

    from tests.chaos_monkey import _AUDIT_SCRIPT

    tls = MagicMock()
    tls.__enter__.return_value = tls
    tls.recv.side_effect = [reply, b""]
    context = MagicMock()
    context.wrap_socket.return_value = tls
    raw = MagicMock()
    raw.__enter__.return_value = raw
    connect = MagicMock(side_effect=connect_effect, return_value=raw)

    out = io.StringIO()
    with (
        patch("socket.create_connection", connect),
        patch("ssl.create_default_context", return_value=context),
        patch.object(sys, "argv", ["-c", "192.0.2.10", "api.ipify.org"]),
        redirect_stdout(out),
    ):
        exec(_AUDIT_SCRIPT, {})
    return out.getvalue().strip(), connect, context


@pytest.mark.parametrize(
    ("connect_effect", "expected_prefix"),
    [
        pytest.param(OSError("Network is unreachable"), "NETFAIL", id="blocked-request"),
        pytest.param(None, "OK", id="successful-request"),
    ],
)
def test_the_child_reports_both_answers_on_stdout_and_exits_cleanly(connect_effect, expected_prefix) -> None:
    """The exit code must mean one thing only: whether the audit ran. If the
    child exited non-zero on a blocked request, the killswitch working and the
    harness breaking would be the same observation, and classify_audit could
    not separate them."""
    out, _, _ = _run_child(connect_effect)
    assert out.startswith(expected_prefix), out
    assert classify_audit(_REAL_IP, 0, out)[0] is not AuditResult.INCONCLUSIVE


def test_the_child_connects_to_the_pre_resolved_address_and_verifies_the_name() -> None:
    """No lookup in the child: with TTP up its DNS is Tor's, so a dead Tor failed
    every audit on the name - the canary's too - and "contained" measured DNS.
    The name still has to match the certificate, so a wrong address is not
    silently asked instead."""
    out, connect, context = _run_child()
    assert connect.call_args.args[0] == ("192.0.2.10", 443)
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "api.ipify.org"
    assert out == "OK 198.51.100.4"


def test_an_audit_without_a_pre_resolved_address_is_inconclusive_and_spawns_nothing() -> None:
    with patch("tests.chaos_monkey.subprocess.run") as run:
        assert run_connectivity_audit(_REAL_IP, TEST_USER, None) is AuditResult.INCONCLUSIVE
    run.assert_not_called()


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


# ---------------------------------------------------------------------------
# Tor dying outside systemd
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        pytest.param("MainPID=4213\n", 4213, id="a-running-unit-has-a-pid"),
        pytest.param("MainPID=0\n", None, id="systemd-writes-zero-for-no-process"),
        pytest.param("", None, id="no-output-is-not-a-pid"),
        pytest.param("MainPID=\n", None, id="an-empty-value-is-not-a-pid"),
        pytest.param("MainPID=not-a-number\n", None, id="unparseable-is-not-a-pid"),
        pytest.param("MainPID=-1\n", None, id="a-negative-pid-is-not-a-pid"),
    ],
)
def test_the_tor_pid_is_read_rather_than_assumed(output, expected) -> None:
    """`kill -9 0` signals the whole process group, so a bad parse is dangerous.

    systemd writes `MainPID=0` for a unit with no process, and that value
    reaching `kill` would signal every process in the group rather than Tor.
    """
    assert parse_main_pid(output) == expected


def test_killing_tor_without_a_pid_is_an_error_rather_than_a_no_op() -> None:
    """A fault that silently did nothing would be scored as a fault that was injected."""
    completed = MagicMock(stdout="MainPID=0\n", returncode=0)
    with patch("tests.chaos_monkey.subprocess.run", return_value=completed) as run:
        with pytest.raises(RuntimeError, match="no running Tor process"):
            inject_sigkill_tor()
    assert all("kill" not in str(call.args[0][0]) for call in run.call_args_list), (
        "nothing may be killed when the PID could not be read"
    )


def test_tor_is_killed_by_signal_and_not_through_systemd() -> None:
    """The point of this fault is that systemd is not told: the unit goes to

    `failed` rather than `inactive`, and with `Restart=no` Tor stays dead. A
    `systemctl kill` would be a different, orderly thing.
    """
    completed = MagicMock(stdout="MainPID=4213\n", returncode=0)
    with patch("tests.chaos_monkey.subprocess.run", return_value=completed) as run:
        inject_sigkill_tor()

    killed = [call.args[0] for call in run.call_args_list if call.args[0][0] == "kill"]
    assert killed == [["kill", "-KILL", "4213"]], f"expected one SIGKILL to 4213, got {run.call_args_list}"


def test_the_sweep_includes_tor_dying_outside_systemd() -> None:
    """The gap docs/security-assessment.md 4.3 lists as needing no new infrastructure."""
    assert "sigkill_tor" in INJECTIONS
    assert "sigkill_tor" in plan_injections()


# ---------------------------------------------------------------------------
# The canary (#30): a bypassed user whose audit must come back as a leak.
#
# Every chaos run so far has printed [PASS]. That is what a working killswitch
# looks like, and also what an audit that cannot see a leak looks like. The
# canary is traffic TTP is configured to let out, audited by the same code in
# the same pass, so a pass is only CONTAINED if that code was shown able to
# report a leak at the time. The emergency killswitch blocks bypassed traffic
# too, by design, so there a blocked canary is the expected answer - and only
# there, which is why the table's shape is checked rather than assumed.
# ---------------------------------------------------------------------------

C, L, INC = AuditResult.CONTAINED, AuditResult.LEAK, AuditResult.INCONCLUSIVE


@pytest.mark.parametrize(
    ("containment", "canary", "killswitch", "expected"),
    [
        pytest.param(L, L, False, L, id="a-leak-is-a-leak"),
        pytest.param(L, C, True, L, id="a-leak-is-a-leak-whatever-the-canary-says"),
        pytest.param(INC, L, False, INC, id="containment-could-not-measure"),
        pytest.param(C, L, False, C, id="contained-and-the-audit-could-see-a-leak"),
        pytest.param(C, C, True, C, id="killswitch-blocks-the-canary-by-design"),
        pytest.param(C, C, False, INC, id="canary-blocked-without-a-killswitch-proves-nothing"),
        pytest.param(C, INC, False, INC, id="canary-could-not-measure"),
        pytest.param(C, INC, True, INC, id="canary-could-not-measure-even-under-killswitch"),
    ],
)
def test_a_pass_is_only_contained_if_the_canary_showed_the_audit_can_see_a_leak(
    containment, canary, killswitch, expected
) -> None:
    result, reason = judge_pass(containment, canary, killswitch)
    assert result is expected, reason
    assert reason


def test_the_killswitch_table_is_recognised_by_its_shape() -> None:
    killswitch = """table inet ttp {
\tchain filter_out {
\t\ttype filter hook output priority filter; policy drop;
\t\toifname "lo" accept
\t}
\tchain filter_forward {
\t\ttype filter hook forward priority filter; policy drop;
\t}
\tchain filter_input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiifname "lo" accept
\t}
}"""
    session = """table inet ttp {
\tchain output {
\t\ttype nat hook output priority -150; policy accept;
\t}
\tchain filter_out {
\t\ttype filter hook output priority filter; policy accept;
\t\tcounter name "cleartext_rejected" reject
\t}
}"""
    assert is_killswitch_table(killswitch)
    assert not is_killswitch_table(session)
    assert not is_killswitch_table("")


def test_only_the_canary_is_bypassed() -> None:
    """The two audits are only meaningful as a pair: one let out, one held."""
    argv = ttp_start_command()
    assert argv[:2] == ["ttp", "start"]
    assert "--watchdog" in argv
    bypassed = [argv[i + 1] for i, a in enumerate(argv) if a == "--bypass-user"]
    assert bypassed == [CANARY_USER]
    assert TEST_USER not in argv
