# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Tests for the leak probes' verdict layer.

The probes in ``tests/leak/`` are excluded from the default suite - they need a
live session and real egress. The code that decides whether they passed is not,
and that is deliberate: the oracle is the part that was wrong, so it is the part
that has to be exercised on every commit.

The property under test throughout is the one the old inline oracles lacked:
**there must be no path to a safe answer that does not go through evidence.**
"""

from __future__ import annotations

import json

import pytest

from tests.leak.oracle import (
    SCHEMA_VERSION,
    Observation,
    Outcome,
    Verdict,
    assert_contained,
    read_verdict,
    record,
    verdict_for,
)


def _obs(outcome: Outcome, *, session: bool = True, probe: str = "probe") -> Observation:
    return Observation(probe=probe, target="1.1.1.1:53", outcome=outcome, session_active=session)


# ---------------------------------------------------------------------------
# verdict_for
# ---------------------------------------------------------------------------


def test_a_blocked_packet_is_the_only_socket_outcome_that_proves_containment() -> None:
    """A refusal or a drop is decisive: something stopped the packet leaving."""
    verdict, _ = verdict_for(_obs(Outcome.BLOCKED))
    assert verdict is Verdict.CONTAINED


def test_a_well_formed_answer_does_not_prove_containment() -> None:
    """The regression this whole module exists for.

    The old probe asserted the response was a valid DNS reply with a matching
    transaction ID and called that "safely intercepted". Cloudflare sends
    exactly that reply when the query leaks to it in cleartext, so the
    assertion was true in both worlds and distinguished neither.
    """
    verdict, reason = verdict_for(_obs(Outcome.ANSWERED))
    assert verdict is Verdict.INCONCLUSIVE
    assert "cannot tell them apart" in reason


def test_an_answer_with_proof_of_its_origin_does_prove_containment() -> None:
    """The outcome #38 will produce once the redirect rule carries a counter."""
    verdict, _ = verdict_for(_obs(Outcome.ANSWERED_BY_PROXY))
    assert verdict is Verdict.CONTAINED


@pytest.mark.parametrize("outcome", list(Outcome))
def test_no_outcome_is_ever_containment_without_a_session(outcome: Outcome) -> None:
    """Without a session there is no TTP to credit.

    A blocked packet on a host with no TTP session was blocked by something
    else - a corporate firewall, an unplugged cable - and scoring that as
    CONTAINED is how a leak suite passes on a machine where the product is not
    even installed. Parametrised over every outcome so a new one cannot be
    added that quietly skips this check.
    """
    verdict, reason = verdict_for(_obs(outcome, session=False))
    assert verdict is Verdict.INCONCLUSIVE
    assert "no active TTP session" in reason


def test_an_answer_only_the_target_could_have_sent_is_a_leak() -> None:
    """`Verdict.LEAK` must be reachable.

    A verdict no code path can produce is the same defect this module exists to
    remove, one level smaller: an enum member that looks like a possible outcome
    and never is. The STUN probe is what produces it - TTP does not redirect
    UDP/19302 at all, so any reply proves the packet left the machine.
    """
    verdict, reason = verdict_for(_obs(Outcome.ESCAPED))
    assert verdict is Verdict.LEAK
    assert "left the machine" in reason


def test_an_unreachable_probe_is_inconclusive_not_contained() -> None:
    verdict, _ = verdict_for(_obs(Outcome.UNREACHABLE))
    assert verdict is Verdict.INCONCLUSIVE


def test_a_probe_that_never_ran_is_inconclusive() -> None:
    verdict, _ = verdict_for(_obs(Outcome.NOT_ATTEMPTED))
    assert verdict is Verdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# The artifact
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _artifacts_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr("tests.leak.oracle.ARTIFACT_DIR", tmp_path)
    return tmp_path


def test_the_artifact_records_what_was_observed_and_what_was_concluded(_artifacts_in_tmp) -> None:
    path = record(_obs(Outcome.BLOCKED, probe="dns_v4"))
    payload = json.loads(path.read_text())

    assert payload["schema"] == SCHEMA_VERSION
    assert payload["probe"] == "dns_v4"
    assert payload["outcome"] == "blocked"
    assert payload["verdict"] == "contained"
    assert payload["reason"]
    assert payload["observed_at"]  # when, not just what


def test_a_missing_artifact_is_inconclusive(tmp_path) -> None:
    """An exception cannot produce an artifact, so a crashed probe lands here.

    This is the structural half of the design: the safe answer is unreachable
    by accident, not merely discouraged.
    """
    verdict, reason = read_verdict(tmp_path / "never-written.json")
    assert verdict is Verdict.INCONCLUSIVE
    assert "could not be read" in reason


def test_an_unparseable_artifact_is_inconclusive(tmp_path) -> None:
    path = tmp_path / "truncated.json"
    path.write_text('{"schema": 1, "verdict": "contai')
    verdict, reason = read_verdict(path)
    assert verdict is Verdict.INCONCLUSIVE
    assert "not valid JSON" in reason


def test_an_unknown_schema_is_inconclusive_rather_than_read_best_effort(tmp_path) -> None:
    """A reader that parses what it recognises from an unknown schema will
    happily return CONTAINED from a format it does not understand."""
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"schema": SCHEMA_VERSION + 1, "verdict": "contained"}))
    verdict, reason = read_verdict(path)
    assert verdict is Verdict.INCONCLUSIVE
    assert "is not the" in reason


def test_an_artifact_with_no_schema_at_all_is_inconclusive(tmp_path) -> None:
    path = tmp_path / "bare.json"
    path.write_text(json.dumps({"verdict": "contained"}))
    assert read_verdict(path)[0] is Verdict.INCONCLUSIVE


def test_a_json_document_that_is_not_an_object_is_inconclusive(tmp_path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]")
    verdict, reason = read_verdict(path)
    assert verdict is Verdict.INCONCLUSIVE
    assert "not a JSON object" in reason


def test_an_unrecognised_verdict_string_is_inconclusive(tmp_path) -> None:
    path = tmp_path / "odd.json"
    path.write_text(json.dumps({"schema": SCHEMA_VERSION, "verdict": "probably-fine"}))
    verdict, reason = read_verdict(path)
    assert verdict is Verdict.INCONCLUSIVE
    assert "probably-fine" in reason


# ---------------------------------------------------------------------------
# assert_contained
# ---------------------------------------------------------------------------


def test_assert_contained_passes_only_on_evidence(_artifacts_in_tmp) -> None:
    assert_contained(_obs(Outcome.BLOCKED))  # does not raise


@pytest.mark.parametrize(
    ("outcome", "session"),
    [
        pytest.param(Outcome.ANSWERED, True, id="answered-cannot-be-attributed"),
        pytest.param(Outcome.UNREACHABLE, True, id="probe-could-not-run"),
        pytest.param(Outcome.NOT_ATTEMPTED, True, id="probe-never-ran"),
        pytest.param(Outcome.BLOCKED, False, id="blocked-but-no-session"),
    ],
)
def test_assert_contained_fails_on_every_inconclusive_case(outcome, session, _artifacts_in_tmp) -> None:
    """Inconclusive is red. This is the assertion the old probes could not make,
    because `except TimeoutError: pass` has no way to express a doubt."""
    with pytest.raises(AssertionError) as exc_info:
        assert_contained(_obs(outcome, session=session))
    assert "INCONCLUSIVE" in str(exc_info.value)


def test_the_failure_message_names_the_artifact_it_read(_artifacts_in_tmp) -> None:
    """A red run must point at the evidence, or the first thing anyone does is
    re-run it blind."""
    with pytest.raises(AssertionError) as exc_info:
        assert_contained(_obs(Outcome.ANSWERED, probe="dns_v6"))
    assert "dns_v6.json" in str(exc_info.value)
    assert str(_artifacts_in_tmp) in str(exc_info.value)


def test_assert_contained_fails_loudly_on_an_actual_leak(_artifacts_in_tmp) -> None:
    """The one case that is not a doubt but a finding."""
    with pytest.raises(AssertionError) as exc_info:
        assert_contained(_obs(Outcome.ESCAPED, probe="stun_v4"))
    assert "LEAK" in str(exc_info.value)
    assert "INCONCLUSIVE" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# The probes' own classification, exercised without a network
# ---------------------------------------------------------------------------
#
# The probe bodies live under tests/leak/, which the default suite ignores, so
# the code that turns a socket result into an Outcome would otherwise only ever
# run on a machine with a live session. It is ordinary branching logic and it
# decides the verdict, so it is tested here with the socket mocked out.

import socket  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

from tests.leak.test_dns_leak import _probe as dns_probe  # noqa: E402
from tests.leak.test_udp_egress_leak import _probe as udp_probe  # noqa: E402


@pytest.fixture
def _no_session():
    with patch("tests.leak.oracle.session_is_active", return_value=True):
        yield


def _sock_raising(exc: BaseException) -> MagicMock:
    sock = MagicMock()
    sock.recvfrom.side_effect = exc
    return sock


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        pytest.param(TimeoutError(), Outcome.BLOCKED, id="timeout-is-a-drop"),
        pytest.param(ConnectionRefusedError(), Outcome.BLOCKED, id="refusal-is-a-reject"),
        pytest.param(OSError("network unreachable"), Outcome.BLOCKED, id="unreachable-is-a-block"),
    ],
)
def test_the_dns_probe_reads_a_silent_socket_as_containment(exc, expected) -> None:
    with (
        patch("tests.leak.test_dns_leak.session_is_active", return_value=True),
        patch("socket.socket", return_value=_sock_raising(exc)),
    ):
        observation = dns_probe(socket.AF_INET, "1.1.1.1", "dns_test")
    assert observation.outcome is expected
    assert verdict_for(observation)[0] is Verdict.CONTAINED


def test_the_dns_probe_reads_a_valid_answer_as_undecidable() -> None:
    """The exact bytes the old version accepted as proof of containment."""
    reply = b"\xaa\xbb\x81\x80" + b"\x00" * 8
    sock = MagicMock()
    sock.recvfrom.return_value = (reply, ("1.1.1.1", 53))
    with (
        patch("tests.leak.test_dns_leak.session_is_active", return_value=True),
        patch("socket.socket", return_value=sock),
    ):
        observation = dns_probe(socket.AF_INET, "1.1.1.1", "dns_test")

    assert observation.outcome is Outcome.ANSWERED
    assert "well-formed" in observation.detail
    assert verdict_for(observation)[0] is Verdict.INCONCLUSIVE


def test_the_udp_probe_reads_any_reply_as_a_leak() -> None:
    sock = MagicMock()
    sock.recvfrom.return_value = (b"\x01\x01\x00\x0c" + b"\x00" * 20, ("74.125.0.1", 19302))
    with (
        patch("tests.leak.test_udp_egress_leak.session_is_active", return_value=True),
        patch("socket.getaddrinfo", return_value=[(2, 2, 17, "", ("74.125.0.1", 19302))]),
        patch("socket.socket", return_value=sock),
    ):
        observation = udp_probe(socket.AF_INET, "stun.example", 19302, "stun_test")

    assert observation.outcome is Outcome.ESCAPED
    assert verdict_for(observation)[0] is Verdict.LEAK


def test_the_udp_probe_reads_a_dns_failure_as_a_probe_that_could_not_run() -> None:
    """It used to call this a test failure. A STUN probe whose hostname would
    not resolve has said nothing about whether UDP is contained."""
    with (
        patch("tests.leak.test_udp_egress_leak.session_is_active", return_value=True),
        patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")),
    ):
        observation = udp_probe(socket.AF_INET, "stun.example", 19302, "stun_test")

    assert observation.outcome is Outcome.UNREACHABLE
    assert verdict_for(observation)[0] is Verdict.INCONCLUSIVE


def test_every_probe_records_whether_a_session_was_live() -> None:
    """The field the verdict turns on first, taken from the host, not assumed."""
    with (
        patch("tests.leak.test_dns_leak.session_is_active", return_value=False),
        patch("socket.socket", return_value=_sock_raising(TimeoutError())),
    ):
        observation = dns_probe(socket.AF_INET, "1.1.1.1", "dns_test")

    assert observation.session_active is False
    assert verdict_for(observation)[0] is Verdict.INCONCLUSIVE
