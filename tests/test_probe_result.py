# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Failures at the HTTP/worker boundary must not become negative Tor verdicts."""

import json
import socket
import ssl
import subprocess
import urllib.error
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ttp import netprobe, probe
from ttp.evidence import VerificationState

AUTHORITY = netprobe.ENDPOINTS[0]


@pytest.fixture
def parent(monkeypatch, tmp_path):
    groups = tmp_path / "cgroups"
    groups.write_text("0::/user.slice/session.scope\n")
    monkeypatch.setattr(probe, "CGROUP_PATH", groups)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    monkeypatch.setattr(probe.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=65534, pw_gid=65534))
    monkeypatch.setattr(probe.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=65534))
    clock = [100.0]
    monkeypatch.setattr(probe, "boottime", lambda: clock[0])
    monkeypatch.setattr(probe.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    return groups, clock


def reply(payload):
    return subprocess.CompletedProcess([], 0, json.dumps(payload), "")


@pytest.mark.parametrize(
    "verdict,state,code", [(True, VerificationState.CONFIRMED, 0), (False, VerificationState.NEGATIVE, 6)]
)
def test_authoritative_boolean_and_valid_address_are_required(parent, monkeypatch, verdict, state, code):
    run = MagicMock(return_value=reply({"data": {"IsTor": verdict, "IP": "185.220.101.1"}}))
    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.verify_session(lock={"tor_uid": 110})
    assert result.state is state
    assert result.result.exit_code == code
    assert result.ip == "185.220.101.1"
    assert result.observed_at == 100
    assert run.call_args.kwargs["user"] == 65534
    assert run.call_args.kwargs["group"] == 65534
    assert run.call_args.kwargs["extra_groups"] == []
    assert run.call_args.args[0][1:5] == ["-I", "-m", "ttp.netprobe", "--report"]


@pytest.mark.parametrize(
    "data",
    [
        {"IsTor": "false", "IP": "1.2.3.4"},
        {"IsTor": False},
        {"IsTor": True, "IP": "bad"},
        {"IsTor": False, "IP": "fe80::1%eth0"},
        {"IP": "1.2.3.4"},
        {"IP": "x" * 100},
    ],
)
def test_malformed_authority_reply_is_inconclusive(parent, monkeypatch, data):
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: reply({"data": data}))
    result = probe.verify_session()
    assert result.state is VerificationState.INCONCLUSIVE
    assert result.result.exit_code == 3
    assert "probe.authority_response_invalid" in {d.reason for d in result.diagnostics}


def test_reflector_cannot_assert_tor_but_its_address_is_retained(parent, monkeypatch):
    def run(cmd, **kwargs):
        return reply({"error": "timeout"}) if AUTHORITY in cmd else reply({"data": {"IsTor": True, "ip": "1.2.3.4"}})

    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.verify_session()
    assert result.state is VerificationState.INCONCLUSIVE
    assert result.ip == "1.2.3.4"
    assert result.result.exit_code == 3


def test_later_success_keeps_failed_attempts_without_making_them_current_failures(parent, monkeypatch):
    results = [
        reply({"error": "dns_error"}),
        reply({"data": {"ip": "1.2.3.4"}}),
        reply({"data": {"IsTor": True, "IP": "185.220.101.1"}}),
    ]
    monkeypatch.setattr(probe.subprocess, "run", MagicMock(side_effect=results))
    result = probe.verify_session()
    assert result.confirmed
    assert result.result.exit_code == 0
    assert result.diagnostics[0].reason == "probe.dns_error"
    assert not result.diagnostics[0].active


def test_each_retry_spends_the_same_total_deadline(parent, monkeypatch):
    _, clock = parent
    budgets = []

    def run(cmd, **kwargs):
        budgets.append(kwargs["timeout"])
        clock[0] += kwargs["timeout"]
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.verify_session(timeout=20)
    assert budgets == [15, 5]
    assert clock[0] == 120
    assert result.reason == "probe.deadline"
    assert result.result.exit_code == 3


@pytest.mark.parametrize(
    "failure,reason",
    [
        (PermissionError(13, "denied"), "probe.execution_failed"),
        (subprocess.CompletedProcess([], 1, "", "module absent"), "probe.worker_failed"),
    ],
)
def test_unprivileged_worker_failure_never_falls_back_to_root(parent, monkeypatch, failure, reason):
    run = MagicMock(side_effect=failure) if isinstance(failure, Exception) else MagicMock(return_value=failure)
    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.verify_session()
    assert result.reason == reason
    assert run.call_count == 1
    assert run.call_args.kwargs["user"] == 65534


@pytest.mark.parametrize(
    "payload", ["x" * 4097, "broken json", "[]", "{}", '{"data":[]}', '{"error":[]}', '{"error":"arbitrary"}']
)
def test_bad_worker_protocol_is_not_a_network_verdict(parent, monkeypatch, payload):
    monkeypatch.setattr(
        probe.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, payload, "")
    )
    result = probe.verify_session()
    assert result.reason == "probe.invalid_worker_reply"


@pytest.mark.parametrize(
    "lock",
    [
        {"tor_uid": 65534},
        {"bypass_users": ["65534"]},
        {"bypass_users": ["nobody"]},
        {"bypass_groups": ["65534"]},
        {"bypass_groups": ["nogroup"]},
    ],
)
def test_probe_must_not_be_one_of_the_configured_exemptions(parent, monkeypatch, lock):
    run = MagicMock()
    monkeypatch.setattr(probe.subprocess, "run", run)
    result = probe.verify_session(lock=lock)
    assert result.reason == "probe.exempt_identity"
    assert not run.called


def test_inherited_bypass_cgroup_prevents_a_trusted_verdict(parent):
    parent[0].write_text("0::/ttp-bypass.slice/tool.scope\n")
    assert probe.verify_session(lock={}).reason == "probe.exempt_cgroup"


def test_unreadable_routing_context_is_not_assumed_nonexempt(parent):
    parent[0].unlink()
    assert probe.verify_session(lock={}).reason == "probe.identity_unavailable"


def test_missing_probe_account_is_reported(parent, monkeypatch):
    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(probe.pwd, "getpwnam", missing)
    assert probe.verify_session().reason == "probe.identity_unavailable"


def test_nobody_must_not_resolve_to_root(parent, monkeypatch):
    monkeypatch.setattr(probe.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=0, pw_gid=0))
    assert probe.verify_session().reason == "probe.identity_unavailable"


def test_nonroot_worker_retains_callers_credentials_and_checks_supplementary_groups(parent, monkeypatch):
    monkeypatch.setattr(probe.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(probe.os, "getegid", lambda: 1000)
    monkeypatch.setattr(probe.os, "getgroups", lambda: [2000])
    assert probe.verify_session(lock={"bypass_groups": ["2000"]}).reason == "probe.exempt_identity"
    run = MagicMock(return_value=reply({"data": {"IsTor": True, "IP": "1.2.3.4"}}))
    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe.verify_session(lock={}).confirmed
    assert "user" not in run.call_args.kwargs


@pytest.mark.parametrize("timeout", [0, -1, 3601, float("nan"), float("inf")])
def test_invalid_verification_budget_is_refused(timeout):
    with pytest.raises(ValueError):
        probe.verify_session(timeout=timeout)


@pytest.fixture
def opener(monkeypatch):
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"IsTor":true,"IP":"185.220.101.1"}'
    client = MagicMock()
    client.open.return_value = response
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(netprobe.urllib.request, "build_opener", factory)
    return client, response, factory


def test_worker_disables_environment_proxy_and_redirects(opener):
    _, response, factory = opener
    assert netprobe.fetch_report(AUTHORITY, 5)["data"]["IsTor"] is True
    assert factory.call_args.args[0].proxies == {}
    assert isinstance(factory.call_args.args[1], netprobe._NoRedirect)
    assert netprobe._NoRedirect().redirect_request(None, None, 302, "", {}, "https://other/") is None
    response.read.assert_called_once_with(netprobe._MAX_BODY + 1)


@pytest.mark.parametrize(
    "error,reason",
    [
        (urllib.error.HTTPError(AUTHORITY, 302, "", {}, None), "http_redirect"),
        (urllib.error.HTTPError(AUTHORITY, 503, "", {}, None), "http_error"),
        (urllib.error.URLError(socket.gaierror()), "dns_error"),
        (urllib.error.URLError(ssl.SSLError()), "tls_error"),
        (urllib.error.URLError(TimeoutError()), "timeout"),
        (urllib.error.URLError(OSError()), "connection_error"),
        (TimeoutError(), "timeout"),
        (ssl.SSLError(), "tls_error"),
        (OSError(), "connection_error"),
    ],
)
def test_worker_reports_distinct_transport_failures(opener, error, reason):
    opener[0].open.side_effect = error
    assert netprobe.fetch_report(AUTHORITY, 5)["error"] == reason


@pytest.mark.parametrize(
    "body,reason",
    [
        (b"x" * (netprobe._MAX_BODY + 1), "response_too_large"),
        (b"[]", "response_shape"),
        (b"\xff", "response_encoding"),
        (b"bad", "response_json"),
    ],
)
def test_worker_reports_distinct_response_failures(opener, body, reason):
    opener[1].read.return_value = body
    assert netprobe.fetch_report(AUTHORITY, 5)["error"] == reason


def test_worker_report_cli_prints_one_structured_response(opener, capsys):
    assert netprobe.main(["--report", AUTHORITY, "5"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["IsTor"] is True


@pytest.mark.parametrize("timeout", ["0", "-1", "3601", "nan", "inf", "bad"])
def test_worker_report_cli_rejects_invalid_deadline(timeout, capsys):
    assert netprobe.main(["--report", AUTHORITY, timeout]) == 2
    assert "timeout" in capsys.readouterr().err
