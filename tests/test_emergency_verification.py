# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""An applied-looking table is not enough: exercise concrete protection failures."""

import copy
import json
import subprocess

import pytest

from ttp.firewall.verification import inspect_emergency_rules, matches_emergency_contract
from ttp.paths import UnsafeBinaryError


@pytest.fixture
def ruleset():
    # A representative nft JSON dump, independent of the production matcher.
    return {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"table": {"family": "inet", "name": "ttp", "handle": 20}},
            {
                "chain": {
                    "family": "inet",
                    "table": "ttp",
                    "name": "filter_out",
                    "type": "filter",
                    "hook": "output",
                    "prio": 0,
                    "policy": "drop",
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "ttp",
                    "name": "filter_forward",
                    "type": "filter",
                    "hook": "forward",
                    "prio": 0,
                    "policy": "drop",
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "ttp",
                    "name": "filter_input",
                    "type": "filter",
                    "hook": "input",
                    "prio": 0,
                    "policy": "drop",
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "ttp",
                    "chain": "filter_out",
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}},
                        {"accept": None},
                    ],
                }
            },
            {
                "rule": {
                    "family": "inet",
                    "table": "ttp",
                    "chain": "filter_input",
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
                        {"accept": None},
                    ],
                }
            },
        ]
    }


def test_expected_hooks_policies_and_loopback_are_accepted(ruleset):
    assert matches_emergency_contract(ruleset)


def test_empty_nat_chains_and_unused_counters_retained_by_atomic_flush_are_allowed(ruleset):
    ruleset["nftables"].extend(
        [
            {
                "chain": {
                    "family": "inet",
                    "table": "ttp",
                    "name": "output",
                    "type": "nat",
                    "hook": "output",
                    "prio": -150,
                    "policy": "accept",
                }
            },
            {"counter": {"family": "inet", "table": "ttp", "name": "dns_redirected", "packets": 55, "bytes": 500}},
        ]
    )
    assert matches_emergency_contract(ruleset)


@pytest.mark.parametrize(
    "key,value",
    [
        ("policy", "accept"),
        ("hook", "prerouting"),
        ("type", "nat"),
        ("prio", -100),
        ("prio", False),
        ("dev", "eth0"),
        ("devices", ["eth0"]),
        ("flags", ["offload"]),
    ],
)
def test_a_filter_hook_that_does_not_cover_the_required_traffic_is_rejected(ruleset, key, value):
    ruleset["nftables"][2]["chain"][key] = value
    assert not matches_emergency_contract(ruleset)


@pytest.mark.parametrize("index", [1, 2, 3, 4, 5, 6])
def test_missing_table_hook_or_loopback_rule_is_not_verified(ruleset, index):
    del ruleset["nftables"][index]
    assert not matches_emergency_contract(ruleset)


def test_dormant_table_is_not_protection(ruleset):
    ruleset["nftables"][1]["table"]["flags"] = ["dormant"]
    assert not matches_emergency_contract(ruleset)


def test_nonloopback_accept_is_detected_even_with_drop_policy(ruleset):
    ruleset["nftables"][5]["rule"]["expr"][0]["match"]["right"] = "eth0"
    assert not matches_emergency_contract(ruleset)


def test_an_extra_accept_or_jump_cannot_be_adopted_as_the_expected_ruleset(ruleset):
    extra = copy.deepcopy(ruleset["nftables"][5])
    extra["rule"]["expr"] = [{"accept": None}]
    ruleset["nftables"].append(extra)
    assert not matches_emergency_contract(ruleset)


@pytest.mark.parametrize(
    "entry",
    [
        None,
        {},
        {"chain": {}, "rule": {}},
        {"chain": {"family": "ip", "table": "ttp"}},
        {"chain": {"family": "inet", "table": "other", "name": "filter_out"}},
        {"chain": {"family": "inet", "table": "ttp", "name": 4}},
        {"chain": {"family": "inet", "table": "ttp", "name": "unknown"}},
        {"rule": {"family": "inet", "table": "ttp", "chain": None}},
        {"flowtable": {"family": "inet", "table": "ttp", "name": "offload"}},
        {"table": {"family": "inet", "name": "other"}},
    ],
)
def test_unknown_or_malformed_kernel_structure_is_not_accepted(ruleset, entry):
    ruleset["nftables"].append(entry)
    assert not matches_emergency_contract(ruleset)


def test_duplicate_chains_are_not_silently_overwritten(ruleset):
    ruleset["nftables"].append(copy.deepcopy(ruleset["nftables"][2]))
    assert not matches_emergency_contract(ruleset)


@pytest.mark.parametrize("payload", [None, [], {}, {"nftables": None}])
def test_invalid_document_is_not_protection(payload):
    assert not matches_emergency_contract(payload)


def test_successful_inspection_returns_explicit_verified_code(ruleset, monkeypatch):
    def run(cmd, **kwargs):
        assert cmd[1:] == ["-j", "list", "table", "inet", "ttp"]
        assert kwargs["timeout"] == 4
        return subprocess.CompletedProcess(cmd, 0, json.dumps(ruleset))

    monkeypatch.setattr("ttp.firewall.verification.subprocess.run", run)
    result = inspect_emergency_rules(timeout=4)
    assert result.verified
    assert result.diagnostic.code == 7


@pytest.mark.parametrize(
    "response,reason",
    [
        (subprocess.CompletedProcess([], 1, ""), "firewall.emergency_read_failed"),
        (subprocess.CompletedProcess([], 0, "bad"), "firewall.emergency_reply_invalid"),
        (subprocess.CompletedProcess([], 0, "{}"), "firewall.emergency_rules_mismatch"),
    ],
)
def test_inspection_failure_has_its_own_reason(monkeypatch, response, reason):
    monkeypatch.setattr("ttp.firewall.verification.subprocess.run", lambda *args, **kwargs: response)
    result = inspect_emergency_rules()
    assert not result.verified
    assert result.reason == reason
    assert result.diagnostic.code == 8


@pytest.mark.parametrize("error", [OSError("denied"), UnsafeBinaryError("unsafe"), subprocess.TimeoutExpired("nft", 1)])
def test_unreadable_rules_never_attest_isolation(monkeypatch, error):
    def run(*args, **kwargs):
        raise error

    monkeypatch.setattr("ttp.firewall.verification.subprocess.run", run)
    assert inspect_emergency_rules().diagnostic.code == 8
