# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Verify the emergency contract against structured kernel rules, not a hash
adopted after application. This is a structural observation at a point in time,
not a measurement of every packet path on the host.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from ttp.evidence import Diagnostic, ExitCode
from ttp.paths import UnsafeBinaryError, resolve


@dataclass(frozen=True)
class KernelCheck:
    verified: bool
    reason: str
    message: str

    @property
    def diagnostic(self) -> Diagnostic:
        code = ExitCode.EMERGENCY_VERIFIED if self.verified else ExitCode.CONTAINMENT_UNCONFIRMED
        return Diagnostic(code, self.reason, "firewall", "verify_emergency", self.message)


def _loopback_expression(direction: str) -> list[dict[str, Any]]:
    return [{"match": {"op": "==", "left": {"meta": {"key": direction}}, "right": "lo"}}, {"accept": None}]


def matches_emergency_contract(payload: object) -> bool:
    """Accept only the expected inet hooks, drop policies and loopback rules.

    nft flush table retains the original output/prerouting NAT chains and named
    counters. Those chains may remain empty; their old redirect/accept rules may
    not remain. A dormant table or a hook scoped to a device is not protection.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        return False
    tables = []
    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[object]] = {}
    for entry in payload["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            return False
        kind, item = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        if not isinstance(item, dict) or item.get("family") != "inet":
            return False
        if kind == "table":
            if item.get("name") != "ttp" or item.get("flags"):
                return False
            tables.append(item)
            continue
        if item.get("table") != "ttp":
            return False
        if kind == "chain":
            name = item.get("name")
            if not isinstance(name, str) or name in chains:
                return False
            chains[name] = item
        elif kind == "rule":
            name = item.get("chain")
            if not isinstance(name, str):
                return False
            rules.setdefault(name, []).append(item.get("expr"))
        elif kind != "counter":
            return False
    expected = {"filter_out": "output", "filter_forward": "forward", "filter_input": "input"}
    if len(tables) != 1 or set(chains) - (set(expected) | {"output", "prerouting"}):
        return False
    for name, hook in expected.items():
        chain = chains.get(name, {})
        if chain.get("type") != "filter" or chain.get("hook") != hook or chain.get("policy") != "drop":
            return False
        if type(chain.get("prio")) is not int or chain["prio"] != 0:
            return False
        if any(key in chain for key in ("dev", "device", "devices")) or chain.get("flags"):
            return False
    expected_rules = {
        "filter_out": [_loopback_expression("oifname")],
        "filter_input": [_loopback_expression("iifname")],
    }
    return rules == expected_rules


def inspect_emergency_rules(*, timeout: float = 10) -> KernelCheck:
    try:
        response = subprocess.run(
            [resolve("nft"), "-j", "list", "table", "inet", "ttp"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if response.returncode:
            return KernelCheck(False, "firewall.emergency_read_failed", f"nft exit={response.returncode}")
        payload = json.loads(response.stdout)
    except subprocess.TimeoutExpired:
        return KernelCheck(False, "firewall.emergency_read_timeout", "Kernel rules inspection exceeded its deadline")
    except (OSError, UnsafeBinaryError) as exc:
        return KernelCheck(False, "firewall.emergency_read_failed", type(exc).__name__)
    except ValueError:
        return KernelCheck(False, "firewall.emergency_reply_invalid", "nft returned invalid JSON")
    if not matches_emergency_contract(payload):
        return KernelCheck(
            False, "firewall.emergency_rules_mismatch", "Kernel rules do not match the emergency contract"
        )
    return KernelCheck(True, "firewall.emergency_verified", "Emergency rules verified in the kernel")
