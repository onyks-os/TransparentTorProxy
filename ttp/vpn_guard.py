# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Independent, fail-closed VPN table; root intent survives partial startup."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ttp.paths import resolve
from ttp.vpn import VPNError, VPNPolicy

TABLE = "ttp_vpn"
INTENT = Path("/run/ttp/vpn-intent.json")


def _match(left: object, right: object) -> dict[str, Any]:
    return {"match": {"op": "==", "left": left, "right": right}}


def _meta(key: str, value: object) -> dict[str, Any]:
    return _match({"meta": {"key": key}}, value)


def transport_expressions(policy: VPNPolicy) -> list[list[dict[str, Any]]]:
    """The only non-Tor physical IP exceptions, shared by both tables."""
    family = "ip6" if ":" in policy.address else "ip"
    physical = [_meta("oif", policy.underlay_index)]
    return [
        [
            *physical,
            _meta("mark", policy.mark),
            _match({"payload": {"protocol": family, "field": "daddr"}}, policy.address),
            _match({"payload": {"protocol": "udp", "field": "dport"}}, policy.port),
        ],
        # DHCP client renewal/discovery. Privileged source ports are required;
        # this does not grant arbitrary root egress or DNS bootstrap.
        [
            *physical,
            _meta("skuid", 0),
            _meta("nfproto", 2),
            _match({"payload": {"protocol": "udp", "field": "sport"}}, 68),
            _match({"payload": {"protocol": "udp", "field": "dport"}}, 67),
        ],
        [
            *physical,
            _meta("skuid", 0),
            _meta("nfproto", 10),
            _match({"payload": {"protocol": "udp", "field": "sport"}}, 546),
            _match({"payload": {"protocol": "udp", "field": "dport"}}, 547),
        ],
        [
            *physical,
            _match({"payload": {"protocol": "ip6", "field": "hoplimit"}}, 255),
            _match({"payload": {"protocol": "icmpv6", "field": "type"}}, {"set": [133, 135, 136]}),
        ],
    ]


def transport_rules(policy: VPNPolicy) -> str:
    """Equivalent nft text for the normal TTP filter (not its NAT redirect)."""
    family = "ip6" if ":" in policy.address else "ip"
    prefix = f"meta oif {policy.underlay_index}"
    return "\n".join(
        [
            f"{prefix} meta mark {policy.mark} {family} daddr {policy.address} udp dport {policy.port} accept",
            f"{prefix} meta skuid 0 meta nfproto ipv4 udp sport 68 udp dport 67 accept",
            f"{prefix} meta skuid 0 meta nfproto ipv6 udp sport 546 udp dport 547 accept",
            f"{prefix} ip6 hoplimit 255 icmpv6 type {{ 133, 135, 136 }} accept",
        ]
    )


def specification(policy: VPNPolicy, tor_uid: int) -> list[dict[str, Any]]:
    policy = VPNPolicy.from_snapshot(policy.snapshot())
    if type(tor_uid) is not int or tor_uid <= 0:
        raise VPNError("VPN guard requires a non-root Tor UID")
    base = {"family": "inet", "table": TABLE}
    objects: list[dict[str, Any]] = [
        {"table": {"family": "inet", "name": TABLE}},
        {"chain": {**base, "name": "output", "type": "filter", "hook": "output", "prio": 10, "policy": "drop"}},
        {"chain": {**base, "name": "forward", "type": "filter", "hook": "forward", "prio": 10, "policy": "drop"}},
    ]
    expressions = [
        [_meta("oifname", "lo")],
        [_meta("skuid", tor_uid), _meta("oif", policy.ifindex)],
        *transport_expressions(policy),
    ]
    objects.extend({"rule": {**base, "chain": "output", "expr": [*expr, {"accept": None}]}} for expr in expressions)
    return objects


def _nft(*args: str, payload: object | None = None) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [resolve("nft"), *args],
            input=json.dumps(payload) if payload is not None else None,
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
        return result
    except (OSError, subprocess.SubprocessError) as exc:
        raise VPNError("VPN kernel rules unavailable") from exc


def _normalized(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        raise VPNError("Invalid VPN kernel reply")
    result = []
    for entry in payload["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise VPNError("Invalid VPN kernel object")
        kind, item = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        if kind not in {"table", "chain", "rule"} or not isinstance(item, dict):
            raise VPNError("Unexpected VPN kernel object")
        if kind == "rule":
            for expression in item.get("expr", []):
                match = expression.get("match", {})
                if match.get("left") == {"meta": {"key": "oif"}} and isinstance(match.get("right"), str):
                    try:
                        match["right"] = socket.if_nametoindex(match["right"])
                    except OSError as exc:
                        raise VPNError("VPN interface disappeared") from exc
        result.append({kind: {key: value for key, value in item.items() if key not in {"handle", "index"}}})
    return result


def verify(policy: VPNPolicy, tor_uid: int) -> None:
    result = _nft("-j", "-n", "list", "table", "inet", TABLE)
    try:
        if result.returncode or _normalized(json.loads(result.stdout)) != specification(policy, tor_uid):
            raise VPNError("VPN kernel rules differ from the frozen contract")
    except ValueError as exc:
        raise VPNError("Invalid VPN kernel JSON") from exc


def _table_exists() -> bool:
    reply = _nft("-j", "list", "tables")
    try:
        if reply.returncode:
            raise VPNError("Cannot inspect retained VPN protection")
        tables = json.loads(reply.stdout)["nftables"]
        return any(
            item.get("table", {}).get("family") == "inet" and item["table"].get("name") == TABLE for item in tables
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise VPNError("Invalid kernel table listing") from exc


def retained() -> bool:
    """Refuse a new session even when startup died before publishing its lock."""
    return INTENT.exists() or _table_exists()


def install(policy: VPNPolicy, tor_uid: int) -> None:
    expected = specification(policy, tor_uid)
    if retained():
        raise VPNError("VPN protection from an earlier attempt remains; run ttp stop --restore-only")
    content = json.dumps({"vpn": policy.snapshot(), "tor_uid": tor_uid}).encode()
    fd, temporary = tempfile.mkstemp(prefix=".vpn-", dir=INTENT.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, INTENT)
        except FileExistsError as exc:
            raise VPNError("Concurrent VPN startup; protection intent already exists") from exc
    finally:
        os.close(fd)
        Path(temporary).unlink(missing_ok=True)
    result = _nft("-j", "-f", "-", payload={"nftables": [{"add": obj} for obj in expected]})
    if result.returncode:
        raise VPNError("Could not install VPN protection; intent retained for explicit recovery")
    verify(policy, tor_uid)


def release_after_stop() -> None:
    """Never remove protection on the strength of an unverified stop attempt."""
    if not retained():
        return
    try:
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise VPNError("Tor cgroup inspection unavailable; VPN guard retained")
        # stop_tor_service may have unlinked the volatile unit. A fully unloaded
        # unit is safe only after systemd reports no live or control process.
        reply = subprocess.run(
            [
                resolve("systemctl"),
                "show",
                "ttp-tor.service",
                "-p",
                "ActiveState",
                "-p",
                "MainPID",
                "-p",
                "ControlPID",
                "-p",
                "ControlGroup",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        values = dict(line.split("=", 1) for line in reply.stdout.splitlines() if "=" in line)
        if (
            values.get("ActiveState") not in {"inactive", "failed"}
            or values.get("MainPID") != "0"
            or values.get("ControlPID") != "0"
        ):
            raise VPNError("Tor termination unconfirmed; VPN guard retained")
        group = values.get("ControlGroup")
        if group is None or (group and (not group.startswith("/") or ".." in group.split("/"))):
            raise VPNError("Tor cgroup identity unconfirmed; VPN guard retained")
        if group:
            try:
                events = (Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events").read_text()
            except FileNotFoundError:
                events = "populated 0\n"
            if dict(line.split() for line in events.splitlines()).get("populated") != "0":
                raise VPNError("Tor descendants remain; VPN guard retained")
        _nft("delete", "table", "inet", TABLE)
        if _table_exists():
            raise VPNError("VPN guard removal failed")
        INTENT.unlink(missing_ok=True)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise VPNError("Tor termination unconfirmed; VPN protection retained") from exc
