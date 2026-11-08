# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Read-only, non-secret NetworkManager/WireGuard evidence for a frozen path.

Never call GetSecrets, wg dump, connection up/down, or change routes here.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import subprocess
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ttp.exceptions import TorError
from ttp.paths import resolve

GUIDE = "https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/web/how-to/vpn.md"
NM = "org.freedesktop.NetworkManager"
ROOT = "/org/freedesktop/NetworkManager"


class VPNError(TorError):
    """Required VPN evidence is missing, unsupported or inconsistent."""


def _run(binary: str, *args: str) -> str:
    try:
        response = subprocess.run([resolve(binary), *args], capture_output=True, text=True, timeout=2, check=False)
        if response.returncode or len(response.stdout) > 262144:
            raise VPNError(f"VPN observation failed ({binary}); see {GUIDE}")
        return response.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise VPNError(f"VPN observation unavailable ({binary}); see {GUIDE}") from exc


def _unpack(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"type", "data"}:
            return _unpack(value["data"])
        return {key: _unpack(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_unpack(item) for item in value]
    return value


def _bus(*args: str) -> Any:
    try:
        reply = json.loads(_run("busctl", "--system", "--auto-start=no", "--timeout=2", "--json=short", *args))
        data = reply["data"]
        if args[0] == "get-property":
            return _unpack(data)
        if not isinstance(data, list) or len(data) != 1:
            raise ValueError("Unexpected busctl result")
        return _unpack(data[0])
    except (ValueError, KeyError, TypeError) as exc:
        raise VPNError(f"Invalid NetworkManager reply; see {GUIDE}") from exc


def _property(path: str, interface: str, name: str) -> Any:
    return _bus("get-property", NM, path, interface, name)


def _name(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", value) or value == "lo":
        raise VPNError("Unsupported VPN interface identity")
    return value


def endpoint(value: str) -> tuple[str, int]:
    try:
        if "%" in value:
            raise ValueError("Scoped endpoints are unsupported")
        host, port = value.rsplit(":", 1)
        address = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
        number = int(port)
        if not 1 <= number <= 65535 or address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError("Invalid remote")
        return str(address), number
    except (ValueError, AttributeError) as exc:
        raise VPNError("VPN requires a stable numeric endpoint (no hostname or scoped address)") from exc


@dataclass(frozen=True)
class VPNPolicy:
    uuid: str
    active_path: str
    interface: str
    ifindex: int
    underlay: str
    underlay_index: int
    peer: str
    address: str
    port: int
    mark: int
    ipv6: bool

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_snapshot(cls, value: object) -> VPNPolicy:
        try:
            if not isinstance(value, dict):
                raise ValueError("Missing VPN snapshot")
            policy = cls(**value)
            if str(uuid.UUID(policy.uuid)) != policy.uuid:
                raise ValueError("Invalid UUID")
            if not re.fullmatch(ROOT + r"/ActiveConnection/[0-9]+", policy.active_path):
                raise ValueError("Invalid connection path")
            _name(policy.interface)
            _name(policy.underlay)
            if policy.interface == policy.underlay:
                raise ValueError("VPN endpoint routes into itself")
            if any(type(item) is not int or item <= 0 for item in (policy.ifindex, policy.underlay_index, policy.mark)):
                raise ValueError("Invalid kernel identity")
            if policy.mark > 0xFFFFFFFF or type(policy.ipv6) is not bool:
                raise ValueError("Invalid VPN policy")
            if len(base64.b64decode(policy.peer, validate=True)) != 32:
                raise ValueError("Invalid peer key")
            if endpoint(f"[{policy.address}]:{policy.port}") != (policy.address, policy.port):
                raise ValueError("Invalid endpoint")
            return policy
        except (ValueError, TypeError, KeyError) as exc:
            raise VPNError("Invalid frozen VPN policy") from exc


def _route(address: str, *, mark: int = 0, uid: int = 0) -> dict[str, Any]:
    family = "-6" if ":" in address else "-4"
    try:
        rows = json.loads(_run("ip", "-j", family, "route", "get", address, "mark", str(mark), "uid", str(uid)))
        if len(rows) != 1 or rows[0].get("type", "unicast") != "unicast":
            raise ValueError("Invalid route")
        result: dict[str, Any] = rows[0]
        return result
    except (ValueError, KeyError, TypeError) as exc:
        raise VPNError("VPN effective route unavailable") from exc


def inspect_profile(profile_uuid: str, *, no_ipv6: bool, tor_uid: int = 0) -> VPNPolicy:
    """Observe actual kernel settings as well as NetworkManager's public profile."""
    try:
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise VPNError("Required VPN mode needs unified cgroup v2 for verified Tor teardown")
        profile_uuid = str(uuid.UUID(profile_uuid))
        path = _bus("call", NM, ROOT + "/Settings", NM + ".Settings", "GetConnectionByUuid", "s", profile_uuid)
        config = _bus("call", NM, path, NM + ".Settings.Connection", "GetSettings")
        if config["connection"]["type"] != "wireguard" or config["connection"]["uuid"] != profile_uuid:
            raise VPNError("Only native NetworkManager WireGuard profiles are supported")
        peers = config["wireguard"]["peers"]
        if len(peers) != 1:
            raise VPNError("Exactly one VPN peer is required")
        peer = peers[0]
        address, port = endpoint(peer["endpoint"])
        allowed = {str(ipaddress.ip_network(item)) for item in peer["allowed-ips"]}
        if "0.0.0.0/0" not in allowed or (not no_ipv6 and "::/0" not in allowed):
            raise VPNError("VPN must cover IPv4 and IPv6, or select --no-ipv6 explicitly")
        active = []
        for candidate in _property(ROOT, NM, "ActiveConnections"):
            if _property(candidate, NM + ".Connection.Active", "Uuid") == profile_uuid:
                active.append(candidate)
            elif _property(candidate, NM + ".Connection.Active", "Type") == "wireguard" or _property(
                candidate, NM + ".Connection.Active", "Vpn"
            ):
                raise VPNError("Multiple active VPN connections are unsupported")
        if len(active) != 1:
            raise VPNError("Required VPN profile is not uniquely active")
        active_path = active[0]
        iface = NM + ".Connection.Active"
        if _property(active_path, iface, "State") != 2:
            raise VPNError("Required VPN is not activated")
        devices = _property(active_path, iface, "Devices")
        if len(devices) != 1:
            raise VPNError("VPN must have exactly one device")
        interface = _name(_property(devices[0], NM + ".Device", "Interface"))
        links = json.loads(_run("ip", "-j", "-d", "link", "show", "dev", interface))
        link = links[0]
        if link["linkinfo"]["info_kind"] != "wireguard" or "UP" not in link["flags"]:
            raise VPNError("VPN kernel device is not an active WireGuard interface")
        # Each query is public-only: never use `wg show ... dump` (contains keys).
        ends = _run("wg", "show", interface, "endpoints").splitlines()
        if ends != [f"{peer['public-key']}\t{'[' + address + ']' if ':' in address else address}:{port}"]:
            raise VPNError("Live VPN endpoint differs from its configured numeric peer")
        live_allowed = _run("wg", "show", interface, "allowed-ips").split()
        if not live_allowed or live_allowed[0] != peer["public-key"]:
            raise VPNError("VPN live peer mismatch")
        if {item.rstrip(",") for item in live_allowed[1:]} != allowed:
            raise VPNError("VPN live AllowedIPs differs from the profile")
        mark = int(_run("wg", "show", interface, "fwmark"), 0)
        route = _route(address, mark=mark)
        underlay = _name(route["dev"])
        underlay_link = json.loads(_run("ip", "-j", "-d", "link", "show", "dev", underlay))[0]
        if "UP" not in underlay_link["flags"]:
            raise VPNError("VPN underlay is administratively down")
        if underlay_link.get("linkinfo", {}).get("info_kind") not in (None, "veth"):
            raise VPNError("Nested VPN or virtual underlay is unsupported")
        # Diagnostic route samples complement packet-level enforcement; they
        # do not claim to enumerate every possible destination or policy rule.
        for target in ("1.1.1.1", "2606:4700:4700::1111") if not no_ipv6 else ("1.1.1.1",):
            if _route(target, uid=tor_uid).get("dev") != interface:
                raise VPNError("Tor's observed route does not use the required VPN")
        policy = VPNPolicy(
            profile_uuid,
            active_path,
            interface,
            link["ifindex"],
            underlay,
            underlay_link["ifindex"],
            peer["public-key"],
            address,
            port,
            mark,
            not no_ipv6,
        )
        return VPNPolicy.from_snapshot(policy.snapshot())
    except VPNError:
        raise
    except (ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
        raise VPNError(f"Unsupported or inconsistent VPN evidence; see {GUIDE}") from exc


def observe(policy: VPNPolicy, tor_uid: int) -> dict[str, Any]:
    from ttp.vpn_guard import verify

    guard_verified = False
    try:
        verify(policy, tor_uid)
        guard_verified = True
        if inspect_profile(policy.uuid, no_ipv6=not policy.ipv6, tor_uid=tor_uid) != policy:
            raise VPNError("VPN connection identity or policy changed")
        handshake = _run("wg", "show", policy.interface, "latest-handshakes").split()
        if len(handshake) != 2 or handshake[0] != policy.peer or not handshake[1].isdigit():
            raise VPNError("VPN handshake evidence invalid")
        return {
            "state": "constrained",
            "reason": "vpn.path_constrained",
            "guard_verified": True,
            "handshake_at": int(handshake[1]) or None,
        }
    except Exception:
        return {"state": "unknown", "reason": "vpn.required_path_unavailable", "guard_verified": guard_verified}
