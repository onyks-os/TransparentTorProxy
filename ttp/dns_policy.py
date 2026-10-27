# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Read-only DNSSEC preflight, before changing Tor, firewall or DNS state.

resolved's D-Bus DNSSEC property reports the *effective* value. To distinguish
an explicit per-link requirement from inheritance, also read its saved link
configuration (or networkd's state for a networkd-managed link). These files
are an internal systemd format, not a public API: keep the adapter here, check
it against D-Bus, and refuse an unreadable, inconsistent or unknown state.
See docs/web/how-to/dnssec.md for the supported contract and limitations.
"""

from __future__ import annotations

import json
import shlex
import socket
import subprocess
from pathlib import Path

from ttp import dns_resolved
from ttp.exceptions import DNSError, DNSSECConflictError
from ttp.paths import UnsafeBinaryError, resolve

RESOLVED_LINKS = Path("/run/systemd/resolve/netif")
NETWORKD_LINKS = Path("/run/systemd/netif/links")
DNSSEC_HELP = "https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/web/how-to/dnssec.md"
_SERVICE = "org.freedesktop.resolve1"
_MANAGER = "/org/freedesktop/resolve1"
_MODES = {"yes", "no", "allow-downgrade"}


def _bus_json(*args: str, signature: str) -> object:
    result = subprocess.run(
        [resolve("busctl"), "--system", "--auto-start=no", "--timeout=5", "--json=short", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or payload.get("type") != signature or "data" not in payload:
        raise ValueError("Unexpected systemd-resolved D-Bus reply")
    return payload["data"]


def _dnssec(path: str, interface: str) -> str:
    value = _bus_json("get-property", _SERVICE, path, interface, "DNSSEC", signature="s")
    if not isinstance(value, str) or value not in _MODES:
        raise ValueError("Unrecognized DNSSEC mode from systemd-resolved")
    return value


def _link_state(path: Path) -> dict[str, str] | None:
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    fields: dict[str, str] = {}
    for line in content.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in {"DNSSEC", "ADMIN_STATE"}:
            continue
        if key in fields:
            raise ValueError(f"Duplicate {key} in {path}")
        words = shlex.split(value)
        if len(words) != 1:
            raise ValueError(f"Unrecognized {key} in {path}")
        fields[key] = words[0]
    if "DNSSEC" in fields and fields["DNSSEC"] not in _MODES:
        raise ValueError(f"Unrecognized DNSSEC mode in {path}")
    return fields


def _configured_mode(index: int) -> str | None:
    networkd = _link_state(NETWORKD_LINKS / str(index))
    if networkd is not None and "ADMIN_STATE" not in networkd:
        raise ValueError(f"Missing networkd administrative state for interface {index}")
    admin = (networkd or {}).get("ADMIN_STATE")
    if admin is not None and admin not in {
        "pending",
        "initialized",
        "unmanaged",
        "configuring",
        "configured",
        "failed",
        "linger",
    }:
        raise ValueError(f"Unrecognized networkd link state for interface {index}")
    if admin in {"configuring", "configured", "failed", "linger"}:
        return (networkd or {}).get("DNSSEC")
    return (_link_state(RESOLVED_LINKS / str(index)) or {}).get("DNSSEC")


def check_dnssec_policy() -> None:
    """Reject explicit DNSSEC=yes on any current non-loopback interface.

    No per-link setting is changed. Checking all links matters because TTP's
    DNS redirection is system-wide, including when --interface selects one link.
    A policy that cannot be inspected is an error, not permission to override it.
    """
    if not dns_resolved.is_resolved_active(strict=True):
        return
    try:
        global_mode = _dnssec(_MANAGER, f"{_SERVICE}.Manager")
        links = socket.if_nameindex()
        for index, name in links:
            if name == "lo":
                continue
            mode = _configured_mode(index)
            if mode == "yes":
                raise DNSSECConflictError(
                    f"Interface {name} explicitly requires DNSSEC=yes. "
                    "Tor's DNSPort cannot provide the records needed for local DNSSEC validation. "
                    "TTP refused to start and did not change this policy. "
                    f"Keep DNSSEC and use a separate Tor environment, or review the interface policy yourself. "
                    f"See {DNSSEC_HELP}"
                )
            reply = _bus_json(
                "call", _SERVICE, _MANAGER, f"{_SERVICE}.Manager", "GetLink", "i", str(index), signature="o"
            )
            # Method replies contain a list of output arguments; properties do not.
            if not isinstance(reply, list) or len(reply) != 1 or not isinstance(reply[0], str):
                raise ValueError("Unexpected GetLink reply")
            effective = _dnssec(reply[0], f"{_SERVICE}.Link")
            if mode != _configured_mode(index) or effective != (mode or global_mode):
                raise ValueError(f"DNSSEC policy for {name} changed or disagrees with saved configuration")
        if links != socket.if_nameindex() or global_mode != _dnssec(_MANAGER, f"{_SERVICE}.Manager"):
            raise ValueError("Network or DNSSEC configuration changed during preflight; retry on a stable network")
    except DNSSECConflictError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError, UnsafeBinaryError) as exc:
        raise DNSError(f"Cannot determine the per-interface DNSSEC policy: {exc}. See {DNSSEC_HELP}") from exc
