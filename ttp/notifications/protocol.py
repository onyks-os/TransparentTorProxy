# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Small authenticated local protocol with a fixed, privacy-preserving vocabulary."""

from __future__ import annotations

import json
import socket
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_MESSAGE = 8192


@dataclass(frozen=True)
class Event:
    title: str
    body: str
    severity: int


EVENTS = {
    "started": Event(
        "TTP session started", "Selected startup requirements were satisfied. Inspect ttp status for observations.", 1
    ),
    "stopped": Event("TTP session stopped", "TTP protection was removed. Applications may reconnect outside Tor.", 1),
    "inconclusive": Event(
        "Tor verification inconclusive",
        "The session remains configured. Inspect ttp check and the journal; this is not proof of isolation.",
        1,
    ),
    "watchdog_unavailable": Event(
        "Required watchdog unavailable",
        "Supervision failed. Containment was requested; inspect ttp status for the outcome.",
        2,
    ),
    "tor_negative": Event(
        "Tor verification returned a negative result",
        "Containment was requested. Inspect ttp status for the outcome.",
        2,
    ),
    "emergency_verified": Event(
        "TTP emergency rules verified",
        "Close sensitive applications before sudo ttp stop; they may reconnect outside Tor.",
        2,
    ),
    "containment_unconfirmed": Event(
        "TTP containment UNCONFIRMED",
        "Isolation could not be established. Inspect ttp status and the journal. Close sensitive applications before terminating TTP.",
        3,
    ),
    "recovered": Event(
        "TTP verification recovered",
        "A new evaluation succeeded. Inspect ttp status for its scope. Any latched emergency remains until explicit stop.",
        1,
    ),
}


def socket_path(uid: int, session_id: str) -> Path:
    if type(uid) is not int or uid <= 0:
        raise ValueError("A non-root notification recipient is required")
    identifier = uuid.UUID(session_id).hex
    return Path(f"/run/ttp-notify-{uid}/{identifier}.sock")


def peer_uid(sock: socket.socket) -> int:
    _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return int(uid)


def send(sock: socket.socket, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, allow_nan=False).encode()
    if len(encoded) > MAX_MESSAGE:
        raise ValueError("Notification message too large")
    sock.sendall(encoded)


def receive(sock: socket.socket) -> dict[str, Any]:
    encoded = sock.recv(MAX_MESSAGE + 1)
    if not encoded or len(encoded) > MAX_MESSAGE:
        raise ValueError("Invalid notification message length")
    payload = json.loads(encoded)
    if not isinstance(payload, dict):
        raise ValueError("Invalid notification message")
    return payload
