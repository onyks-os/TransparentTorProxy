# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Freedesktop Notify calls made only by the unprivileged recipient agent."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from ttp.evidence import boottime
from ttp.notifications.protocol import EVENTS
from ttp.paths import resolve
from ttp.settings import NotificationSettings

SERVICE = "org.freedesktop.Notifications"
OBJECT = "/org/freedesktop/Notifications"


def call(bus: str, method: str, args: list[str], timeout: float) -> dict[str, Any]:
    response = subprocess.run(
        [
            resolve("busctl"),
            f"--address={bus}",
            f"--timeout={timeout:g}",
            "--json=short",
            "--",
            "call",
            SERVICE,
            OBJECT,
            SERVICE,
            method,
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )
    if len(response.stdout) > 4096:
        raise ValueError("Oversized notification server reply")
    payload = json.loads(response.stdout)
    if not isinstance(payload, dict):
        raise ValueError("Invalid notification server reply")
    return payload


def check_server(bus: str, timeout: float) -> None:
    payload = call(bus, "GetServerInformation", [], timeout)
    data = payload.get("data")
    if (
        payload.get("type") != "ssss"
        or not isinstance(data, list)
        or len(data) != 4
        or any(not isinstance(v, str) for v in data)
    ):
        raise ValueError("Invalid GetServerInformation response")


@dataclass
class Delivery:
    bus: str
    settings: NotificationSettings
    last_event: str | None = None
    notification_id: int = 0
    last_receipt: dict[str, Any] | None = None

    def deliver(self, name: str) -> dict[str, Any]:
        event = EVENTS[name]
        if name == self.last_event and self.last_receipt and self.last_receipt["state"] == "accepted":
            return {**self.last_receipt, "deduplicated": True}
        deadline = boottime() + self.settings.delivery_timeout
        ambiguous = False
        reason = "notifications.server_failed"
        for attempt in range(self.settings.attempts):
            remaining = deadline - boottime()
            if remaining <= 0:
                break
            try:
                payload = call(
                    self.bus,
                    "Notify",
                    [
                        "susssasa{sv}i",
                        "TTP",
                        str(self.notification_id),
                        "network-vpn",
                        event.title,
                        event.body,
                        "0",
                        "1",
                        "urgency",
                        "y",
                        str(min(event.severity, 2)),
                        "0" if event.severity >= 2 else "-1",
                    ],
                    min(self.settings.call_timeout, remaining),
                )
                data = payload.get("data")
                if (
                    payload.get("type") != "u"
                    or not isinstance(data, list)
                    or len(data) != 1
                    or type(data[0]) is not int
                    or not 0 < data[0] < 2**32
                ):
                    raise ValueError("Invalid notification acceptance identifier")
                self.notification_id = data[0]
                self.last_event = name
                self.last_receipt = {
                    "state": "accepted",
                    "reason": "notifications.server_accepted",
                    "event": name,
                    "notification_id": data[0],
                    "attempts": attempt + 1,
                    "observed_at": boottime(),
                }
                return self.last_receipt
            except subprocess.TimeoutExpired:
                # The server may have accepted the call before its reply was
                # lost. Never label this as proof that nothing was delivered.
                ambiguous = True
                reason = "notifications.reply_timeout"
            except subprocess.CalledProcessError:
                # busctl also returns a nonzero status for a D-Bus timeout.
                # Transport errors cannot prove the server rejected the call.
                ambiguous = True
                reason = "notifications.call_unconfirmed"
            except (OSError, ValueError):
                reason = "notifications.reply_invalid"
        self.last_event = name
        self.last_receipt = {
            "state": "unconfirmed" if ambiguous else "failed",
            "reason": reason,
            "event": name,
            "observed_at": boottime(),
        }
        return self.last_receipt
