# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Recipient selection, unprivileged service lifecycle and authenticated IPC."""

from __future__ import annotations

import os
import pwd
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from ttp import state
from ttp.evidence import Diagnostic, ExitCode, Result, boottime
from ttp.notifications.protocol import EVENTS, peer_uid, receive, send, socket_path
from ttp.paths import resolve
from ttp.settings import Settings

UNIT = "ttp-notify.service"
UNIT_PATH = Path("/run/systemd/system") / UNIT


class NotificationError(Exception):
    pass


def recipient(explicit: str | None = None) -> dict[str, Any]:
    selected = explicit or os.environ.get("SUDO_UID")
    if not selected:
        raise NotificationError("Direct root invocation needs --notification-user USER; no recipient is guessed")
    try:
        account = pwd.getpwuid(int(selected)) if selected.isdigit() else pwd.getpwnam(selected)
    except (KeyError, ValueError) as exc:
        raise NotificationError("Notification recipient does not exist") from exc
    if account.pw_uid <= 0:
        raise NotificationError("Notification recipient must be a non-root user")
    deadline = boottime() + 5
    listing = subprocess.run(
        [resolve("loginctl"), "list-sessions", "--no-legend", "--no-pager"],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    candidates = []
    for line in listing.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        remaining = deadline - boottime()
        if remaining <= 0:
            raise NotificationError("Notification recipient discovery timed out")
        identifier = fields[0]
        if not identifier.isalnum():
            raise NotificationError("Invalid login session identifier")
        response = subprocess.run(
            [
                resolve("loginctl"),
                "show-session",
                identifier,
                "-p",
                "User",
                "-p",
                "Remote",
                "-p",
                "Type",
                "-p",
                "State",
                "-p",
                "Class",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=remaining,
        )
        details = dict(item.split("=", 1) for item in response.stdout.splitlines() if "=" in item)
        if (
            details.get("User") == str(account.pw_uid)
            and details.get("Remote") == "no"
            and details.get("Type") in {"x11", "wayland"}
            and details.get("State") in {"active", "online"}
            and details.get("Class") == "user"
        ):
            candidates.append(identifier)
    if len(candidates) != 1:
        raise NotificationError("Exactly one local graphical session is required for the notification recipient")
    resolve("busctl")
    return {"uid": account.pw_uid, "gid": account.pw_gid, "login_session": candidates[0]}


def _quote(value: str) -> str:
    if any(ord(c) < 32 for c in value):
        raise NotificationError("Invalid systemd argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def start_agent(lock: dict[str, Any], target: dict[str, Any]) -> None:
    settings = Settings.from_snapshot(lock["settings"])
    uid, gid = target["uid"], target["gid"]
    socket_path(uid, lock["session_id"])
    argv = [
        sys.executable,
        "-I",
        "-m",
        "ttp.notifications.agent",
        "--uid",
        str(uid),
        "--session",
        lock["session_id"],
        "--watchdog-uid",
        str(state._watchdog_uid_or_root()),
        "--call-timeout",
        str(settings.notifications.call_timeout),
        "--delivery-timeout",
        str(settings.notifications.delivery_timeout),
        "--attempts",
        str(settings.notifications.attempts),
        "--heartbeat",
        str(settings.watchdog.heartbeat_interval),
    ]
    unit = "\n".join(
        [
            "[Unit]",
            "Description=TTP optional desktop notification agent",
            "StartLimitIntervalSec=60",
            "StartLimitBurst=5",
            "[Service]",
            "Type=notify",
            "NotifyAccess=main",
            f"User={uid}",
            f"Group={gid}",
            "ExecStart=" + " ".join(_quote(arg) for arg in argv),
            f"RuntimeDirectory=ttp-notify-{uid}",
            "RuntimeDirectoryMode=0755",
            f"TimeoutStartSec={settings.notifications.readiness_timeout:g}",
            f"WatchdogSec={settings.watchdog.service_timeout:g}",
            "WatchdogSignal=SIGKILL",
            f"TimeoutStopSec={settings.notifications.delivery_timeout:g}",
            "Restart=on-failure",
            "RestartSec=3",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "RestrictAddressFamilies=AF_UNIX",
            "RestrictNamespaces=yes",
            "RestrictSUIDSGID=yes",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "LockPersonality=yes",
            "StandardOutput=journal",
            "StandardError=journal",
            "",
        ]
    )
    UNIT_PATH.write_text(unit)
    subprocess.run([resolve("systemctl"), "daemon-reload"], check=True, capture_output=True, timeout=10)
    subprocess.run(
        [resolve("systemctl"), "start", UNIT],
        check=True,
        capture_output=True,
        timeout=settings.notifications.readiness_timeout,
    )
    response = rpc(lock, "status", timeout=1)
    if not response.get("instance_id"):
        raise NotificationError("Notification agent has no service identity")


def rpc(
    lock: dict[str, Any], operation: str, *, event: str | None = None, timeout: float = 1, wait: bool = True
) -> dict[str, Any]:
    target = lock.get("notification_target")
    if not isinstance(target, dict):
        raise NotificationError("No notification recipient recorded")
    uid = target["uid"]
    path = socket_path(uid, lock["session_id"])
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        if peer_uid(connection) != uid:
            raise NotificationError("Notification agent peer identity mismatch")
        send(connection, {"session_id": lock["session_id"], "operation": operation, "event": event})
        if not wait:
            return {"state": "pending", "reason": "notifications.enqueued", "event": event}
        payload = receive(connection)
        if payload.get("session_id") != lock["session_id"] or payload.get("state") not in {
            "pending",
            "accepted",
            "unconfirmed",
            "failed",
        }:
            raise NotificationError("Notification receipt is invalid")
        instance = payload.get("instance_id")
        progress = payload.get("progress_at")
        if (
            not isinstance(instance, str)
            or uuid.UUID(instance).hex != instance
            or not isinstance(progress, (float, int))
            or isinstance(progress, bool)
            or not 0 <= boottime() - progress <= Settings.from_snapshot(lock["settings"]).watchdog.observation_max_age
        ):
            raise NotificationError("Notification agent identity or progress is invalid")
        if payload["state"] == "accepted":
            identifier = payload.get("notification_id")
            if type(identifier) is not int or not 0 < identifier < 2**32:
                raise NotificationError("Notification acceptance identifier is invalid")
        return payload


def emit(lock: dict[str, Any], event: str, *, wait: bool = True) -> Result:
    """Delivery failure has no dependency on or authority over containment."""
    from ttp.runtime_records import session_store

    settings = Settings.from_snapshot(lock["settings"])
    if not settings.notifications.enabled:
        return Result()
    if event not in EVENTS:
        raise ValueError("Unknown notification event")
    try:
        receipt = rpc(
            lock, "notify", event=event, timeout=settings.notifications.delivery_timeout if wait else 0.2, wait=wait
        )
    except TimeoutError:
        receipt = {"state": "unconfirmed", "reason": "notifications.agent_timeout", "event": event}
    except (OSError, ValueError, NotificationError):
        receipt = {"state": "failed", "reason": "notifications.agent_unavailable", "event": event}
    result = Result()
    if wait and receipt["state"] == "pending":
        receipt = {**receipt, "state": "unconfirmed", "reason": "notifications.acceptance_pending"}
    if receipt["state"] not in {"accepted", "pending"}:
        result = result.add(
            Diagnostic(
                ExitCode.NOTIFICATION_FAILED,
                receipt["reason"],
                "notifications",
                "deliver",
                "Desktop delivery was not confirmed; inspect CLI and journal",
            )
        )
    try:
        session_store().write("notifications", lock["session_id"], {**receipt, "result": result.as_dict()})
    except Exception:
        result = result.add(
            Diagnostic(
                ExitCode.NOTIFICATION_FAILED,
                "notifications.evidence_write_failed",
                "notifications",
                "deliver",
                "Could not retain notification delivery evidence",
            )
        )
    return result


def stop_agent() -> None:
    subprocess.run([resolve("systemctl"), "stop", UNIT], capture_output=True, check=True, timeout=10)
    UNIT_PATH.unlink(missing_ok=True)
    subprocess.run([resolve("systemctl"), "daemon-reload"], capture_output=True, check=True, timeout=10)


def finish_notifications(lock: dict[str, Any]) -> Result:
    if not lock.get("settings") or not Settings.from_snapshot(lock["settings"]).notifications.enabled:
        return Result()
    result = emit(lock, "stopped")
    try:
        stop_agent()
    except Exception:
        result = result.add(
            Diagnostic(
                ExitCode.NOTIFICATION_FAILED,
                "notifications.agent_stop_failed",
                "notifications",
                "stop",
                "Session stopped, but the desktop agent could not be stopped",
            )
        )
    return result
