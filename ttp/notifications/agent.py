# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Unprivileged desktop agent. Its only accepted operations are notify/status."""

from __future__ import annotations

import argparse
import logging
import os
import socket
import stat
import uuid
from pathlib import Path

from ttp.evidence import boottime
from ttp.notifications.delivery import Delivery, check_server
from ttp.notifications.protocol import EVENTS, peer_uid, receive, send, socket_path
from ttp.settings import NotificationSettings
from ttp.watchdog.progress import notify_progress

logger = logging.getLogger("ttp")


def run_agent(uid: int, session_id: str, watchdog_uid: int, settings: NotificationSettings, heartbeat: float) -> None:
    if os.geteuid() != uid or uid <= 0:
        raise PermissionError("Desktop delivery must run as its non-root recipient")
    uuid.UUID(session_id)
    bus_path = Path(f"/run/user/{uid}/bus")
    info = bus_path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid:
        raise PermissionError("Recipient bus ownership or type is invalid")
    bus = f"unix:path={bus_path}"
    check_server(bus, settings.call_timeout)
    delivery = Delivery(bus, settings)
    path = socket_path(uid, session_id)
    path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(path))
        # Peers are authenticated by kernel credentials. The watchdog does not
        # need the recipient's group, and the recipient never gains ours.
        path.chmod(0o666)
        listener.listen(8)
        listener.settimeout(heartbeat)
        notify_progress(ready=True)
        while True:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                notify_progress()
                continue
            with connection:
                connection.settimeout(1)
                try:
                    if peer_uid(connection) not in {0, watchdog_uid}:
                        continue
                    payload = receive(connection)
                    if payload.get("session_id") != session_id:
                        continue
                    operation = payload.get("operation")
                    event = payload.get("event")
                    if operation == "notify" and isinstance(event, str) and event in EVENTS:
                        receipt = delivery.deliver(payload["event"])
                        if receipt["state"] != "accepted":
                            logger.error(
                                "%s: desktop delivery %s for event %s", receipt["reason"], receipt["state"], event
                            )
                    elif operation == "status":
                        receipt = delivery.last_receipt or {"state": "pending", "reason": "notifications.no_event"}
                    else:
                        continue
                    send(
                        connection,
                        {
                            "session_id": session_id,
                            "instance_id": os.environ.get("INVOCATION_ID"),
                            "progress_at": boottime(),
                            **receipt,
                        },
                    )
                except BrokenPipeError:
                    # Normal for fire-and-forget emergency publishers. The
                    # receipt is retained and available through status.
                    pass
                except (OSError, ValueError):
                    # An asynchronous publisher may have closed after enqueueing.
                    # Delivery evidence remains available to a later status RPC.
                    logger.warning("Notification IPC request could not be completed")
            notify_progress()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--session", required=True)
    parser.add_argument("--watchdog-uid", required=True, type=int)
    parser.add_argument("--call-timeout", type=float, required=True)
    parser.add_argument("--delivery-timeout", type=float, required=True)
    parser.add_argument("--attempts", type=int, required=True)
    parser.add_argument("--heartbeat", type=float, required=True)
    args = parser.parse_args()
    run_agent(
        args.uid,
        args.session,
        args.watchdog_uid,
        NotificationSettings(
            enabled=True,
            call_timeout=args.call_timeout,
            delivery_timeout=args.delivery_timeout,
            attempts=args.attempts,
        ),
        args.heartbeat,
    )


if __name__ == "__main__":
    main()
