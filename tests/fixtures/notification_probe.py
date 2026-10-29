# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Run actual busctl delivery against a disposable server as a non-root user."""

import json
import os
import select
import subprocess
import sys
from pathlib import Path

from ttp.notifications.delivery import Delivery, check_server
from ttp.settings import NotificationSettings

assert os.geteuid() != 0, "Protocol test must run as a non-root recipient"
output = Path(sys.argv[1])
mode = sys.argv[2]
events = output.with_suffix(".events")
server = subprocess.Popen(
    [
        "/usr/bin/python3",
        str(Path(__file__).with_name("notification_server.py")),
        str(events),
        "1" if mode == "timeout" else "0",
    ],
    stdout=subprocess.PIPE,
    text=True,
)
try:
    assert server.stdout is not None
    assert select.select([server.stdout], [], [], 5)[0], "Fixture server readiness timed out"
    assert server.stdout.readline().strip() == "READY"
    bus = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    check_server(bus, 2)
    timing = (
        NotificationSettings(call_timeout=0.1, delivery_timeout=0.1, attempts=1)
        if mode == "timeout"
        else NotificationSettings()
    )
    sender = Delivery(bus, timing)
    first = sender.deliver("started" if mode == "accept" else "emergency_verified")
    if mode == "timeout":
        assert first["state"] == "unconfirmed", first
        assert events.exists(), "Server must receive the call before its reply times out"
    else:
        assert first["state"] == "accepted" and first["notification_id"] == 42, first
        assert sender.deliver("started")["deduplicated"]
        assert sender.deliver("containment_unconfirmed")["state"] == "accepted"
        calls = [json.loads(line) for line in events.read_text().splitlines()]
        assert len(calls) == 2
        assert calls[0]["replaces"] == 0 and calls[1]["replaces"] == 42
        assert calls[0]["expire"] == -1
        assert calls[1]["urgency"] == 2 and calls[1]["expire"] == 0
        assert calls[0]["actions"] == []
    output.write_text(json.dumps(first))
finally:
    server.terminate()
    server.wait(timeout=5)
