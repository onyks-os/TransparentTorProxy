# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Disposable notification protocol server, for a private test bus only."""

import json
import sys
import time
from pathlib import Path

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
name = dbus.service.BusName("org.freedesktop.Notifications", bus)
record = Path(sys.argv[1])
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0


class Server(dbus.service.Object):
    @dbus.service.method("org.freedesktop.Notifications", in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return "TTP test server", "TTP tests", "1", "1.2"

    @dbus.service.method("org.freedesktop.Notifications", in_signature="susssasa{sv}i", out_signature="u")
    def Notify(self, app, replaces, icon, title, body, actions, hints, expire):
        with record.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "app": str(app),
                        "replaces": int(replaces),
                        "title": str(title),
                        "body": str(body),
                        "actions": list(actions),
                        "expire": int(expire),
                        "urgency": int(hints["urgency"]),
                    }
                )
                + "\n"
            )
        time.sleep(delay)
        return dbus.UInt32(int(replaces) or 42)


server = Server(bus, "/org/freedesktop/Notifications")
print("READY", flush=True)
GLib.MainLoop().run()
