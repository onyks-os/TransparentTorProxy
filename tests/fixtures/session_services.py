# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Destructive integration fixture: ONLY inside the dedicated offline container.

Exercises real systemd, nftables, sockets and a private D-Bus server. The dummy
Tor unit is deliberately not a Tor transport test or an Internet leak test.
"""

import json
import os
import pwd
import signal
import subprocess
import time
from pathlib import Path

from ttp import firewall, state
from ttp.firewall.verification import inspect_emergency_rules
from ttp.notifications.service import emit, rpc, start_agent, stop_agent
from ttp.runtime_records import session_store
from ttp.session_safety import mark_stopping, supervision_terminated
from ttp.settings import Settings, WatchdogSettings
from ttp.watchdog.service import start_watchdog, stop_watchdog, watchdog_observation


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout


def eventually(condition, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise AssertionError("Integration condition exceeded its deadline")


def main():
    assert Path("/run/.containerenv").exists()
    assert os.environ.get("TTP_SESSION_INTEGRATION") == "1"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert set(Path("/sys/class/net").iterdir()) == {Path("/sys/class/net/lo")}, "Requires --network none"
    try:
        pwd.getpwnam("ttp-watchdog")
    except KeyError:
        run("/usr/sbin/useradd", "--system", "--no-create-home", "ttp-watchdog")
    state.ensure_runtime_dir()
    session_store().prepare()
    resolver = Path("/run/ttp/test-resolv.conf")
    resolver.write_text("nameserver 127.0.0.1\n")
    resolver.chmod(0o644)
    run("/usr/bin/mount", "--bind", str(resolver), "/etc/resolv.conf")
    Path("/run/systemd/system/ttp-tor.service").write_text("[Service]\nExecStart=/usr/bin/sleep infinity\n")
    run("/usr/bin/systemctl", "daemon-reload")
    run("/usr/bin/systemctl", "start", "ttp-tor")
    settings = Settings(
        watchdog=WatchdogSettings(
            enabled=True,
            readiness_timeout=10,
            heartbeat_interval=1,
            service_timeout=10,
            check_interval=2,
            check_timeout=3,
            observation_max_age=6,
        )
    ).validate()
    for fault in (signal.SIGSTOP, signal.SIGKILL):
        # The deliberately wrong declaration also tests full atomic replacement.
        subprocess.run(
            ["/usr/sbin/nft", "-f", "-"],
            input="add table inet ttp\ndelete table inet ttp\ntable inet ttp {\nchain filter_out {\n}\n}\n",
            text=True,
            check=True,
        )
        state.write_lock(
            settings=settings.snapshot(),
            watchdog_requested=True,
            interface="lo",
            table_fingerprint=firewall.table_fingerprint(),
        )
        lock = state.read_lock(strict=True)
        start_watchdog()
        before = watchdog_observation()
        assert before["value"] == "healthy"
        os.kill(before["pid"], fault)
        eventually(lambda: inspect_emergency_rules().verified)
        eventually(
            lambda before=before: (
                (current := watchdog_observation())["value"] == "emergency"
                and current["instance_id"] != before["instance_id"]
            )
        )
        # Repair must not trust a post-application hash or mere table presence.
        run("/usr/sbin/nft", "insert", "rule", "inet", "ttp", "filter_out", "accept")
        eventually(lambda: inspect_emergency_rules().verified)
        mark_stopping(lock)
        stop_watchdog()
        state.delete_lock()
        firewall.destroy_rules()
        assert supervision_terminated(lock["session_id"]).exit_code == 0
        assert firewall.read_table_listing() is None
        print(f"PASS watchdog {fault.name}, independent containment, restart latch, repair, explicit stop", flush=True)
    target = {"uid": 65534, "gid": 65534, "login_session": "fixture"}
    directory = Path("/run/user/65534")
    directory.mkdir(exist_ok=True)
    os.chown(directory, 65534, 65534)
    run(
        "/usr/sbin/runuser",
        "-u",
        "nobody",
        "--",
        "/usr/bin/dbus-daemon",
        "--session",
        "--address=unix:path=/run/user/65534/bus",
        "--fork",
    )
    run(
        "/usr/bin/systemd-run",
        "--unit=ttp-test-notification-server",
        "--uid=nobody",
        "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/65534/bus",
        "/usr/bin/python3",
        str(Path(__file__).with_name("notification_server.py")),
        "/tmp/ttp-notification-events.json",
    )

    # Wait for private server ownership, not an arbitrary startup sleep.
    def server_ready():
        return (
            subprocess.run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    "nobody",
                    "--",
                    "/usr/bin/busctl",
                    "--address=unix:path=/run/user/65534/bus",
                    "--list",
                ],
                capture_output=True,
                text=True,
            ).stdout.find("org.freedesktop.Notifications")
            >= 0
        )

    eventually(server_ready)
    state.write_lock(settings=Settings().select(notifications=True).snapshot(), notification_target=target)
    lock = state.read_lock(strict=True)
    start_agent(lock, target)
    assert emit(lock, "started").exit_code == 0
    first = rpc(lock, "status")
    assert first["state"] == "accepted"
    assert emit(lock, "started").exit_code == 0
    assert emit(lock, "containment_unconfirmed").exit_code == 0
    events = [json.loads(line) for line in Path("/tmp/ttp-notification-events.json").read_text().splitlines()]
    assert len(events) == 2 and events[0]["expire"] == -1 and events[1]["replaces"] == 42
    pid = int(run("/usr/bin/systemctl", "show", "ttp-notify", "-p", "MainPID", "--value"))
    status = Path(f"/proc/{pid}/status").read_text()
    assert "Uid:\t65534\t65534\t65534\t65534" in status
    assert "CapEff:\t0000000000000000" in status
    run("/usr/bin/systemctl", "stop", "ttp-test-notification-server")
    assert emit(lock, "inconclusive").exit_code == 9
    assert firewall.read_table_listing() is None
    stop_agent()
    assert firewall.read_table_listing() is None
    print(
        "PASS real unprivileged agent, private D-Bus, acceptance, dedup, replacement, failure without isolation",
        flush=True,
    )


if __name__ == "__main__":
    main()
