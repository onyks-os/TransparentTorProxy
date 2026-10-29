# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Required supervision with readiness, useful progress and a persistent latch."""

from __future__ import annotations

import logging
import os
import select
import socket
import uuid
from typing import Any

from ttp import state
from ttp.evidence import Diagnostic, ExitCode, boottime
from ttp.exceptions import StateError
from ttp.runtime_records import session_store
from ttp.session_safety import emergency_latched, request_emergency
from ttp.settings import Settings
from ttp.watchdog.fsm import WatchdogFSM
from ttp.watchdog.integrity import attempt_auto_healing, check_system_integrity
from ttp.watchdog.progress import CheckDeadline, bounded_check, notify_progress

logger = logging.getLogger("ttp")


def _cause(component: str, reason: str) -> Diagnostic:
    return Diagnostic(
        ExitCode.WATCHDOG_UNAVAILABLE if component == "watchdog" else ExitCode.ERROR,
        reason,
        component,
        "supervise",
        "Required local integrity unavailable",
    )


def run_supervisor() -> None:
    lock = state.read_lock(strict=True)
    if not lock or lock.get("phase") == "stopping":
        return
    settings = Settings.from_snapshot(lock.get("settings")).watchdog
    session_id = lock.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise StateError("Watchdog requires a session identity")
    instance_id = os.environ.get("INVOCATION_ID", "")
    if not instance_id or uuid.UUID(instance_id).hex != instance_id:
        raise StateError("Watchdog requires a systemd invocation identity")
    store = session_store()
    fsm = WatchdogFSM()
    observation: dict[str, Any] = {"value": "unknown", "instance_id": instance_id, "observed_at": None}
    ready = False
    last_check = -settings.check_interval

    def publish(value: str, reason: str, *, completed: bool = False) -> None:
        observation.update(value=value, reason=reason)
        observation["observed_at"] = boottime() if completed else None
        store.write("watchdog", session_id, observation)

    def contain(cause: Diagnostic) -> None:
        result = request_emergency(lock, cause, repair=True)
        observation["result"] = result.as_dict()
        publish("emergency", "watchdog.emergency_latched", completed=True)

    try:
        publish("unknown", "watchdog.initializing")
        fsm.initialize(interface=lock.get("interface"), interval_seconds=settings.check_interval)
        if fsm.netlink_socket is None or fsm.inotify_fd < 0 or fsm.wd_real < 0 or fsm.wd_link < 0:
            raise StateError("Required event subscriptions could not be established")
        while True:
            current = state.read_lock(strict=True)
            if not current or current.get("session_id") != session_id or current.get("phase") == "stopping":
                return
            try:
                latched = emergency_latched(lock, store=store)
            except StateError:
                contain(_cause("session", "session.evidence_invalid"))
                latched = True

            if latched:
                contain(_cause("watchdog", "watchdog.emergency_latched"))
            elif boottime() - last_check >= settings.check_interval:
                publish("unknown", "watchdog.evaluation_pending")
                try:
                    failed, detail = bounded_check(check_system_integrity, settings.check_timeout)
                except CheckDeadline:
                    contain(_cause("watchdog", "watchdog.check_timeout"))
                else:
                    recovering = failed == "tor"
                    if failed == "tor":
                        # Retain existing Tor-only healing. Progress is reported
                        # between bounded stages, with no healthy observation.
                        publish("unknown", "watchdog.tor_healing")
                        if ready:
                            notify_progress()
                        try:
                            healed = bounded_check(lambda: attempt_auto_healing("tor"), settings.check_timeout)
                            if healed:
                                if ready:
                                    notify_progress()
                                failed, detail = bounded_check(check_system_integrity, settings.check_timeout)
                        except CheckDeadline:
                            failed, detail = "watchdog", "Local healing exceeded its deadline"
                    if failed:
                        logger.error("Local integrity failure in %s: %s", failed, detail)
                        contain(_cause(failed, f"watchdog.{failed}_integrity_failed"))
                    else:
                        publish("healthy", "watchdog.local_integrity_verified", completed=True)
                        if recovering:
                            from ttp.notifications.service import emit

                            emit(lock, "recovered", wait=False)
                last_check = boottime()
            # READY only follows subscriptions AND initial evaluation. A ready
            # supervisor may be holding an emergency; start must inspect both.
            store.write("watchdog", session_id, observation)
            notify_progress(ready=not ready)
            ready = True
            assert fsm.netlink_socket is not None
            sources: list[socket.socket | int] = [fsm.netlink_socket, fsm.inotify_fd]
            delay = min(settings.heartbeat_interval, max(0, settings.check_interval - (boottime() - last_check)))
            if latched:
                delay = settings.heartbeat_interval
            try:
                readable, _, _ = select.select(sources, [], [], delay)
            except InterruptedError:
                continue
            if readable:
                # Invalidate before draining queues or doing any expensive work.
                publish("unknown", "watchdog.event_invalidated")
                if fsm.inotify_fd in readable:
                    from ttp.watchdog.inotify import inotify_watch_lost

                    try:
                        lost = inotify_watch_lost(os.read(fsm.inotify_fd, 65536))
                    except BlockingIOError:
                        lost = False
                    if lost:
                        fsm.readd_watch()
                        if fsm.wd_real < 0 or fsm.wd_link < 0:
                            raise StateError("DNS event subscription was lost")
                fsm.flush_event_buffers(readable)
                last_check = -settings.check_interval
    except Exception:
        logger.exception("Required watchdog failed")
        request_emergency(lock, _cause("watchdog", "watchdog.failed"), repair=True)
        raise
    finally:
        fsm.shutdown()
