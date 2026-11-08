# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Transient, read-only presentation of existing session observations."""

from __future__ import annotations

import math
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


@dataclass(frozen=True)
class MonitorEvent:
    at: datetime
    message: str


@dataclass
class MonitorView:
    """Keep only changes observed during this invocation of ``ttp monitor``."""

    events: deque[MonitorEvent] = field(default_factory=lambda: deque(maxlen=6))
    report: dict[str, Any] | None = None
    error: str | None = None
    sampled_at: datetime | None = None
    rejected_delta: int | None = None
    watchdog_age: float | None = None
    _seen_sample: bool = False
    _session_id: str | None = None
    _previous_count: int | None = None

    def _record(self, at: datetime, message: str) -> None:
        self.events.append(MonitorEvent(at, message))

    def unavailable(self, at: datetime, reason: str) -> None:
        """Invalidate the displayed sample; never leave old evidence looking live."""
        if self.error is None:
            self._record(at, "Observation became unavailable")
        self.report = None
        self.error = reason
        self.sampled_at = at
        self.rejected_delta = None
        self.watchdog_age = None
        self._previous_count = None
        self._seen_sample = True

    def accept(self, report: dict[str, Any], at: datetime, *, boot_now: float) -> None:
        """Accept one complete snapshot and retain only meaningful transitions."""
        session_id = report.get("session_id")
        if not isinstance(session_id, str):
            session_id = None
        if self._seen_sample and session_id != self._session_id:
            self.events.clear()
            self._previous_count = None
            label = (
                "Session ended"
                if report.get("phase") == "absent"
                else "Session identity unavailable"
                if session_id is None
                else "Session started or changed"
            )
            self._record(at, label)
        elif self.error is not None:
            self._record(at, "Observation restored")
        elif self.report is not None:
            self._record_changes(self.report, report, at)

        count = report.get("rejected_packets")
        self.rejected_delta = None
        if type(count) is int:
            if self._previous_count is not None:
                if count >= self._previous_count:
                    self.rejected_delta = count - self._previous_count
                else:
                    self._record(at, "Rejected-packet counter reset")
            self._previous_count = count
        else:
            self._previous_count = None

        watchdog = report.get("watchdog", {})
        progress_at = watchdog.get("progress_at") if isinstance(watchdog, dict) else None
        self.watchdog_age = None
        if isinstance(progress_at, (int, float)) and not isinstance(progress_at, bool):
            age = boot_now - progress_at
            if math.isfinite(age) and age >= 0:
                self.watchdog_age = age

        self.report = report
        self.error = None
        self.sampled_at = at
        self._session_id = session_id
        self._seen_sample = True

    def _record_changes(self, old: dict[str, Any], new: dict[str, Any], at: datetime) -> None:
        old_vpn, new_vpn = old.get("vpn", {}), new.get("vpn", {})
        if tuple(old_vpn.get(key) for key in ("state", "reason", "guard_verified")) != tuple(
            new_vpn.get(key) for key in ("state", "reason", "guard_verified")
        ):
            self._record(at, f"Required VPN: {new.get('vpn', {}).get('state', 'unknown')}")
        if old.get("phase") != new.get("phase"):
            self._record(at, f"Session phase: {old.get('phase', 'unknown')} → {new.get('phase', 'unknown')}")
        if old.get("health") != new.get("health"):
            self._record(at, f"Health assessment: {new.get('health', 'unknown')}")

        old_watchdog = old.get("watchdog", {})
        new_watchdog = new.get("watchdog", {})
        old_wd = (old_watchdog.get("value"), old_watchdog.get("reason"))
        new_wd = (new_watchdog.get("value"), new_watchdog.get("reason"))
        if old_wd != new_wd:
            self._record(
                at, f"Watchdog: {old_wd[0] or 'unknown'} → {new_wd[0] or 'unknown'} ({new_wd[1] or 'no reason'})"
            )
        elif old_watchdog.get("instance_id") != new_watchdog.get("instance_id"):
            self._record(at, "Watchdog service instance changed")

        old_verification = old.get("verification", {})
        new_verification = new.get("verification", {})
        old_ver = (old_verification.get("state"), old_verification.get("observed_at"))
        new_ver = (new_verification.get("state"), new_verification.get("observed_at"))
        if old_ver != new_ver:
            self._record(at, f"New Tor verification record: {new_ver[0] or 'unknown'}")

        old_emergency = old.get("emergency", {})
        new_emergency = new.get("emergency", {})
        old_em = tuple(old_emergency.get(key) for key in ("requested", "applied", "verified"))
        new_em = tuple(new_emergency.get(key) for key in ("requested", "applied", "verified"))
        if old_em != new_em:
            if new_em[0]:
                state = "kernel rules verified" if new_em[2] is True else "containment unconfirmed"
                self._record(at, f"Emergency containment: {state}")
            else:
                self._record(at, "Emergency containment no longer requested")

        old_notifications = old.get("notifications", {})
        new_notifications = new.get("notifications", {})
        old_delivery = (old_notifications.get("state"), old_notifications.get("reason"))
        new_delivery = (new_notifications.get("state"), new_notifications.get("reason"))
        if old_delivery != new_delivery:
            self._record(at, f"Notifications: {new_delivery[0] or 'unknown'}")


def _age(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0:
        return f"{value:.0f}s ago"
    return "age unknown"


def _text(value: object, *, style: str = "") -> Text:
    # Rich Text does not interpret markup, but raw terminal control characters
    # in observed error strings would still reach the operator's terminal.
    safe = "".join("?" if unicodedata.category(char).startswith("C") else char for char in str(value))
    return Text(safe, style=style)


def render_monitor(view: MonitorView) -> Group:
    """Render data as text, so observed strings cannot become Rich markup."""
    stamp = view.sampled_at.strftime("%H:%M:%S") if view.sampled_at else "waiting for first sample"
    heading = Text(f"TTP monitor · sample {stamp} · passive local observations", style="bold cyan")
    current = Table.grid(padding=(0, 1))
    current.add_column(style="bold", no_wrap=True)
    current.add_column()

    if view.error is not None:
        current.add_row("Observation", _text(f"UNKNOWN — {view.error}", style="bold red"))
    elif view.report is None:
        current.add_row("Observation", "Waiting for first sample")
    elif view.report.get("phase") == "absent":
        current.add_row("Session", "No recorded TTP session; monitor will keep watching")
    else:
        report = view.report
        session_id = str(report.get("session_id") or "unknown")
        current.add_row("Session", _text(f"{report.get('phase', 'unknown')} · {session_id[:12]}"))
        current.add_row("Health assessment", _text(report.get("health", "unknown")))
        if "vpn" in report:
            vpn = report["vpn"]
            current.add_row(
                "Required VPN",
                _text(
                    f"{vpn.get('state', 'unknown')} · guard verified={vpn.get('guard_verified', False)} · not a remote liveness proof"
                ),
            )

        verification = report.get("verification", {})
        ver_state = str(verification.get("state", "unknown"))
        ver_text = (
            f"{ver_state} · {_age(verification.get('age_seconds'))} · historical measurement"
            if ver_state != "not_run"
            else "not run"
        )
        current.add_row("Tor check", _text(ver_text))

        watchdog = report.get("watchdog", {})
        if report.get("watchdog_requested"):
            wd_value = str(watchdog.get("value", "unknown"))
            wd_text = f"{wd_value} · {watchdog.get('reason', 'reason unknown')}"
            if view.watchdog_age is not None:
                wd_text += f" · progress {_age(view.watchdog_age)}"
            style = "green" if wd_value == "healthy" else "bold yellow"
            current.add_row("Watchdog", _text(wd_text, style=style))
        else:
            current.add_row("Watchdog", "not requested")

        emergency = report.get("emergency", {})
        if emergency.get("requested"):
            if emergency.get("verified") is True:
                em_text = "requested · applied · verified against kernel rules"
            else:
                em_text = f"requested · applied={emergency.get('applied')} · containment UNCONFIRMED"
            current.add_row("Emergency", _text(em_text, style="bold red"))
        else:
            current.add_row("Emergency", "not requested; normal routing is not verified by this field")

        notifications = report.get("notifications", {})
        notify_state = str(notifications.get("state", "unknown"))
        notify_text = (
            f"{notify_state} · server acceptance does not prove display" if notify_state == "accepted" else notify_state
        )
        current.add_row("Notifications", _text(notify_text))

        count = report.get("rejected_packets")
        if type(count) is int:
            delta = f" (+{view.rejected_delta} since previous sample)" if view.rejected_delta is not None else ""
            current.add_row("Rejected packets", _text(f"{count}{delta} · not a leak count"))

        diagnostics = report.get("diagnostics", [])
        for diagnostic in diagnostics:
            if isinstance(diagnostic, dict) and diagnostic.get("active", True):
                current.add_row(
                    "Reason", _text(f"{diagnostic.get('reason', 'unknown')}: {diagnostic.get('message', '')}")
                )

    recent = Table.grid(padding=(0, 1))
    recent.add_column(style="dim", no_wrap=True)
    recent.add_column()
    if view.events:
        for event in view.events:
            recent.add_row(event.at.strftime("%H:%M:%S"), _text(event.message))
    else:
        recent.add_row("", "No changes observed in this window")

    footer = Text("Ctrl-C closes this view without stopping TTP · run ttp check for an active Tor test", style="dim")
    return Group(
        heading,
        Panel(current, title="Current observation"),
        Panel(recent, title="Changes seen since opening monitor"),
        footer,
    )
