# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The monitor must not turn historical evidence into a live safety claim."""

from __future__ import annotations

import copy
import io
import signal
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from ttp.cli import app
from ttp.commands import monitor as monitor_command_module
from ttp.monitor import MonitorView, render_monitor


def sample() -> dict:
    return {
        "phase": "running",
        "health": "unknown",
        "session_id": "session-one",
        "watchdog_requested": True,
        "watchdog": {
            "value": "healthy",
            "reason": "watchdog.integrity_ok",
            "instance_id": "instance-one",
            "progress_at": 100.0,
        },
        "verification": {"state": "confirmed", "observed_at": 50.0, "age_seconds": 3600.0},
        "emergency": {"requested": False, "applied": None, "verified": None},
        "notifications": {"state": "accepted"},
        "rejected_packets": 10,
        "diagnostics": [],
    }


def rendered(view: MonitorView) -> str:
    stream = io.StringIO()
    Console(file=stream, force_terminal=False, width=200).print(render_monitor(view))
    return stream.getvalue()


def test_monitor_displays_confinement_loss_as_local_evidence():
    view = MonitorView()
    at = datetime(2026, 11, 10, 10, 0, tzinfo=UTC)
    first = sample()
    first["apparmor"] = {"state": "enforced", "profile": "ttp-tor"}
    view.accept(first, at, boot_now=105.0)
    assert "Tor AppArmor" in rendered(view)
    assert "enforced · ttp-tor · local process evidence" in rendered(view)
    second = copy.deepcopy(first)
    second["apparmor"]["state"] = "unknown"
    view.accept(second, at, boot_now=106.0)
    assert any(event.message == "Tor AppArmor: unknown" for event in view.events)


def test_historical_tor_measurement_and_heartbeat_do_not_create_events():
    view = MonitorView()
    first = sample()
    at = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)
    view.accept(first, at, boot_now=105.0)
    second = copy.deepcopy(first)
    second["verification"]["age_seconds"] = 3605.0
    second["watchdog"]["progress_at"] = 105.0
    view.accept(second, at, boot_now=110.0)

    assert not view.events
    assert view.watchdog_age == 5.0
    assert "historical measurement" in rendered(view)
    assert "progress 5s ago" in rendered(view)


def test_incident_transitions_are_visible_without_claiming_a_leak():
    view = MonitorView()
    at = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)
    view.accept(sample(), at, boot_now=105.0)
    emergency = sample()
    emergency["watchdog"] = {"value": "unknown", "reason": "watchdog.progress_stale"}
    emergency["emergency"] = {"requested": True, "applied": True, "verified": True}
    emergency["health"] = "emergency_verified"
    emergency["rejected_packets"] = 13
    view.accept(emergency, at, boot_now=110.0)

    output = rendered(view)
    assert "Watchdog: healthy → unknown" in output
    assert "Health assessment: emergency_verified" in output
    assert "Emergency containment: kernel rules verified" in output
    assert "verified against kernel rules" in output
    assert "13 (+3 since previous sample) · not a leak count" in output


def test_failed_observation_clears_old_state_and_recovery_is_recorded():
    view = MonitorView()
    at = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)
    view.accept(sample(), at, boot_now=105.0)
    view.unavailable(at, "StateError: unreadable evidence")
    assert view.report is None
    assert "UNKNOWN — StateError: unreadable evidence" in rendered(view)
    assert "healthy" not in rendered(view)

    view.accept(sample(), at, boot_now=110.0)
    assert any(event.message == "Observation restored" for event in view.events)


def test_new_session_resets_history_and_counter_baseline():
    view = MonitorView()
    at = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)
    view.accept(sample(), at, boot_now=105.0)
    changed = sample()
    changed["watchdog"]["value"] = "unknown"
    view.accept(changed, at, boot_now=106.0)
    assert any("Watchdog:" in event.message for event in view.events)

    other = sample()
    other["session_id"] = "session-two"
    other["rejected_packets"] = 1
    view.accept(other, at, boot_now=107.0)
    assert [event.message for event in view.events] == ["Session started or changed"]
    assert view.rejected_delta is None


def test_observed_strings_are_not_interpreted_as_rich_markup():
    view = MonitorView()
    report = sample()
    report["diagnostics"] = [{"reason": "[red]fake[/]", "message": "[bold]not markup[/]\x1b[31m", "active": True}]
    view.accept(report, datetime(2026, 11, 6, 10, 0, tzinfo=UTC), boot_now=105.0)
    output = rendered(view)
    assert "[red]fake[/]" in output
    assert "[bold]not markup[/]" in output
    assert "\x1b" not in output


def test_vpn_path_loss_retains_guard_evidence_in_view_and_history():
    view = MonitorView()
    at = datetime(2026, 11, 6, 10, 0, tzinfo=UTC)
    report = sample()
    report["vpn"] = {"state": "constrained", "reason": "vpn.path_constrained", "guard_verified": True}
    view.accept(report, at, boot_now=105.0)
    changed = copy.deepcopy(report)
    changed["vpn"].update(state="unknown", reason="vpn.path_lost")
    view.accept(changed, at, boot_now=110.0)
    output = rendered(view)
    assert "Required VPN: unknown" in output
    assert "guard verified=True" in output
    assert "not a remote liveness proof" in output


def test_non_terminal_invocation_points_scripts_to_status_json(monkeypatch):
    monkeypatch.setattr(monitor_command_module, "require_root", lambda: None)
    monkeypatch.setattr(monitor_command_module, "_terminal_available", lambda: False)
    with patch("ttp.cli._setup_logging"):
        result = CliRunner().invoke(app, ["monitor"])
    assert result.exit_code == 2
    assert "status --json" in result.output


@pytest.mark.parametrize("interruption", ["ctrl_c", "sigterm"])
def test_closing_monitor_never_stops_session(monkeypatch, interruption):
    monkeypatch.setattr(monitor_command_module, "require_root", lambda: None)
    monkeypatch.setattr(monitor_command_module, "_terminal_available", lambda: True)
    monkeypatch.setattr(monitor_command_module, "observe_session", sample)
    monkeypatch.setattr(monitor_command_module, "boottime", lambda: 105.0)

    class FakeLive:
        def __init__(self, *args, **kwargs):
            self.updates = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def update(self, *args, **kwargs):
            self.updates += 1

    def interrupt(_seconds):
        if interruption == "ctrl_c":
            raise KeyboardInterrupt
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)

    monkeypatch.setattr(monitor_command_module, "Live", FakeLive)
    monkeypatch.setattr(monitor_command_module.time, "sleep", interrupt)
    original_handler = signal.getsignal(signal.SIGTERM)
    with patch("ttp.commands.lifecycle.do_stop", side_effect=AssertionError("monitor stopped TTP")):
        monitor_command_module.monitor_command(interval=2.0)
    assert signal.getsignal(signal.SIGTERM) == original_handler
