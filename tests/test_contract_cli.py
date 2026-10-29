# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""CLI outcome contracts, with private intent files and inert system boundaries."""

import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from ttp import state
from ttp.cli import app
from ttp.evidence import Diagnostic, ExitCode, Result, Verification, VerificationState
from ttp.exceptions import StateError
from ttp.settings import Settings, SettingsError

runner = CliRunner()


@pytest.fixture(autouse=True)
def private_session(tmp_path, monkeypatch):
    from ttp.commands._common import console

    monkeypatch.setattr(console, "quiet", False)
    runtime = tmp_path / "run"
    runtime.mkdir()
    monkeypatch.setattr(state, "LOCK_DIR", runtime)
    monkeypatch.setattr(state, "LOCK_PATH", runtime / "session")
    monkeypatch.setattr(state, "ensure_runtime_dir", lambda: None)
    monkeypatch.setattr(state, "_watchdog_uid_or_root", os.getuid)
    monkeypatch.setattr(state, "_watchdog_gid", os.getgid)
    monkeypatch.setattr(state.os, "fchown", lambda *args: None)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("ttp.cli._setup_logging", Mock())
    monkeypatch.setattr("ttp.state.check_tmpfs_space", Mock())
    monkeypatch.setattr("ttp.settings.CONFIG_PATH", tmp_path / "config")
    state.LOCK_PATH.write_text(
        json.dumps({"session_id": "test", "phase": "running", "settings": Settings().snapshot()})
    )


def test_config_distinguishes_admin_values_from_frozen_session(monkeypatch):
    from ttp.settings import CONFIG_PATH

    CONFIG_PATH.write_text("[watchdog]\ncheck_interval=12\n")
    current = runner.invoke(app, ["config"])
    assert current.exit_code == 0, current.output
    assert json.loads(current.stdout)["settings"]["watchdog"]["check_interval"] == 12
    frozen = runner.invoke(app, ["config", "--session"])
    assert json.loads(frozen.stdout)["settings"]["watchdog"]["check_interval"] == 15
    state.LOCK_PATH.unlink()
    absent = runner.invoke(app, ["config", "--session"])
    assert absent.exit_code == 1 and "No recorded session" in absent.output


@pytest.mark.parametrize("command", [["status"], ["check"]])
def test_unreadable_evidence_fails_loudly(command):
    state.LOCK_PATH.write_text("{")
    result = runner.invoke(app, ["--quiet", *command])
    assert result.exit_code == 1 and "Failed" in result.output


def test_status_json_is_machine_readable_and_separates_operation_from_session(monkeypatch):
    monkeypatch.setattr("ttp.session_report.observe_session", lambda: {"session_exit_code": 8, "health": "unknown"})
    result = runner.invoke(app, ["status", "--json"])
    assert result.exit_code == 0 and json.loads(result.stdout)["session_exit_code"] == 8


@pytest.mark.parametrize("code", [3, 7, 8])
def test_check_loud_diagnostics_and_emergency_advice(monkeypatch, code):
    result = Result().add(Diagnostic(ExitCode(code), "cause.id", "test", "check", "Specific failure"))
    monkeypatch.setattr(
        "ttp.session_report.check_session", lambda: (Verification(VerificationState.INCONCLUSIVE, "reason"), result)
    )
    answer = runner.invoke(app, ["--quiet", "check"])
    assert answer.exit_code == code and "cause.id" in answer.output
    if code in (7, 8):
        assert "sensitive applications" in answer.output


@pytest.mark.parametrize("dns_result", ["ok", "empty", "failure", "missing"])
def test_check_leak_dns_observations_never_mislabel_missing_evidence_as_leaks(monkeypatch, dns_result):
    monkeypatch.setattr(
        "ttp.session_report.check_session",
        lambda: (Verification(VerificationState.CONFIRMED, "tor.confirmed"), Result()),
    )
    monkeypatch.setattr(
        "ttp.commands.session.resolve_optional", lambda name: None if dns_result == "missing" else "/test/dig"
    )
    probe = Mock(return_value=SimpleNamespace(stdout='"ns" "192.0.2.1"' if dns_result == "ok" else "", returncode=0))
    if dns_result == "failure":
        probe.side_effect = subprocess.TimeoutExpired("dig", 10)
    monkeypatch.setattr("ttp.commands.session.subprocess.run", probe)
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 0, result.output
    assert "Leaks detected" not in result.output
    assert "not proof" in result.output


def test_check_leak_refuses_inactive_session():
    state.LOCK_PATH.unlink()
    result = runner.invoke(app, ["check-leak"])
    assert result.exit_code == 1 and "INACTIVE" in result.output


def test_required_watchdog_cannot_be_stopped_separately(monkeypatch):
    lock = state.read_lock()
    lock["watchdog_requested"] = True
    state.LOCK_PATH.write_text(json.dumps(lock))
    stop = Mock()
    monkeypatch.setattr("ttp.watchdog.stop_watchdog", stop)
    result = runner.invoke(app, ["watchdog", "stop"])
    assert result.exit_code == 5 and "requires its watchdog" in result.output
    stop.assert_not_called()


@pytest.mark.parametrize("failure", ["settings", "service"])
def test_manual_watchdog_start_never_succeeds_without_requested_supervision(monkeypatch, failure):
    monkeypatch.setattr("ttp.commands._preflight.require_watchdog_dependency", Mock())
    if failure == "settings":
        monkeypatch.setattr(Settings, "from_snapshot", Mock(side_effect=SettingsError("invalid policy")))
    else:
        monkeypatch.setattr("ttp.watchdog.start_watchdog", Mock(side_effect=OSError("failed")))
        monkeypatch.setattr(
            "ttp.commands.watchdog.request_emergency",
            lambda *args: Result().add(
                Diagnostic(ExitCode.EMERGENCY_VERIFIED, "verified", "firewall", "contain", "verified")
            ),
        )
    result = runner.invoke(app, ["watchdog", "start"])
    assert result.exit_code == (5 if failure == "settings" else 7)


def test_internal_watchdog_crash_is_nonzero(monkeypatch):
    monkeypatch.setattr("ttp.watchdog.supervisor.run_supervisor", Mock(side_effect=StateError("crashed")))
    result = runner.invoke(app, ["watchdog", "run"])
    assert result.exit_code == 1


@pytest.mark.parametrize("unreadable", [False, True])
def test_interrupt_does_not_remove_latched_or_unknown_protection(monkeypatch, unreadable):
    from ttp.commands import lifecycle

    monkeypatch.setattr(
        "ttp.session_safety.emergency_latched",
        Mock(side_effect=StateError() if unreadable else None, return_value=True),
    )
    stop = Mock()
    monkeypatch.setattr(lifecycle, "do_stop", stop)
    with pytest.raises(SystemExit) as error:
        lifecycle.signal_handler(2, None)
    assert error.value.code == 8
    stop.assert_not_called()


def test_restart_refuses_latched_emergency_and_invalid_policy(monkeypatch):
    monkeypatch.setattr("ttp.commands.stop_restart.require_systemd", Mock())
    monkeypatch.setattr("ttp.commands.stop_restart.require_dnssec_compatibility", Mock())
    monkeypatch.setattr("ttp.session_safety.emergency_latched", lambda lock: True)
    result = runner.invoke(app, ["restart"])
    assert result.exit_code == 7
    monkeypatch.setattr("ttp.settings.load_settings", Mock(side_effect=SettingsError("invalid")))
    assert runner.invoke(app, ["restart"]).exit_code == 1


def test_stop_publishes_intent_before_service_stop_even_when_final_notification_fails(monkeypatch):
    from ttp.commands import lifecycle

    for name in (
        "ttp.firewall.apply_teardown_lockdown",
        "ttp.firewall.apply_active_socket_slaughter",
        "ttp.firewall.destroy_rules",
        "ttp.tor_control.graceful_shutdown",
        "ttp.tor_install.stop_tor_service",
        "ttp.tor_install.unlabel_ports_selinux",
        "ttp.dns.restore_dns",
    ):
        monkeypatch.setattr(name, Mock())
    monkeypatch.setattr(lifecycle, "get_uid_from_port", lambda port: 1)
    monkeypatch.setattr(lifecycle, "resolve_optional", lambda name: None)
    monkeypatch.setattr(lifecycle.time, "sleep", Mock())

    def stop():
        assert state.read_lock()["phase"] == "stopping"
        assert state.stop_was_requested("test")

    monkeypatch.setattr("ttp.watchdog.stop_watchdog", stop)
    monkeypatch.setattr(
        "ttp.notifications.service.finish_notifications",
        lambda lock: Result().add(
            Diagnostic(ExitCode.NOTIFICATION_FAILED, "notifications.failed", "notifications", "stop", "Not delivered")
        ),
    )
    result = runner.invoke(app, ["stop"])
    assert result.exit_code == 9 and "Not delivered" in result.output
    assert state.read_lock() is None and state.stop_was_requested("test")


@pytest.mark.parametrize("content", ["{", "[]", '{"session_id": 42}'])
def test_corrupt_stop_marker_is_not_silent_permission_to_rearm(content):
    (state.LOCK_DIR / "stopping.json").write_text(content)
    with pytest.raises(StateError):
        state.stop_was_requested("test")


def test_strict_lock_read_rejects_nonobject_intent():
    state.LOCK_PATH.write_text("[]")
    with pytest.raises(StateError):
        state.read_lock(strict=True)


def test_termination_entrypoint_preserves_session_identity_and_result(monkeypatch):
    handler = Mock(
        return_value=Result().add(
            Diagnostic(ExitCode.CONTAINMENT_UNCONFIRMED, "failed", "session", "terminate", "unknown")
        )
    )
    monkeypatch.setattr("ttp.commands.watchdog.supervision_terminated", handler)
    result = runner.invoke(app, ["watchdog", "terminated", "--session", "test"])
    assert result.exit_code == 8
    handler.assert_called_once_with("test")
