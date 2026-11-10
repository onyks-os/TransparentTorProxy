# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Confinement evidence, refusal paths, and the privilege boundary."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ttp import apparmor, tor_service
from ttp.exceptions import TorError

POLICY = {"required": True, "profile": "ttp-tor"}


@pytest.mark.parametrize("names,expected", [("capability,apparmor,yama\n", True), ("selinux,bpf", False)])
def test_selected_lsm(names, expected):
    apparmor.LSM.write_text(names)
    # A compiled-in module does not imply an active AppArmor LSM.
    apparmor.ENABLED.write_text("Y")
    assert apparmor.active() is expected


@pytest.mark.parametrize("module,expected", [(None, False), ("N", False), ("Y", None), ("?", None)])
def test_missing_lsm_list(module, expected):
    apparmor.LSM.unlink()
    if module is not None:
        apparmor.ENABLED.write_text(module)
    if expected is None:
        with pytest.raises(TorError):
            apparmor.active()
    else:
        assert apparmor.active() is expected


@pytest.mark.parametrize("content", ["capability,,apparmor", "apparmor/unknown", "\ufffd"])
def test_invalid_lsm_list(content):
    apparmor.LSM.write_text(content)
    with pytest.raises(TorError):
        apparmor.active()


@pytest.mark.parametrize("path_name", ["LSM", "ENABLED"])
def test_kernel_state_unreadable(path_name):
    if path_name == "ENABLED":
        apparmor.LSM.unlink()
    with patch.object(Path, "read_text", side_effect=PermissionError):
        if path_name == "ENABLED":
            # Only the LSM path is absent; denying the module must also refuse.

            def denied(path, **kwargs):
                if path == apparmor.LSM:
                    raise FileNotFoundError
                raise PermissionError

            with patch.object(Path, "read_text", denied), pytest.raises(TorError):
                apparmor.active()
        else:
            with pytest.raises(TorError):
                apparmor.active()


def test_inactive_never_loads_policy():
    with patch.object(apparmor.subprocess, "run") as run:
        assert apparmor.prepare() is None
    run.assert_not_called()


@pytest.fixture
def policy_loader(monkeypatch, tmp_path):
    apparmor.LSM.write_text("capability,apparmor")
    apparmor.PROFILES.write_text("other (enforce)\nttp-tor (enforce)\n")
    monkeypatch.setattr(apparmor.state, "LOCK_DIR", tmp_path)
    with (
        patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o750)),
        patch.object(apparmor.subprocess, "run") as run,
    ):
        run.side_effect = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]
        yield run


def test_policy_is_private_and_no_cache(policy_loader, tmp_path):
    # A previous symlink cannot redirect the privileged writer.
    victim = tmp_path / "unrelated"
    victim.write_text("unchanged")
    policy = tmp_path / "ttp-tor.apparmor"
    policy.symlink_to(victim)
    assert apparmor.prepare() == POLICY
    assert not policy.is_symlink()
    assert stat.S_IMODE(policy.stat().st_mode) == 0o600
    assert victim.read_text() == "unchanged"
    command = policy_loader.call_args_list[1]
    assert command.args[0][1:] == ["--replace", "--skip-cache", str(policy)]
    assert command.kwargs["timeout"] == 30
    assert command.kwargs["check"] is True
    assert command.kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    assert not list(tmp_path.glob(".apparmor-*"))


@pytest.mark.parametrize("code", [0, 2, -1])
def test_container_or_undetermined_virtualization_refuses(policy_loader, code):
    policy_loader.side_effect = [SimpleNamespace(returncode=code)]
    with pytest.raises(TorError, match="host or VM"):
        apparmor.prepare()
    assert policy_loader.call_count == 1


@pytest.mark.parametrize(
    "uid,mode", [(1000, stat.S_IFDIR | 0o700), (0, stat.S_IFDIR | 0o770), (0, stat.S_IFLNK | 0o777)]
)
def test_unsafe_policy_directory(policy_loader, uid, mode):
    with patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)):
        with pytest.raises(TorError, match="Unsafe"):
            apparmor.prepare()
    assert policy_loader.call_count == 1


@pytest.mark.parametrize("profiles", ["ttp-tor (complain)\n", "other (enforce)\n", "prefix-ttp-tor (enforce)\n"])
def test_kernel_must_confirm_enforce(policy_loader, profiles):
    apparmor.PROFILES.write_text(profiles)
    with pytest.raises(TorError, match="enforce"):
        apparmor.prepare()


@pytest.mark.parametrize(
    "error", [PermissionError(), subprocess.TimeoutExpired("parser", 30), subprocess.CalledProcessError(1, "parser")]
)
def test_load_failure_refuses_and_cleans_temporary(policy_loader, tmp_path, error):
    policy_loader.side_effect = [SimpleNamespace(returncode=1), error]
    with pytest.raises(TorError, match="Cannot load"):
        apparmor.prepare()
    assert not list(tmp_path.glob(".apparmor-*"))


def test_source_read_failure_closes_and_cleans(policy_loader, monkeypatch, tmp_path):
    monkeypatch.setattr(apparmor, "POLICY_SOURCE", tmp_path / "missing-profile")
    with pytest.raises(TorError):
        apparmor.prepare()
    assert not list(tmp_path.glob(".apparmor-*"))


@pytest.fixture
def process_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(apparmor, "PROC", tmp_path)
    process = tmp_path / "123"
    attrs = process / "attr/apparmor"
    attrs.mkdir(parents=True)
    label = attrs / "current"
    label.write_text("ttp-tor (enforce)\n")
    with patch.object(apparmor.subprocess, "run") as run:
        run.return_value = SimpleNamespace(stdout="ActiveState=active\nMainPID=123\n")
        yield process, label, run


def test_actual_service_process_enforced(process_evidence):
    _, _, run = process_evidence
    result = apparmor.observe(POLICY, os.getuid())
    if os.getuid() == 0:
        # Managed Tor is never root; model its account independently of runner.
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=103)):
            result = apparmor.observe(POLICY, 103)
    assert result == {
        **POLICY,
        "state": "enforced",
        "reason": "apparmor.process_enforced",
        "pid": 123,
        "label": "ttp-tor (enforce)",
    }
    assert all("show" in call.args[0] for call in run.call_args_list)


@pytest.mark.parametrize(
    "label", ["unconfined", "ttp-tor (complain)", "system_tor (enforce)", "ttp-tor (enforce)//other (enforce)"]
)
def test_wrong_label_is_never_enforced(process_evidence, label):
    _, path, _ = process_evidence
    path.write_text(label)
    with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=103)):
        assert apparmor.observe(POLICY, 103)["state"] == "unverified"


@pytest.mark.parametrize(
    "policy,uid",
    [(None, 103), ({}, 103), ({"required": 1, "profile": "ttp-tor"}, 103), (POLICY, 0), (POLICY, True), (POLICY, None)],
)
def test_invalid_intent_never_queries_process(policy, uid):
    with patch.object(apparmor.subprocess, "run") as run:
        assert apparmor.observe(policy, uid)["state"] == "unknown"
    run.assert_not_called()


@pytest.mark.parametrize(
    "state",
    [
        "ActiveState=inactive\nMainPID=123",
        "ActiveState=active\nMainPID=0",
        "ActiveState=active\nMainPID=bad",
        "malformed",
    ],
)
def test_invalid_systemd_evidence(process_evidence, state):
    _, _, run = process_evidence
    run.return_value.stdout = state
    assert apparmor.observe(POLICY, 103)["state"] == "unknown"


def test_legacy_attribute_fallback_only_if_absent(process_evidence):
    process, label, _ = process_evidence
    label.unlink()
    (process / "attr/current").write_text("ttp-tor (enforce)")
    with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=103)):
        assert apparmor.observe(POLICY, 103)["state"] == "enforced"
        with patch.object(Path, "read_text", side_effect=PermissionError):
            assert apparmor.observe(POLICY, 103)["state"] == "unknown"


def test_wrong_account_or_replaced_service(process_evidence):
    _, _, run = process_evidence
    with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=999)):
        assert apparmor.observe(POLICY, 103)["state"] == "unknown"
    with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=103)):
        run.side_effect = [
            SimpleNamespace(stdout="ActiveState=active\nMainPID=123"),
            SimpleNamespace(stdout="ActiveState=active\nMainPID=124"),
        ]
        assert apparmor.observe(POLICY, 103)["state"] == "unknown"


@pytest.mark.parametrize(
    "error",
    [FileNotFoundError(), subprocess.TimeoutExpired("systemctl", 10), subprocess.CalledProcessError(1, "systemctl")],
)
def test_observation_failure_is_unknown(process_evidence, error):
    process_evidence[2].side_effect = error
    assert apparmor.observe(POLICY, 103)["state"] == "unknown"


@pytest.mark.parametrize("verified", [True, False])
def test_start_requires_actual_label_and_stops_on_failure(verified):
    with (
        patch.object(tor_service, "generate_torrc"),
        patch.object(tor_service, "label_ports_selinux"),
        patch.object(tor_service, "_write_service_unit") as write,
        patch.object(apparmor, "prepare", return_value=POLICY),
        patch.object(apparmor, "observe", return_value={"state": "enforced" if verified else "unknown"}),
        patch.object(tor_service.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=103)),
        patch.object(tor_service.subprocess, "run"),
        patch.object(tor_service, "stop_tor_service") as stop,
    ):
        if verified:
            assert tor_service.start_tor_service("debian-tor") == POLICY
            stop.assert_not_called()
        else:
            with pytest.raises(TorError, match="could not be verified"):
                tor_service.start_tor_service("debian-tor")
            stop.assert_called_once()
        write.assert_called_once_with("debian-tor", "ttp-tor")
    unit = tor_service._build_service_unit_content("debian-tor", "/usr/bin/tor", "ttp-tor")
    assert "\nAppArmorProfile=ttp-tor\n" in unit
    assert "AppArmorProfile=-" not in unit


def test_watchdog_checks_confinement_before_network():
    from ttp.watchdog import integrity

    with (
        patch.object(integrity.state, "read_lock", return_value={"apparmor": POLICY, "tor_uid": 103}),
        patch.object(apparmor, "observe", return_value={"state": "unknown", "reason": "apparmor.evidence_invalid"}),
        patch.object(integrity.subprocess, "run") as run,
    ):
        assert integrity.check_system_integrity() == ("apparmor", "apparmor.evidence_invalid")
    run.assert_not_called()


def test_watchdog_continues_other_checks_when_confinement_is_enforced():
    from ttp.watchdog import integrity

    with (
        patch.object(integrity.state, "read_lock", return_value={"apparmor": POLICY, "tor_uid": 103}),
        patch.object(apparmor, "observe", return_value={"state": "enforced"}),
        patch.object(integrity.dns, "_is_mount_point", return_value=False),
    ):
        assert integrity.check_system_integrity()[0] == "dns"
