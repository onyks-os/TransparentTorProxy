# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Exercise administrative settings as files and immutable session snapshots."""

import math
import os
import stat
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from ttp import settings


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "ttp.conf"
    path.write_text("")
    path.chmod(0o644)
    real_fstat = os.fstat

    def root_owned(fd):
        actual = real_fstat(fd)
        return SimpleNamespace(st_mode=actual.st_mode, st_uid=0)

    # The filesystem boundary only: contents, mode, descriptor handling and
    # all parsing are real, regardless of the developer's UID.
    monkeypatch.setattr(settings.os, "fstat", root_owned)
    return path


def test_absent_file_keeps_optional_features_off_and_approved_budgets(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_PATH", tmp_path / "absent")
    result = settings.load_settings()
    assert not result.settings.watchdog.enabled
    assert not result.settings.notifications.enabled
    assert result.settings.watchdog.readiness_timeout == 30
    assert result.settings.watchdog.check_interval == 15
    assert result.settings.verification.timeout == 60
    assert set(result.origins.values()) == {"default"}


def test_documented_example_is_valid_and_complete(config_file):
    config_file.write_text((Path(__file__).parents[1] / "assets/ttp.conf.example").read_text())
    result = settings.load_settings(config_file)
    assert result.settings == settings.Settings()
    assert set(result.origins.values()) == {str(config_file)}


def test_explicit_cli_false_overrides_admin_true_without_mutating_snapshot(config_file):
    config_file.write_text("[watchdog]\nenabled=true\n[verification]\ntimeout=120\n")
    loaded = settings.load_settings(config_file)
    selected = loaded.select(watchdog=False, notifications=True)
    assert loaded.settings.watchdog.enabled
    assert not selected.settings.watchdog.enabled
    assert selected.settings.notifications.enabled
    assert selected.settings.verification.timeout == 120
    assert selected.origins["watchdog.enabled"] == "command line"
    assert selected.origins["notifications.enabled"] == "command line"
    assert selected.origins["verification.timeout"] == str(config_file)
    assert loaded.origins["watchdog.enabled"] == str(config_file)
    assert loaded.select().settings == loaded.settings
    with pytest.raises(FrozenInstanceError):
        loaded.settings.verification.timeout = 1


def test_running_session_uses_saved_values_after_file_is_changed(config_file):
    config_file.write_text("[notifications]\nenabled=true\nattempts=2\n")
    initial = settings.load_settings(config_file).settings
    snapshot = initial.snapshot()
    config_file.write_text("[notifications]\nenabled=false\nattempts=1\n")
    assert settings.Settings.from_snapshot(snapshot) == initial
    assert settings.load_settings(config_file).settings != initial
    snapshot["notifications"]["enabled"] = False
    assert initial.notifications.enabled


@pytest.mark.parametrize(
    "content",
    [
        "[watcdog]\nenabled=true\n",
        "[watchdog]\ncheck_intervl=15\n",
        "[watchdog]\nEnabled=true\n",
        "[watchdog]\nenabled=yes\n",
        "[DEFAULT]\nenabled=true\n[watchdog]\n",
        "[verification]\ntimeout=NaN\n",
        "[verification]\ntimeout=inf\n",
        "[verification]\ntimeout=-1\n",
        "[verification]\ntimeout=0\n",
        "[verification]\ntimeout=3601\n",
        "[verification]\ntimeout=oops\n",
        "[verification]\ntimeout=30\ntimeout=60\n",
        "[notifications]\nattempts=1.5\n",
        "[notifications]\nattempts=0\n",
        "[notifications]\nattempts=11\n",
        "[notifications]\ndelivery_timeout=1\n",
        "[watchdog]\nservice_timeout=29\n",
        "[watchdog]\nreadiness_timeout=14\n",
        "[watchdog]\nobservation_max_age=24\n",
        "not an ini file",
    ],
)
def test_mistyped_or_inconsistent_policy_is_never_silently_accepted(config_file, content):
    config_file.write_text(content)
    with pytest.raises(settings.SettingsError):
        settings.load_settings(config_file)


@pytest.mark.parametrize("mode", [0o664, 0o666])
def test_group_or_world_writable_configuration_is_refused(config_file, mode):
    config_file.chmod(mode)
    with pytest.raises(settings.SettingsError, match="root-owned regular file"):
        settings.load_settings(config_file)


def test_non_root_configuration_is_refused(config_file, monkeypatch):
    monkeypatch.setattr(settings.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=1234))
    with pytest.raises(settings.SettingsError, match="root-owned"):
        settings.load_settings(config_file)


def test_symlink_is_not_followed_even_when_target_is_valid(config_file):
    link = config_file.parent / "link"
    link.symlink_to(config_file)
    with pytest.raises(settings.SettingsError, match="Cannot load"):
        settings.load_settings(link)


def test_nonregular_file_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(settings.SettingsError, match="regular file"):
        settings.load_settings(fifo)


@pytest.mark.parametrize("content", [b"\xff", b"#" * (settings.MAX_CONFIG_BYTES + 1)])
def test_invalid_or_unbounded_input_is_refused(config_file, content):
    config_file.write_bytes(content)
    with pytest.raises(settings.SettingsError):
        settings.load_settings(config_file)


def test_read_errors_are_configuration_errors(config_file, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(settings.os, "open", denied)
    with pytest.raises(settings.SettingsError, match="denied"):
        settings.load_settings(config_file)


@pytest.mark.parametrize("raw", [None, [], {}, {"new_section": {}}])
def test_invalid_snapshot_sections_are_refused(raw):
    with pytest.raises(settings.SettingsError, match="snapshot sections"):
        settings.Settings.from_snapshot(raw)


@pytest.mark.parametrize("value", [None, {}, {"timeout": 60, "extra": 1}])
def test_invalid_snapshot_fields_are_refused(value):
    snapshot = settings.Settings().snapshot()
    snapshot["verification"] = value
    with pytest.raises(settings.SettingsError, match="snapshot for verification"):
        settings.Settings.from_snapshot(snapshot)


@pytest.mark.parametrize(
    "key,value", [("enabled", 1), ("attempts", True), ("call_timeout", True), ("call_timeout", math.nan)]
)
def test_snapshot_types_cannot_weaken_validation(key, value):
    snapshot = settings.Settings().snapshot()
    snapshot["notifications"][key] = value
    with pytest.raises(settings.SettingsError):
        settings.Settings.from_snapshot(snapshot)


def test_longer_consistent_profile_is_supported():
    baseline = settings.Settings()
    custom = replace(
        baseline,
        watchdog=replace(
            baseline.watchdog,
            heartbeat_interval=10,
            check_timeout=20,
            service_timeout=60,
            readiness_timeout=60,
            check_interval=30,
            observation_max_age=60,
        ),
    )
    assert custom.validate() == custom


def test_notification_delivery_must_not_starve_agent_heartbeat():
    from dataclasses import replace

    from ttp.settings import NotificationSettings, Settings, SettingsError

    settings = Settings(notifications=NotificationSettings(enabled=True, delivery_timeout=30))
    with pytest.raises(SettingsError, match="notification delivery_timeout"):
        settings.validate()
    # Headless operation does not depend on the disabled desktop's budget.
    replace(settings, notifications=replace(settings.notifications, enabled=False)).validate()
