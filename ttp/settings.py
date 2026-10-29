# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Validated session settings; no I/O or environment reads at import time.

Only the fixed administrator-owned file is read by the CLI. The effective
snapshot is stored with the session, so editing the file cannot silently change
a running watchdog's deadlines or requirements. See ADR 0013.
"""

from __future__ import annotations

import configparser
import math
import os
import stat
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any

from ttp.exceptions import TTPError

CONFIG_PATH = Path("/etc/ttp/ttp.conf")
MAX_CONFIG_BYTES = 16384


class _ConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


class SettingsError(TTPError):
    """An unknown, unsafe or inconsistent setting refused before network changes."""


@dataclass(frozen=True)
class WatchdogSettings:
    enabled: bool = False
    readiness_timeout: float = 30
    heartbeat_interval: float = 5
    service_timeout: float = 30
    check_interval: float = 15
    check_timeout: float = 10
    observation_max_age: float = 30


@dataclass(frozen=True)
class VerificationSettings:
    timeout: float = 60


@dataclass(frozen=True)
class NotificationSettings:
    enabled: bool = False
    readiness_timeout: float = 15
    call_timeout: float = 5
    delivery_timeout: float = 15
    attempts: int = 3


@dataclass(frozen=True)
class Settings:
    watchdog: WatchdogSettings = WatchdogSettings()
    verification: VerificationSettings = VerificationSettings()
    notifications: NotificationSettings = NotificationSettings()

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> Settings:
        for section, values in self.snapshot().items():
            for key, value in values.items():
                name = f"{section}.{key}"
                if key == "enabled":
                    if type(value) is not bool:
                        raise SettingsError(f"{name} must be a boolean")
                elif key == "attempts":
                    if type(value) is not int or not 1 <= value <= 10:
                        raise SettingsError(f"{name} must be an integer from 1 to 10")
                elif type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 3600:
                    raise SettingsError(f"{name} must be a finite number of seconds greater than 0 and at most 3600")
        wd = self.watchdog
        # Leave room for a bounded check plus the next nominal heartbeat, and
        # satisfy systemd's recommendation to report at least twice per timeout.
        if 2 * (wd.check_timeout + wd.heartbeat_interval) > wd.service_timeout:
            raise SettingsError("watchdog.service_timeout must be at least 2 * (check_timeout + heartbeat_interval)")
        if wd.readiness_timeout < wd.check_timeout + wd.heartbeat_interval:
            raise SettingsError("watchdog.readiness_timeout must cover check_timeout + heartbeat_interval")
        if wd.observation_max_age < wd.check_interval + wd.check_timeout:
            raise SettingsError("watchdog.observation_max_age must cover check_interval + check_timeout")
        if self.notifications.delivery_timeout < self.notifications.call_timeout:
            raise SettingsError("notifications.delivery_timeout must cover call_timeout")
        if (
            self.notifications.enabled
            and wd.service_timeout <= self.notifications.delivery_timeout + wd.heartbeat_interval
        ):
            raise SettingsError(
                "watchdog.service_timeout must exceed notification delivery_timeout + heartbeat_interval"
            )
        return self

    def select(self, *, watchdog: bool | None = None, notifications: bool | None = None) -> Settings:
        """Apply explicit CLI choices; None retains the administrator's value."""
        return replace(
            self,
            watchdog=replace(self.watchdog, enabled=self.watchdog.enabled if watchdog is None else watchdog),
            notifications=replace(
                self.notifications, enabled=self.notifications.enabled if notifications is None else notifications
            ),
        ).validate()

    @classmethod
    def from_snapshot(cls, raw: object) -> Settings:
        """Reject corrupt/newer snapshots instead of changing session policy."""
        if not isinstance(raw, dict) or set(raw) != {"watchdog", "verification", "notifications"}:
            raise SettingsError("Invalid settings snapshot sections")
        parsed: dict[str, Any] = {}
        for section, kind in _SECTIONS.items():
            values = raw[section]
            if not isinstance(values, dict) or set(values) != {field.name for field in fields(kind)}:
                raise SettingsError(f"Invalid settings snapshot for {section}")
            parsed[section] = kind(**values)
        return cls(**parsed).validate()


_SECTIONS = {"watchdog": WatchdogSettings, "verification": VerificationSettings, "notifications": NotificationSettings}


@dataclass(frozen=True)
class LoadedSettings:
    settings: Settings
    origins: dict[str, str]

    def select(self, *, watchdog: bool | None = None, notifications: bool | None = None) -> LoadedSettings:
        origins = dict(self.origins)
        for section, value in (("watchdog", watchdog), ("notifications", notifications)):
            if value is not None:
                origins[f"{section}.enabled"] = "command line"
        return LoadedSettings(self.settings.select(watchdog=watchdog, notifications=notifications), origins)


def _read_file(path: Path) -> str | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise SettingsError(f"{path} must be a root-owned regular file, not writable by group or others")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(MAX_CONFIG_BYTES + 1)
        if len(content) > MAX_CONFIG_BYTES:
            raise SettingsError(f"{path} exceeds {MAX_CONFIG_BYTES} bytes")
        return content.decode("utf-8")
    finally:
        os.close(fd)


def load_settings(path: Path | None = None) -> LoadedSettings:
    """Read the fixed config path (an alternate path is used by isolated tests)."""
    path = CONFIG_PATH if path is None else path
    defaults = Settings()
    origins = {f"{section}.{key}": "default" for section, values in defaults.snapshot().items() for key in values}
    try:
        content = _read_file(path)
        if content is None:
            return LoadedSettings(defaults, origins)
        parser = _ConfigParser(interpolation=None, strict=True)
        parser.read_string(content)
        if parser.defaults():
            raise SettingsError("[DEFAULT] inheritance is not supported; set each value in its section")
        parsed: dict[str, Any] = {}
        for section in parser.sections():
            if section not in _SECTIONS:
                raise SettingsError(f"Unknown settings section: {section}")
            kind = _SECTIONS[section]
            values: dict[str, Any] = {}
            for key, value in parser[section].items():
                if key not in {field.name for field in fields(kind)}:
                    raise SettingsError(f"Unknown setting: {section}.{key}")
                if key == "enabled":
                    if value not in {"true", "false"}:
                        raise SettingsError(f"{section}.{key} must be true or false")
                    values[key] = value == "true"
                else:
                    values[key] = int(value) if key == "attempts" else float(value)
                origins[f"{section}.{key}"] = str(path)
            parsed[section] = kind(**values)
        return LoadedSettings(Settings(**parsed).validate(), origins)
    except (OSError, ValueError, configparser.Error) as exc:
        raise SettingsError(f"Cannot load {path}: {exc}") from exc
