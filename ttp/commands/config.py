# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Display selected configuration and provenance without changing a session."""

import json

import typer

from ttp import state
from ttp.commands._common import print_error, require_root
from ttp.exceptions import StateError
from ttp.settings import Settings, SettingsError, load_settings


def config_command(
    session: bool = typer.Option(False, "--session", help="Show the frozen running-session configuration."),
) -> None:
    require_root()
    try:
        if session:
            lock = state.read_lock(strict=True)
            if not lock:
                raise StateError("No recorded session")
            settings = Settings.from_snapshot(lock.get("settings"))
            origins = lock.get("settings_origins")
        else:
            loaded = load_settings()
            settings, origins = loaded.settings, loaded.origins
        typer.echo(json.dumps({"settings": settings.snapshot(), "origins": origins}, indent=2))
    except (SettingsError, StateError) as exc:
        print_error("Configuration Unavailable", str(exc))
        raise typer.Exit(code=1)
