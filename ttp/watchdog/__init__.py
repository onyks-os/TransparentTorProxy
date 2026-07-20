# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Watchdog & Killswitch Module - Proactive Session Integrity & Auto-Healing."""

# Re-expose standard modules and libraries for test mock compatibility
from pathlib import Path as Path
import shutil as shutil
import subprocess as subprocess
import time as time
import select as select
from ttp import (
    state as state,
    dns as dns,
    firewall as firewall,
    tor_control as tor_control,
)

# Expose internal submodules so they are accessible as attributes on ttp.watchdog
from ttp.watchdog import (
    service as service,
    inotify as inotify,
    integrity as integrity,
    alerts as alerts,
    fsm as fsm,
)

# Re-export the public API
from ttp.watchdog.service import (
    start_watchdog,
    stop_watchdog,
    _write_watchdog_service_unit,
    WATCHDOG_SERVICE_NAME,
    WATCHDOG_SERVICE_PATH,
)
from ttp.watchdog.inotify import run_watchdog_loop
from ttp.watchdog.fsm import WatchdogFSM
from ttp.watchdog.integrity import (
    check_system_integrity,
    attempt_auto_healing,
    is_interface_online,
    has_default_route,
)
from ttp.watchdog.alerts import (
    _sanitize_alert_text,
    trigger_emergency_killswitch,
)

__all__ = [
    "start_watchdog",
    "stop_watchdog",
    "_write_watchdog_service_unit",
    "WATCHDOG_SERVICE_NAME",
    "WATCHDOG_SERVICE_PATH",
    "run_watchdog_loop",
    "WatchdogFSM",
    "check_system_integrity",
    "attempt_auto_healing",
    "is_interface_online",
    "has_default_route",
    "_sanitize_alert_text",
    "trigger_emergency_killswitch",
]
