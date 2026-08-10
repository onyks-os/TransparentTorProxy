# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Watchdog & Killswitch Module - Proactive Session Integrity & Auto-Healing."""

# Re-expose standard modules and libraries for test mock compatibility
import select as select
import shutil as shutil
import subprocess as subprocess
import time as time
from pathlib import Path as Path

from ttp import (
    dns as dns,
)
from ttp import (
    firewall as firewall,
)
from ttp import (
    state as state,
)
from ttp import (
    tor_control as tor_control,
)
from ttp.watchdog import (
    alerts as alerts,
)
from ttp.watchdog import (
    fsm as fsm,
)
from ttp.watchdog import (
    inotify as inotify,
)
from ttp.watchdog import (
    integrity as integrity,
)

# Expose internal submodules so they are accessible as attributes on ttp.watchdog
from ttp.watchdog import (
    service as service,
)
from ttp.watchdog.alerts import (
    _sanitize_alert_text,
    trigger_emergency_killswitch,
)
from ttp.watchdog.fsm import WatchdogFSM
from ttp.watchdog.inotify import run_watchdog_loop
from ttp.watchdog.integrity import (
    attempt_auto_healing,
    check_system_integrity,
    has_default_route,
    is_interface_online,
)

# Re-export the public API
from ttp.watchdog.service import (
    WATCHDOG_SERVICE_NAME,
    WATCHDOG_SERVICE_PATH,
    _write_watchdog_service_unit,
    start_watchdog,
    stop_watchdog,
)

__all__ = [
    "WATCHDOG_SERVICE_NAME",
    "WATCHDOG_SERVICE_PATH",
    "WatchdogFSM",
    "_sanitize_alert_text",
    "_write_watchdog_service_unit",
    "attempt_auto_healing",
    "check_system_integrity",
    "has_default_route",
    "is_interface_online",
    "run_watchdog_loop",
    "start_watchdog",
    "stop_watchdog",
    "trigger_emergency_killswitch",
]
