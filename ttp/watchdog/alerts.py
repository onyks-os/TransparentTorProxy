# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Alerts and lockdown notifications for TTP watchdog."""

import logging
import re

from ttp import state
from ttp.evidence import Diagnostic, ExitCode, Result
from ttp.session_safety import request_emergency

logger = logging.getLogger("ttp")


def _sanitize_alert_text(text: str) -> str:
    """Strip ANSI escape sequences and non-printable control characters."""
    # Strip ANSI escape sequences (e.g. \x1b[31m)
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)
    # Keep only printable characters or space
    return "".join(c for c in text if c.isprintable() or c == " ")


def trigger_emergency_killswitch(failed_component: str, err_msg: str) -> Result:
    """Apply and verify containment; never broadcast to unrelated users."""
    component = _sanitize_alert_text(failed_component)
    logger.critical("Emergency requested: %s (%s)", component, _sanitize_alert_text(err_msg))
    lock = state.read_lock(strict=True)
    if lock is None:
        return Result()
    return request_emergency(
        lock,
        Diagnostic(
            ExitCode.WATCHDOG_UNAVAILABLE if component == "watchdog" else ExitCode.ERROR,
            "watchdog.integrity_failed",
            component,
            "supervise",
            "Required session integrity failed",
        ),
    )
