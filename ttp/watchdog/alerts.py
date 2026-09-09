# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Alerts and lockdown notifications for TTP watchdog."""

import logging
import re
import subprocess

from ttp import firewall
from ttp.paths import resolve_optional

logger = logging.getLogger("ttp")


def _sanitize_alert_text(text: str) -> str:
    """Strip ANSI escape sequences and non-printable control characters."""
    # Strip ANSI escape sequences (e.g. \x1b[31m)
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)
    # Keep only printable characters or space
    return "".join(c for c in text if c.isprintable() or c == " ")


def trigger_emergency_killswitch(failed_component: str, err_msg: str) -> None:
    """Lock down network interfaces to prevent traffic leakage, then sound alert."""
    failed_component = _sanitize_alert_text(failed_component)
    err_msg = _sanitize_alert_text(err_msg)

    logger.critical(
        "EMERGENCY KILLSWITCH ACTIVATED! Reason: %s (%s)",
        failed_component,
        err_msg,
    )

    # 1. Apply emergency total drop ruleset
    try:
        firewall.apply_emergency_killswitch()
    except Exception as e:
        logger.critical("Failed to apply firewall emergency killswitch: %s", e)

    # 2. System broadcast
    alert_msg = (
        f"[TTP EMERGENCY] Tor session integrity failure detected on '{failed_component}' "
        f"({err_msg})! Network has been completely isolated to prevent cleartext leaks."
    )
    wall = resolve_optional("wall")
    if wall:
        subprocess.run([wall, alert_msg], check=False, timeout=10)

    # 3. Desktop Notification (if notify-send is present).
    # resolve_optional, not shutil.which: `which` consults $PATH, so on a host
    # without notify-send in a trusted directory it would report a caller-chosen
    # binary as present and we would then refuse to run it - or worse, run it.
    notify_send = resolve_optional("notify-send")
    if notify_send:
        subprocess.run(
            [
                notify_send,
                "TTP EMERGENCY",
                f"Failure detected on '{failed_component}'! Network isolated to prevent leaks.",
                "-u",
                "critical",
                "-i",
                "dialog-warning",
            ],
            check=False,
            timeout=10,
        )
