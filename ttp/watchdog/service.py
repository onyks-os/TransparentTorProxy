# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Service management for the volatile TTP watchdog daemon."""

import logging
import sys
import subprocess
from pathlib import Path
from ttp import state
from ttp.exceptions import TorError

logger = logging.getLogger("ttp")

WATCHDOG_SERVICE_NAME = "ttp-watchdog"
WATCHDOG_SERVICE_PATH = Path(f"/run/systemd/system/{WATCHDOG_SERVICE_NAME}.service")


def _write_watchdog_service_unit() -> None:
    """Write the volatile systemd unit file for the TTP watchdog service."""
    python_bin = sys.executable
    import pwd

    has_watchdog_user = False
    try:
        pwd.getpwnam("ttp-watchdog")
        has_watchdog_user = True
    except KeyError:
        pass

    service_lines = [
        "Type=simple",
        f"ExecStart={python_bin} -m ttp.cli watchdog run",
        "Restart=on-failure",
        "RestartSec=3",
        "LimitNOFILE=32768",
    ]

    if has_watchdog_user:
        service_lines.extend(
            [
                "User=ttp-watchdog",
                "Group=ttp-watchdog",
                "CapabilityBoundingSet=CAP_NET_ADMIN",
                "AmbientCapabilities=CAP_NET_ADMIN",
                "StandardOutput=journal",
                "StandardError=journal",
            ]
        )

    service_str = "\n".join(service_lines)

    unit = f"""\
[Unit]
Description=TTP Session Watchdog & Killswitch
After=network.target ttp-tor.service
Requires=ttp-tor.service

[Service]
{service_str}
"""
    WATCHDOG_SERVICE_PATH.parent.mkdir(parents=True, exist_ok=True)
    WATCHDOG_SERVICE_PATH.write_text(unit, encoding="utf-8")
    logger.debug("Wrote volatile watchdog service unit to %s", WATCHDOG_SERVICE_PATH)


def start_watchdog() -> None:
    """Start the volatile watchdog service daemon and track it in the state lock."""
    _write_watchdog_service_unit()
    try:
        subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        subprocess.run(
            ["systemctl", "start", WATCHDOG_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        # Retrieve the PID of the watchdog process
        res = subprocess.run(
            ["systemctl", "show", WATCHDOG_SERVICE_NAME, "-p", "MainPID"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        parts = res.stdout.strip().split("=")
        watchdog_pid = (
            int(parts[1])
            if len(parts) > 1 and parts[1].isdigit() and int(parts[1]) > 0
            else None
        )

        state.update_lock_keys(watchdog_active=True, watchdog_pid=watchdog_pid)
        logger.info("TTP watchdog service started (PID: %s).", watchdog_pid)
    except Exception as e:
        logger.error("Failed to start TTP watchdog service: %s", e)
        raise TorError(f"Failed to start watchdog service: {e}") from e


def stop_watchdog() -> None:
    """Stop the watchdog service and delete the volatile service unit."""
    subprocess.run(
        ["systemctl", "stop", WATCHDOG_SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    WATCHDOG_SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(
        ["systemctl", "daemon-reload"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    try:
        state.update_lock_keys(watchdog_active=False, watchdog_pid=None)
    except Exception:
        # Lock might be already removed or corrupt; ignore.
        pass
    logger.info("TTP watchdog service stopped and cleaned up.")
