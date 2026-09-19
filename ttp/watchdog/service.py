# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Service management for the volatile TTP watchdog daemon."""

import logging
import subprocess
import sys
from pathlib import Path

from ttp import state
from ttp.exceptions import TorError
from ttp.paths import resolve

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
                # docs/security-assessment.md already describes the watchdog as
                # running with NoNewPrivileges=yes; it was never emitted.
                "NoNewPrivileges=yes",
                "CapabilityBoundingSet=CAP_NET_ADMIN",
                "AmbientCapabilities=CAP_NET_ADMIN",
                "StandardOutput=journal",
                "StandardError=journal",
            ]
        )

    # A watchdog that cannot start must end up visibly `failed`, not restart
    # every few seconds for the whole session. With RestartSec=3 the stock
    # 10s/5-start limiter is never reached, so the unit would loop silently.
    service_lines.extend(["StartLimitIntervalSec=60", "StartLimitBurst=5"])

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


def _unit_state() -> tuple[str, int | None]:
    """Return ``(ActiveState, MainPID)`` for the watchdog unit.

    ``("unknown", None)`` when the unit cannot be probed at all.
    """
    try:
        res = subprocess.run(
            [resolve("systemctl"), "show", WATCHDOG_SERVICE_NAME, "-p", "ActiveState", "-p", "MainPID"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except Exception:
        return "unknown", None
    fields = dict(line.split("=", 1) for line in res.stdout.strip().splitlines() if "=" in line)
    raw_pid = fields.get("MainPID", "0").strip()
    pid = int(raw_pid) if raw_pid.isdigit() and int(raw_pid) > 0 else None
    return fields.get("ActiveState", "unknown").strip(), pid


def watchdog_liveness() -> tuple[bool, int | None]:
    """Re-probe the unit and repair the lock, for every status reader.

    ``watchdog_active`` was written once at start and never corrected, so it
    kept reporting ACTIVE after the daemon exited -- including on the
    killswitch and heal-failure paths, where run_watchdog_loop returns 0 and
    Restart=on-failure does not restart it. The recorded PID went stale on
    every restart of a healthy daemon too.
    """
    active_state, pid = _unit_state()
    if active_state == "unknown":
        # Cannot probe: never upgrade a recorded value to "active".
        return False, None
    live = active_state in ("active", "activating") and pid is not None
    try:
        state.update_lock_keys(watchdog_active=live, watchdog_pid=pid if live else None)
    except Exception:
        pass
    return live, pid if live else None


def start_watchdog() -> None:
    """Start the volatile watchdog service daemon and track it in the state lock."""
    _write_watchdog_service_unit()
    try:
        subprocess.run(
            [resolve("systemctl"), "daemon-reload"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        subprocess.run(
            [resolve("systemctl"), "start", WATCHDOG_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        # Retrieve the PID of the watchdog process
        res = subprocess.run(
            [resolve("systemctl"), "show", WATCHDOG_SERVICE_NAME, "-p", "MainPID"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        parts = res.stdout.strip().split("=")
        watchdog_pid = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() and int(parts[1]) > 0 else None

        # `systemctl start` on a Type=simple unit returns as soon as the main
        # process is forked, so it proves nothing about the daemon staying up.
        # Confirm the unit is really active before recording it as such,
        # otherwise `ttp status` reports a watchdog that never ran.
        active_state, watchdog_pid = _unit_state()
        if active_state != "active" or watchdog_pid is None:
            state.update_lock_keys(watchdog_active=False, watchdog_pid=None)
            raise TorError(f"Watchdog service did not stay active (state: {active_state}, MainPID: {watchdog_pid}).")

        state.update_lock_keys(watchdog_active=True, watchdog_pid=watchdog_pid)
        logger.info("TTP watchdog service started (PID: %s).", watchdog_pid)
    except Exception as e:
        logger.error("Failed to start TTP watchdog service: %s", e)
        raise TorError(f"Failed to start watchdog service: {e}") from e


def stop_watchdog() -> None:
    """Stop the watchdog service and delete the volatile service unit."""
    subprocess.run(
        [resolve("systemctl"), "stop", WATCHDOG_SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    WATCHDOG_SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(
        [resolve("systemctl"), "daemon-reload"],
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
