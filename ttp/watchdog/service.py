# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Service management for the volatile TTP watchdog daemon."""

import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

from ttp import state
from ttp.evidence import Observation, boottime
from ttp.exceptions import TorError
from ttp.paths import resolve
from ttp.runtime_records import boot_id, session_store
from ttp.settings import Settings

logger = logging.getLogger("ttp")

WATCHDOG_SERVICE_NAME = "ttp-watchdog"
WATCHDOG_SERVICE_PATH = Path(f"/run/systemd/system/{WATCHDOG_SERVICE_NAME}.service")


def _write_watchdog_service_unit(settings: Settings | None = None, session_id: str | None = None) -> None:
    """Write the volatile systemd unit file for the TTP watchdog service."""
    python_bin = sys.executable
    import pwd

    has_watchdog_user = False
    try:
        pwd.getpwnam("ttp-watchdog")
        has_watchdog_user = True
    except KeyError:
        pass

    timing = (settings or Settings()).watchdog
    import uuid

    termination_args = f" --session {uuid.UUID(session_id)}" if session_id else ""
    service_lines = [
        "Type=notify",
        "NotifyAccess=main",
        f"TimeoutStartSec={timing.readiness_timeout:g}",
        f"WatchdogSec={timing.service_timeout:g}",
        "WatchdogSignal=SIGKILL",
        # Lost/corrupt intent uses the bounded 10s emergency fallback.
        f"TimeoutStopSec={max(4 * timing.check_timeout + 2, 42):g}",
        f"ExecStart={python_bin} -m ttp.cli watchdog run",
        f"ExecStopPost={python_bin} -m ttp.cli watchdog terminated{termination_args}",
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

    # The sandbox, from what the watchdog was measured to use: netlink (its
    # nftables subscription and nft itself) and UNIX sockets (systemctl, Tor's
    # control socket, the journal); reads of /run/ttp, /etc/resolv.conf and
    # /proc; writes only to its own directory. ProtectHome is read-only rather
    # than off-limits because a pipx install puts sys.executable under a home
    # directory. Desktop delivery is delegated to an unprivileged user agent.
    service_lines.extend(
        [
            "ProtectSystem=strict",
            # '-': the directory exists only when the ttp-watchdog account does
            # (state.ensure_runtime_dir). Without the prefix a pip install, where
            # the watchdog runs as root and has no such directory, failed with
            # 226/NAMESPACE and the watchdog never ran - which the chaos sweep
            # caught as a leak.
            "ReadWritePaths=-/run/ttp/watchdog",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
            "RestrictNamespaces=yes",
            "RestrictRealtime=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "SystemCallArchitectures=native",
        ]
    )

    service_str = "\n".join(service_lines)

    unit = f"""\
[Unit]
Description=TTP Session Watchdog & Killswitch
After=network.target ttp-tor.service
# Wants, not Requires: Requires propagates a stop, so `systemctl stop ttp-tor`
# stopped the watchdog too and Tor stayed dead with nothing left to heal it.
# `ttp stop` stops the watchdog itself, before Tor.
Wants=ttp-tor.service
# A watchdog that cannot start must end up visibly `failed`, not restart every
# few seconds for the whole session: with RestartSec=3 the stock 10s/5-start
# limiter is never reached. systemd reads these in [Unit] only - in [Service]
# they were logged as unknown keys and ignored.
StartLimitIntervalSec=60
StartLimitBurst=5

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


def watchdog_observation() -> dict[str, Any]:
    """Fresh useful progress from the current systemd invocation, or unknown.

    Status never rewrites root intent from a stale observation or infers useful
    supervision from a PID alone. An emergency-holding supervisor is operational
    but the session is not healthy.
    """
    unknown: dict[str, Any] = {"value": "unknown", "reason": "watchdog.observation_unavailable", "pid": None}
    try:
        lock = state.read_lock(strict=True)
        if not lock or not lock.get("watchdog_requested"):
            return {"value": "not_requested", "reason": "watchdog.not_requested", "pid": None}
        settings = Settings.from_snapshot(lock.get("settings"))
        response = subprocess.run(
            [
                resolve("systemctl"),
                "show",
                WATCHDOG_SERVICE_NAME,
                "-p",
                "ActiveState",
                "-p",
                "MainPID",
                "-p",
                "InvocationID",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=settings.watchdog.check_timeout,
        )
        fields = dict(line.split("=", 1) for line in response.stdout.splitlines() if "=" in line)
        if fields.get("ActiveState") != "active":
            return {**unknown, "value": "unavailable", "reason": "watchdog.unit_not_active"}
        pid = int(fields.get("MainPID", "0"))
        instance_id = fields.get("InvocationID", "")
        record = session_store().read("watchdog", lock["session_id"])
        if pid <= 0 or record is None:
            return unknown
        data = record["data"]
        progress = Observation(
            str(data.get("value", "unknown")),
            record["session_id"],
            record["boot_id"],
            str(data.get("instance_id", "")),
            record["written_at"],
        )
        identity = dict(
            session_id=lock["session_id"],
            boot_id=boot_id(),
            instance_id=instance_id,
            now=boottime(),
            max_age=settings.watchdog.observation_max_age,
        )
        if not progress.is_current(**identity):
            return {**unknown, "reason": "watchdog.progress_stale"}
        observed_at = data.get("observed_at")
        if not isinstance(observed_at, (int, float)) or isinstance(observed_at, bool):
            return {**unknown, "pid": pid, "reason": str(data.get("reason", "watchdog.evaluation_pending"))}
        observation = Observation(
            progress.value, progress.session_id, progress.boot_id, progress.instance_id, observed_at
        )
        if not observation.is_current(**identity):
            return {**unknown, "reason": "watchdog.integrity_stale", "pid": pid}
        return {**data, "pid": pid, "instance_id": instance_id, "progress_at": record["written_at"]}
    except Exception:
        return unknown


def watchdog_liveness() -> tuple[bool, int | None]:
    observation = watchdog_observation()
    live = observation["value"] in ("healthy", "emergency")
    return live, observation.get("pid") if live else None


def start_watchdog() -> None:
    """Require READY plus current progress, then inspect the latched outcome."""
    from ttp.session_safety import emergency_latched

    lock = state.read_lock(strict=True)
    if not lock:
        raise TorError("No session to supervise")
    settings = Settings.from_snapshot(lock.get("settings"))
    session_store().prepare()
    state.update_lock_keys(watchdog_requested=True)
    _write_watchdog_service_unit(settings, lock["session_id"])
    try:
        subprocess.run([resolve("systemctl"), "daemon-reload"], capture_output=True, text=True, check=True, timeout=10)
        subprocess.run(
            [resolve("systemctl"), "start", WATCHDOG_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=True,
            timeout=settings.watchdog.readiness_timeout,
        )
        observed = watchdog_observation()
        if observed["value"] != "healthy" or emergency_latched(lock):
            raise TorError(f"Required supervisor is not ready and healthy ({observed['reason']})")
        state.update_lock_keys(watchdog_active=True, watchdog_pid=observed["pid"])
        logger.info("TTP watchdog ready (PID: %s).", observed["pid"])
    except Exception as exc:
        logger.error("Required watchdog unavailable: %s", exc)
        raise TorError(f"Required watchdog unavailable: {exc}") from exc


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
