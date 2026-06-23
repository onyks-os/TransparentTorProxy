# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Watchdog & Killswitch Module - Proactive Session Integrity & Auto-Healing.

This module provides the core logic for the TTP background watchdog process,
which monitors system integrity (Tor socket, nftables table, and DNS overlay mount)
and performs automated recovery or raises the emergency killswitch if needed.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from ttp import dns, firewall, state
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
            ["systemctl", "daemon-reload"], capture_output=True, text=True, check=True
        )
        subprocess.run(
            ["systemctl", "start", WATCHDOG_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=True,
        )

        # Retrieve the PID of the watchdog process
        res = subprocess.run(
            ["systemctl", "show", WATCHDOG_SERVICE_NAME, "-p", "MainPID"],
            capture_output=True,
            text=True,
            check=True,
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
    )
    WATCHDOG_SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(
        ["systemctl", "daemon-reload"], capture_output=True, text=True, check=False
    )

    try:
        state.update_lock_keys(watchdog_active=False, watchdog_pid=None)
    except Exception:
        # Lock might be already removed or corrupt; ignore.
        pass
    logger.info("TTP watchdog service stopped and cleaned up.")


def is_interface_online(interface: str) -> bool:
    """Check if a network interface is physically online (has carrier and is up)."""
    sys_path = Path(f"/sys/class/net/{interface}")
    if not sys_path.exists():
        return False
    try:
        # Check operstate
        operstate_file = sys_path / "operstate"
        if operstate_file.exists():
            operstate = operstate_file.read_text().strip().lower()
            # If state is explicitly down, it is offline
            if operstate == "down":
                return False

        # Check carrier
        carrier_file = sys_path / "carrier"
        if carrier_file.exists():
            carrier = carrier_file.read_text().strip()
            if carrier == "0":
                return False
        return True
    except OSError:
        return False


def has_default_route() -> bool:
    """Return True if a default gateway route exists in the system."""
    try:
        route_path = Path("/proc/net/route")
        if not route_path.exists():
            return False
        with open(route_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 8:
                    # Destination is 2nd column, Mask is 8th column
                    dest = parts[1]
                    mask = parts[7]
                    if dest == "00000000" and mask == "00000000":
                        return True
    except OSError:
        pass
    return False


def check_system_integrity() -> tuple[Optional[str], Optional[str]]:
    """Verify Tor connection, firewall rules and DNS overlay.

    Returns:
    --------
    tuple[Optional[str], Optional[str]]
        (failed_component, error_message)
        e.g., ("dns", "overlay unmounted") or (None, None) if all is healthy.
    """
    lock = state.read_lock()

    # 1. DNS Overlay mount check
    from ttp.dns import RESOLV_CONF, _is_mount_point

    target = RESOLV_CONF
    if os.path.islink(str(RESOLV_CONF)):
        target = Path(os.path.realpath(str(RESOLV_CONF)))
    if not _is_mount_point(str(target)):
        return "dns", "resolv.conf overlay mount has been unmounted"

    # 1b. Check systemd-resolved if it was active on startup
    if lock:
        dns_backup = lock.get("dns_backup")
        if dns_backup and dns_backup.get("systemd_resolved"):
            resolved_config = Path("/run/systemd/resolved.conf.d/ttp.conf")
            if not resolved_config.exists():
                return (
                    "dns",
                    "systemd-resolved drop-in configuration file has been deleted",
                )
            res_resolved = subprocess.run(
                ["systemctl", "is-active", "systemd-resolved"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res_resolved.stdout.strip() != "active":
                return "dns", "systemd-resolved systemd service is inactive/stopped"

    # 2. Firewall Ruleset check
    res = subprocess.run(
        ["nft", "list", "table", "inet", "ttp"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return "firewall", "nftables 'inet ttp' table is missing"
    if "chain filter_out" not in res.stdout:
        return (
            "firewall",
            "nftables 'inet ttp' table is incomplete (missing filter_out)",
        )

    # Verify bypass rules if configured in state lock
    if lock:
        import pwd
        import grp

        for u in lock.get("bypass_users", []):
            try:
                uid = int(u) if u.isdigit() else pwd.getpwnam(u).pw_uid
                if f"meta skuid {uid} accept" not in res.stdout:
                    return (
                        "firewall",
                        f"bypass rule for user '{u}' (UID {uid}) is missing",
                    )
            except KeyError:
                return "firewall", f"bypass user '{u}' cannot be resolved on system"

        for g in lock.get("bypass_groups", []):
            try:
                gid = int(g) if g.isdigit() else grp.getgrnam(g).gr_gid
                if f"meta skgid {gid} accept" not in res.stdout:
                    return (
                        "firewall",
                        f"bypass rule for group '{g}' (GID {gid}) is missing",
                    )
            except KeyError:
                return "firewall", f"bypass group '{g}' cannot be resolved on system"

    # 3. Tor Connection check: perform an *active* query to the control socket
    #    to verify that the Tor daemon is actually responsive, not just that
    #    the socket file exists (a stale socket would pass a mere close() check).
    from ttp.tor_control import get_controller

    ctrl = get_controller()
    if ctrl is not None:
        try:
            with ctrl:
                ctrl.get_info("status/bootstrap-phase")
        except Exception as e:
            return "tor", f"Tor control interface unresponsive: {e}"
    else:
        # Control socket unavailable - fall back to systemd service status
        res_tor = subprocess.run(
            ["systemctl", "is-active", "ttp-tor"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res_tor.stdout.strip() != "active":
            return "tor", "Tor systemd service is inactive/stopped"

    return None, None


def attempt_auto_healing(failed_component: str) -> bool:
    """Attempt to dynamically repair a failed session component.

    Returns:
    --------
    bool
        True if the healing commands succeeded, False otherwise.
    """
    lock = state.read_lock()
    if not lock:
        return False

    logger.warning(
        "Watchdog: Initiating auto-healing for failed component '%s'...",
        failed_component,
    )
    try:
        if failed_component == "tor":
            logger.info("Watchdog: Restarting Tor service via systemctl...")
            res = subprocess.run(
                ["systemctl", "restart", "ttp-tor.service"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                logger.info("Watchdog: Restarted Tor service successfully.")
                return True
            else:
                logger.error(
                    "Watchdog: Failed to restart Tor service: %s",
                    res.stderr.strip() if res.stderr else f"Exit code {res.returncode}",
                )
                return False
        else:
            # dns and firewall tampering: fail closed immediately.
            logger.error(
                "Watchdog: Tampering or failure detected on critical component '%s'. "
                "Fail-closed policy active: auto-healing skipped.",
                failed_component,
            )
            return False
    except Exception as e:
        logger.error("Watchdog: Auto-healing failed for '%s': %s", failed_component, e)
        return False


def trigger_emergency_killswitch(failed_component: str, err_msg: str) -> None:
    """Lock down network interfaces to prevent traffic leakage, then sound alert."""
    logger.critical(
        "EMERGENCY KILLSWITCH ACTIVATED! Reason: %s (%s)", failed_component, err_msg
    )

    # 1. Apply emergency total drop ruleset
    try:
        firewall.apply_emergency_killswitch()
    except Exception as e:
        logger.critical("Failed to apply firewall emergency killswitch: %s", e)

    # 2. System broadcast
    alert_msg = (
        f"⚠️  [TTP EMERGENCY] Tor session integrity failure detected on '{failed_component}' "
        f"({err_msg})! Network has been completely isolated to prevent cleartext leaks."
    )
    subprocess.run(["wall", alert_msg], check=False)

    # 3. Desktop Notification (if notify-send is present)
    if shutil.which("notify-send"):
        subprocess.run(
            [
                "notify-send",
                "TTP EMERGENCY",
                f"Failure detected on '{failed_component}'! Network isolated to prevent leaks.",
                "-u",
                "critical",
                "-i",
                "dialog-warning",
            ],
            check=False,
        )


def run_watchdog_loop(interval_seconds: int = 15) -> None:
    """Run the continuous monitoring loop, reacting to failures in real-time."""
    logger.info(
        "Watchdog: Monitoring loop started with interval of %d seconds.",
        interval_seconds,
    )

    # Allow startup stabilization
    time.sleep(2)

    while True:
        try:
            # Check if the TTP session is still supposed to be active
            lock = state.read_lock()
            if lock is None:
                logger.info(
                    "Watchdog: No active TTP lock file found. Exiting gracefully."
                )
                break

            # Extract active interface from lock
            interface = lock.get("interface")
            if not interface:
                interface = dns.detect_active_interface()

            # Check if network link is online and gateway is present
            online = is_interface_online(interface)
            has_route = has_default_route()

            if not online or not has_route:
                logger.warning(
                    "Watchdog: Network link is offline (Interface '%s' online=%s, DefaultRoute=%s). "
                    "Suspending integrity monitoring to prevent false positives.",
                    interface,
                    online,
                    has_route,
                )
                # Loop here until network link comes back
                while True:
                    time.sleep(5)
                    # Check if lock still exists (e.g. ttp stop was run)
                    lock = state.read_lock()
                    if lock is None:
                        break

                    interface = lock.get("interface") or dns.detect_active_interface()
                    if is_interface_online(interface) and has_default_route():
                        logger.info(
                            "Watchdog: Network link restored on '%s'. "
                            "Waiting 10 seconds for Tor circuit stabilization...",
                            interface,
                        )
                        time.sleep(10)
                        break

                # Re-read lock after exiting the offline loop
                lock = state.read_lock()
                if lock is None:
                    logger.info(
                        "Watchdog: No active TTP lock file found after recovery. Exiting gracefully."
                    )
                    break

            failed_comp, err_msg = check_system_integrity()
            if failed_comp is not None:
                logger.warning(
                    "Watchdog: Integrity check failed! Component: %s. Error: %s",
                    failed_comp,
                    err_msg,
                )

                # First strike: attempt auto-healing
                healed = attempt_auto_healing(failed_comp)

                if not healed:
                    # Healing itself failed (e.g. can't reapply firewall rules) -
                    # skip the re-check and trigger the killswitch immediately.
                    logger.error(
                        "Watchdog: Auto-healing command failed for '%s'. "
                        "Triggering emergency killswitch immediately.",
                        failed_comp,
                    )
                    trigger_emergency_killswitch(failed_comp, err_msg)
                    break

                # Brief stabilization delay after healing attempt
                time.sleep(3)

                # Re-check integrity after successful healing
                re_failed, re_err = check_system_integrity()
                if re_failed is not None:
                    # Healing command ran but system is still broken: trigger lockdown
                    trigger_emergency_killswitch(re_failed, re_err)
                    break
                else:
                    logger.info(
                        "Watchdog: Auto-healing was successful. Session integrity restored."
                    )

            time.sleep(interval_seconds)
        except Exception as e:
            logger.error(
                "Watchdog loop encountered an unexpected error: %s", e, exc_info=True
            )
            time.sleep(5)
