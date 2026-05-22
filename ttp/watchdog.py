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
    unit = f"""\
[Unit]
Description=TTP Session Watchdog & Killswitch
After=network.target ttp-tor.service
Requires=ttp-tor.service

[Service]
Type=simple
ExecStart={python_bin} -m ttp.cli watchdog run
Restart=no
LimitNOFILE=32768
"""
    WATCHDOG_SERVICE_PATH.parent.mkdir(parents=True, exist_ok=True)
    WATCHDOG_SERVICE_PATH.write_text(unit, encoding="utf-8")
    logger.debug("Wrote volatile watchdog service unit to %s", WATCHDOG_SERVICE_PATH)


def start_watchdog() -> None:
    """Start the volatile watchdog service daemon and track it in the state lock."""
    _write_watchdog_service_unit()
    try:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, check=True)
        subprocess.run(["systemctl", "start", WATCHDOG_SERVICE_NAME], capture_output=True, text=True, check=True)

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
    subprocess.run(["systemctl", "stop", WATCHDOG_SERVICE_NAME], capture_output=True, text=True, check=False)
    WATCHDOG_SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, check=False)

    try:
        state.update_lock_keys(watchdog_active=False, watchdog_pid=None)
    except Exception:
        # Lock might be already removed or corrupt; ignore.
        pass
    logger.info("TTP watchdog service stopped and cleaned up.")


def check_system_integrity() -> tuple[Optional[str], Optional[str]]:
    """Verify Tor connection, firewall rules and DNS overlay.

    Returns:
    --------
    tuple[Optional[str], Optional[str]]
        (failed_component, error_message)
        e.g., ("dns", "overlay unmounted") or (None, None) if all is healthy.
    """
    # 1. DNS Overlay mount check
    from ttp.dns import RESOLV_CONF, _is_mount_point
    target = RESOLV_CONF
    if os.path.islink(str(RESOLV_CONF)):
        target = Path(os.path.realpath(str(RESOLV_CONF)))
    if not _is_mount_point(str(target)):
        return "dns", "resolv.conf overlay mount has been unmounted"

    # 2. Firewall Ruleset check
    res = subprocess.run(["nft", "list", "table", "inet", "ttp"], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return "firewall", "nftables 'inet ttp' table is missing"
    if "chain filter_out" not in res.stdout:
        return "firewall", "nftables 'inet ttp' table is incomplete (missing filter_out)"

    # 3. Tor Connection check
    from ttp.tor_control import get_controller
    ctrl = get_controller()
    if ctrl is not None:
        try:
            ctrl.close()
        except Exception as e:
            return "tor", f"failed to close Tor controller socket: {e}"
    else:
        # Check systemd service status
        res_tor = subprocess.run(["systemctl", "is-active", "ttp-tor"], capture_output=True, text=True, check=False)
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

    logger.warning("Watchdog: Initiating auto-healing for failed component '%s'...", failed_component)
    try:
        if failed_component == "dns":
            interface = dns.detect_active_interface()
            dns.apply_dns(interface)
            logger.info("Watchdog: Auto-healed DNS overlay on interface '%s'.", interface)
            return True

        elif failed_component == "firewall":
            from ttp.tor_detect import detect_tor
            tor_info = detect_tor()
            tor_user = tor_info.get("tor_user", "debian-tor")

            firewall.apply_rules(
                tor_user=tor_user,
                transport_port=lock.get("transport_port", 9041),
                dns_port=lock.get("dns_port", 9054),
                allow_root=lock.get("allow_root", False),
                lan_bypass=lock.get("lan_bypass", True),
            )
            logger.info("Watchdog: Auto-healed firewall rules successfully.")
            return True

        elif failed_component == "tor":
            subprocess.run(["systemctl", "restart", "ttp-tor"], capture_output=True, text=True, check=True)
            logger.info("Watchdog: Auto-healed Tor service by restarting ttp-tor service.")
            return True

    except Exception as e:
        logger.error("Watchdog: Auto-healing failed for '%s': %s", failed_component, e)
        return False

    return False


def trigger_emergency_killswitch(failed_component: str, err_msg: str) -> None:
    """Lock down network interfaces to prevent traffic leakage, then sound alert."""
    logger.critical("EMERGENCY KILLSWITCH ACTIVATED! Reason: %s (%s)", failed_component, err_msg)

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
    logger.info("Watchdog: Monitoring loop started with interval of %d seconds.", interval_seconds)

    # Allow startup stabilization
    time.sleep(2)

    while True:
        # Check if the TTP session is still supposed to be active
        lock = state.read_lock()
        if lock is None:
            logger.info("Watchdog: No active TTP lock file found. Exiting gracefully.")
            break

        failed_comp, err_msg = check_system_integrity()
        if failed_comp is not None:
            logger.warning("Watchdog: Integrity check failed! Component: %s. Error: %s", failed_comp, err_msg)

            # First strike: attempt auto-healing
            attempt_auto_healing(failed_comp)

            # Brief stabilization delay after healing attempt
            time.sleep(3)

            # Re-check integrity
            re_failed, re_err = check_system_integrity()
            if re_failed is not None:
                # Second strike / healing failed: trigger immediate lockdown
                trigger_emergency_killswitch(re_failed, re_err)
                break
            else:
                logger.info("Watchdog: Auto-healing was successful. Session integrity restored.")

        time.sleep(interval_seconds)
