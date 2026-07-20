# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Session integrity checks and auto-healing logic."""

import logging
import os
import subprocess
from pathlib import Path
from typing import Optional
from ttp import dns, state, tor_control

logger = logging.getLogger("ttp")


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
    target = dns.RESOLV_CONF
    if os.path.islink(str(dns.RESOLV_CONF)):
        target = Path(os.path.realpath(str(dns.RESOLV_CONF)))
    if not dns._is_mount_point(str(target)):
        return "dns", "resolv.conf overlay mount has been unmounted"

    # Verify content points to localhost nameservers only
    try:
        content = Path("/etc/resolv.conf").read_text(encoding="utf-8")
        nameservers = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    nameservers.append(parts[1])
        if not nameservers:
            return "dns", "resolv.conf has no nameservers configured"
        for ns in nameservers:
            if ns not in ("127.0.0.1", "::1"):
                return (
                    "dns",
                    f"resolv.conf nameserver points to non-local resolver: {ns}",
                )
    except Exception as e:
        return "dns", f"Failed to read/verify resolv.conf: {e}"

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
                timeout=10,
            )
            if res_resolved.stdout.strip() != "active":
                return "dns", "systemd-resolved systemd service is inactive/stopped"

    # 2. Firewall Ruleset check
    res = subprocess.run(
        ["nft", "list", "table", "inet", "ttp"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
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
    ctrl = tor_control.get_controller()
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
            timeout=10,
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
                timeout=10,
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
