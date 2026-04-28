"""System diagnostics and information gathering.

This module is the "reporter" of TTP. It performs a comprehensive
audit of the system state, including OS details, firewall rulesets,
DNS configurations, and Tor daemon status. It is designed to be
purely informational and is used by the `diagnose` command.

KEY FEATURES:
- OS detection (/etc/os-release).
- Firewall inspection (nft list ruleset).
- DNS status (resolvectl or /etc/resolv.conf).
- TTP internal state (lock file contents).
- Decoupled from the UI (returns a data dictionary).
"""

from __future__ import annotations

import json
import platform
import subprocess
from typing import Dict

from ttp import dns, state, tor_control
from ttp.tor_detect import _get_service_name, detect_tor


def collect_diagnostics() -> Dict[str, str]:
    """Gather diagnostic information about the system and Tor.

    Does not raise exceptions if system commands fail. Instead, it embeds
    the error message as the string value for that specific key.

    Returns
    -------
    Dict[str, str]
        A dictionary with the following keys:
        - "os"
        - "tor_service"
        - "torrc"
        - "nftables"
        - "dns"
        - "control_interface"
        - "ttp_state"
    """
    results: Dict[str, str] = {}

    # 1. System
    os_name = "Unknown"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.strip().split("=")[1].strip('"')
    except Exception:
        pass
    results["os"] = f"Hostname: {platform.node()}\nOS: {os_name}"

    # 2. Tor Service
    service = _get_service_name()
    try:
        svc_status = subprocess.run(
            ["systemctl", "status", service, "--no-pager"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not svc_status:
            svc_status = "(Service not found or inactive)"
        results["tor_service"] = svc_status
    except Exception as e:
        results["tor_service"] = str(e)

    # 3. Tor Config
    try:
        torrc = subprocess.run(
            ["grep", "-v", r"^\s*#\|^\s*$", "/etc/tor/torrc"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not torrc:
            torrc = "(Empty or not readable)"
        results["torrc"] = torrc
    except Exception as e:
        results["torrc"] = str(e)

    # 4. nftables
    try:
        nft = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not nft:
            nft = "(Empty ruleset)"
        results["nftables"] = nft
    except Exception as e:
        results["nftables"] = str(e)

    # 5. DNS
    dns_mode = dns.detect_dns_mode()
    dns_info = f"Detected Mode: {dns_mode}\n\n"
    try:
        if dns_mode == "resolvectl":
            dns_info += subprocess.run(
                ["resolvectl", "status"],
                capture_output=True,
                text=True,
            ).stdout.strip()
        else:
            with open("/etc/resolv.conf") as f:
                dns_info += f.read()
        results["dns"] = dns_info
    except Exception as e:
        results["dns"] = dns_info + str(e)

    # 6. Control Interface
    ctrl = tor_control.get_controller()
    if ctrl:
        try:
            with ctrl:
                boot = ctrl.get_info("status/bootstrap-phase")
                ctrl_info = f"Connected successfully!\nBootstrap phase: {boot}"
        except Exception as e:
            ctrl_info = f"Connected but error getting info: {e}"
    else:
        ctrl_info = "Could not connect to Tor ControlSocket or ControlPort."
    results["control_interface"] = ctrl_info

    # 7. TTP Internal
    lock = state.read_lock()
    info = detect_tor()
    ttp_info = (
        f"Tor Installed: {info['is_installed']}\n"
        f"Tor Running: {info['is_running']}\n"
        f"Tor Configured: {info['is_configured']}\n"
        f"Tor User: {info.get('tor_user', 'unknown')}\n"
        f"OS Family: {'Fedora/RedHat' if info.get('is_fedora') else 'Debian/Other'}\n"
        f"SELinux Enforcing: {info.get('selinux', False)}\n\n"
        f"Lock File: {'EXISTS' if lock else 'NONE'}\n"
    )
    if lock:
        ttp_info += f"Lock contents:\n{json.dumps(lock, indent=2)}"
    results["ttp_state"] = ttp_info

    return results
