"""System diagnostics, OS detection, and information gathering.

This module is the "reporter" of TTP. It performs a comprehensive audit
of the system state, including OS details, firewall rulesets, DNS
configurations, and Tor daemon status.  It also provides **OS-level
inspection helpers** (SELinux mode, distro family, IPv6 support, firewalld)
that were formerly spread across ``tor_detect.py``.

KEY FEATURES:
- OS detection (/etc/os-release).
- Firewall inspection (nft list ruleset).
- DNS status (/etc/resolv.conf overlay).
- TTP internal state (lock file contents).
- SELinux / distro / network capability helpers.
- Decoupled from the UI (returns a data dictionary).
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
from pathlib import Path

from ttp import state, tor_control
from ttp.paths import resolve, resolve_optional

# ---------------------------------------------------------------------------
# OS-level inspection helpers (moved from tor_detect.py)
# ---------------------------------------------------------------------------


def is_selinux_enforcing() -> bool:
    """Return ``True`` if SELinux is in Enforcing mode."""
    # Resolved once and reused. Looking it up twice - optionally for the guard,
    # strictly for the argv - lets the two answers disagree on a host that does
    # not ship the binary, which is how these probes crashed on Ubuntu while
    # passing on Fedora.
    getenforce = resolve_optional("getenforce")
    if not getenforce:
        return False
    try:
        result = subprocess.run([getenforce], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() == "Enforcing"
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def is_fedora_family() -> bool:
    """Return ``True`` if the OS belongs to the Red Hat/Fedora family."""
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return Path("/etc/redhat-release").exists()

    try:
        content = os_release.read_text(encoding="utf-8").lower()
        return any(x in content for x in ["fedora", "rhel", "centos", "rocky", "almalinux"])
    except OSError:
        return False


def is_selinux_module_installed() -> bool:
    """Return ``True`` if the ``ttp_tor_policy`` module is already loaded."""
    semodule = resolve_optional("semodule")
    if not semodule:
        return False
    try:
        result = subprocess.run([semodule, "-l"], capture_output=True, text=True, timeout=10)
        return bool(re.search(r"ttp_tor_policy\s+1\.1\b", result.stdout))
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def is_firewalld_active() -> bool:
    """Return ``True`` if the ``firewalld`` service is active.

    Uses ``pgrep`` to be agnostic of the init system (systemd, OpenRC, etc.).
    """
    try:
        result = subprocess.run(
            [resolve("pgrep"), "-x", "firewalld"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def is_ipv6_supported() -> bool:
    """Return ``True`` if the system supports IPv6 loopback and socket operations."""
    import socket

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def collect_diagnostics() -> dict[str, str]:
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
    results: dict[str, str] = {}

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

    # 2. Tor Service (ttp-tor)
    try:
        svc_status = subprocess.run(
            [resolve("systemctl"), "status", "ttp-tor"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if not svc_status:
            svc_status = "(ttp-tor service not found)"
        results["tor_service"] = svc_status
    except Exception as e:
        results["tor_service"] = str(e)

    # 3. Tor Config (Volatile runtime config)
    try:
        torrc = subprocess.run(
            [resolve("grep"), "-v", r"^\s*#\|^\s*$", "/run/tor/ttp/torrc"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if not torrc:
            torrc = "(Empty or not readable)"
        results["torrc"] = torrc
    except Exception as e:
        results["torrc"] = str(e)

    # 4. nftables
    try:
        nft = subprocess.run(
            [resolve("nft"), "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if not nft:
            nft = "(Empty ruleset)"
        results["nftables"] = nft
    except Exception as e:
        results["nftables"] = str(e)

    # 5. DNS
    dns_info = "Status: "
    try:
        # Check if /etc/resolv.conf is a mount point (our overlay)
        mount_check = subprocess.run(
            [resolve("findmnt"), "-n", "/etc/resolv.conf"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()

        if mount_check:
            dns_info += f"ACTIVE OVERLAY\nMount details: {mount_check}\n\n"
        else:
            dns_info += "Standard (No overlay detected)\n\n"

        with open("/etc/resolv.conf") as f:
            dns_info += f"Current /etc/resolv.conf:\n---\n{f.read()}"
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
    from ttp.tor_detect import detect_tor  # local import to avoid circular dependency

    lock = state.read_lock()
    info = detect_tor()
    ttp_info = (
        f"Tor Installed: {info['is_installed']}\n"
        f"Tor Running: {info['is_running']}\n"
        f"Tor Configured: {info['is_configured']}\n"
        f"Tor User: {info.get('tor_user', 'unknown')}\n"
        f"OS Family: {'Fedora/RedHat' if info.get('is_fedora') else 'Debian/Other'}\n"
        f"SELinux Enforcing: {info.get('selinux', False)}\n"
        f"SELinux Module: {'INSTALLED' if info.get('selinux_module') else 'MISSING'}\n"
        f"Firewalld Active: {'YES' if info.get('firewalld') else 'NO'}\n\n"
        f"Lock File: {'EXISTS' if lock else 'NONE'}\n"
    )
    if lock:
        ttp_info += f"Lock contents:\n{json.dumps(lock, indent=2)}"
    results["ttp_state"] = ttp_info

    return results
