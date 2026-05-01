"""Tor installation and system-wide optimization logic.

This module is the "hands" of TTP. It intervenes when system state
needs modification to support Tor. It handles package installation,
config file sanitization, and OS-specific optimizations like SELinux
policy management.
"""

from __future__ import annotations

import importlib.resources
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from ttp.exceptions import TorError
from ttp.tor_detect import detect_tor

# Default paths
TORRC_PATH = Path("/etc/tor/torrc")
_PKG_COMMANDS = ["apt-get", "dnf", "pacman", "zypper"]

logger = logging.getLogger("ttp")


def _restart_tor(service: str = "tor") -> None:
    """Restart the Tor service using systemd."""
    logger.info(f"Restarting Tor service: {service}...")
    result = subprocess.run(
        ["systemctl", "restart", service], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        # Collect journal output
        journal = ""
        try:
            j = subprocess.run(
                ["journalctl", "-u", service, "-n", "20", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            journal = j.stdout.strip()
        except Exception:
            pass

        raise RuntimeError(
            f"Failed to restart Tor service '{service}'.\n"
            f"systemctl stderr: {result.stderr.strip()}\n"
            f"Journal ({service}):\n{journal}"
        )


def configure_torrc(tor_user: str, torrc_path: Path = TORRC_PATH) -> bool:
    """Write or update TTP settings in torrc, avoiding duplicates.

    Returns:
        True if the file was modified, False otherwise.
    """
    if torrc_path.exists():
        backup = torrc_path.with_suffix(".bak")
        shutil.copy2(torrc_path, backup)
        content = torrc_path.read_text(encoding="utf-8")
    else:
        content = ""

    options = {
        "VirtualAddrNetworkIPv4": "10.192.0.0/10",
        "AutomapHostsOnResolve": "1",
        "TransPort": "9040",
        "DNSPort": "9053",
        "ControlPort": "9051",
        "CookieAuthentication": "1",
        "ClientUseIPv4": "1",
        "ClientUseIPv6": "0",
    }
    if tor_user != "root":
        options["User"] = tor_user

    # Remove HashedControlPassword if present (conflicts with CookieAuthentication)
    new_content = re.sub(
        r"^\s*HashedControlPassword\s+.*$\n?", "", content, flags=re.MULTILINE
    )

    modified = new_content != content
    content = new_content

    for opt, val in options.items():
        # Regex to find the option (active or commented)
        # ^\s*#?\s*Option\s+.*$
        pattern = rf"^\s*#?\s*{opt}\s+.*$"
        new_line = f"{opt} {val}"

        if re.search(pattern, content, re.MULTILINE):
            # Check if it already has the correct value and is active
            correct_pattern = rf"^\s*{opt}\s+{re.escape(val)}\b"
            if not re.search(correct_pattern, content, re.MULTILINE):
                # Update/Uncomment existing entry
                content = re.sub(pattern, new_line, content, flags=re.MULTILINE)
                modified = True
        else:
            # Add missing entry
            if content and not content.endswith("\n"):
                content += "\n"
            content += f"{new_line}\n"
            modified = True

    if modified or not torrc_path.exists():
        torrc_path.write_text(content, encoding="utf-8")
        logger.info(f"Updated {torrc_path} with TTP configuration.")
        return True

    return False


def _install_selinux_tools() -> None:
    """Install policycoreutils and checkpolicy if missing."""
    if shutil.which("checkmodule") and shutil.which("semodule_package"):
        return

    logger.info("SELinux compilation tools missing. Attempting to install...")
    pm = detect_package_manager()
    if pm != "dnf":
        logger.warning(
            "Auto-install of checkpolicy is only supported on dnf (Fedora/RHEL)."
        )
        return

    try:
        subprocess.run(
            ["dnf", "install", "-y", "checkpolicy", "policycoreutils"], check=True
        )
        logger.info("SELinux compilation tools installed successfully.")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to install SELinux tools: {e}")


def setup_selinux_if_needed() -> None:
    """Compile and install the custom SELinux policy for Tor on Fedora/RHEL if needed."""
    from ttp.tor_detect import (
        is_fedora_family,
        is_selinux_enforcing,
        is_selinux_module_installed,
    )

    if not is_fedora_family() or not is_selinux_enforcing():
        return

    if is_selinux_module_installed():
        return

    logger.info("SELinux detected. Compiling and installing TTP Tor policy module...")

    # Use importlib.resources to access the policy file inside the package
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath(
        "ttp_tor_policy.te"
    )

    with importlib.resources.as_file(traversable) as te_path:
        if not te_path.exists():
            logger.warning(f"SELinux policy source missing at {te_path}. Skipping.")
            return

        _install_selinux_tools()

        if not shutil.which("checkmodule") or not shutil.which("semodule_package"):
            logger.warning(
                "checkmodule or semodule_package not found. Cannot compile SELinux policy."
            )
            return

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                mod_path = tmp / "ttp_tor_policy.mod"
                pp_path = tmp / "ttp_tor_policy.pp"

                logger.debug(f"Compiling {te_path.name}...")
                subprocess.run(
                    ["checkmodule", "-M", "-m", "-o", str(mod_path), str(te_path)],
                    check=True,
                )
                subprocess.run(
                    ["semodule_package", "-o", str(pp_path), "-m", str(mod_path)],
                    check=True,
                )

                logger.debug(f"Installing {pp_path.name}...")
                subprocess.run(["semodule", "-i", str(pp_path)], check=True)

            logger.info("SELinux policy module installed successfully.")
        except (subprocess.CalledProcessError, OSError) as e:
            logger.warning(
                f"SELinux policy installation failed: {e}. Tor might have permission issues."
            )


def remove_selinux_module() -> None:
    """Remove the custom TTP SELinux policy module."""
    if not Path("/usr/sbin/semodule").exists():
        return

    from ttp.tor_detect import is_selinux_module_installed

    if not is_selinux_module_installed():
        return

    logger.info("Removing TTP Tor policy module...")
    try:
        subprocess.run(["semodule", "-r", "ttp_tor_policy"], check=True)
        logger.info("SELinux policy module removed.")
    except (subprocess.CalledProcessError, OSError) as e:
        logger.warning(f"Failed to remove SELinux policy module: {e}")


def detect_package_manager() -> Optional[str]:
    """Detect available package manager."""
    for pm in _PKG_COMMANDS:
        if shutil.which(pm):
            return pm
    return None


def install_tor(pm: str) -> None:
    """Install Tor using the detected package manager."""
    logger.info(f"Installing Tor via {pm}...")
    cmd = []
    if pm == "apt-get":
        subprocess.run(["apt-get", "update"], check=True)
        cmd = ["apt-get", "install", "-y", "tor"]
    elif pm == "dnf":
        cmd = ["dnf", "install", "-y", "tor"]
    elif pm == "pacman":
        cmd = ["pacman", "-Sy", "--noconfirm", "tor"]
    elif pm == "zypper":
        cmd = ["zypper", "install", "-y", "tor"]

    if not cmd:
        raise TorError(f"Unsupported package manager: {pm}")

    subprocess.run(cmd, check=True)


def ensure_tor_ready() -> dict[str, Any]:
    """Main entry point to ensure Tor is installed, configured, and running."""
    info = detect_tor()

    if not info["is_installed"]:
        pm = detect_package_manager()
        if pm is None:
            raise TorError("No supported package manager found.")
        install_tor(pm)
        info = detect_tor()

    # Configure torrc (idempotent update)
    tor_user = info.get("tor_user", "debian-tor")
    modified = configure_torrc(tor_user)

    # Restart only if needed: modified config OR service not running
    if modified or not info["is_running"]:
        service = info.get("service_name", "tor")
        _restart_tor(service)
        # Give the daemon a moment to open its ports.
        time.sleep(2)
        info = detect_tor()
    else:
        logger.info("Tor is already configured and running. Skipping restart.")

    if not info["is_running"]:
        service = info.get("service_name", "tor")
        raise RuntimeError(f"Tor service '{service}' failed to start.")

    return info
