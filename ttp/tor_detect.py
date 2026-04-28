"""System inspection — Read-only detection of Tor and OS state.

This module is the "eyes" of TTP. It performs non-destructive checks
to determine if Tor is installed, configured, and running. It also
identifies distribution-specific details like the Tor user and
SELinux status.

DESIGN PRINCIPLE:
- This module must be READ-ONLY.
- It should never modify the system state (use tor_install.py for that).
- It returns descriptive dictionaries used by other modules to make decisions.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

TORRC_PATH = Path("/etc/tor/torrc")


def _get_service_name() -> str:
    """Return the systemd service unit that runs the Tor daemon.

    On Debian, the daemon lives in ``tor@default.service``.
    ``tor.service`` is a multi-instance master that exits immediately
    and always reports *active (exited)*.
    """
    import os

    if os.path.exists("/etc/debian_version"):
        return "tor@default"
    return "tor"


def _check_installed() -> bool:
    """Return ``True`` if the ``tor`` binary is found in ``$PATH``."""
    return shutil.which("tor") is not None


def _get_version() -> str:
    """Return the Tor version string, or ``""`` if unavailable."""
    try:
        result = subprocess.run(
            ["tor", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Output looks like: "Tor version 0.4.8.10."
        match = re.search(r"Tor version ([\d]+(?:\.[\d]+)*)", result.stdout)
        return match.group(1) if match else ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _check_running() -> bool:
    """Return ``True`` if the Tor daemon is actually running.

    Uses a two-step check:

    1. ``systemctl is-active`` on the correct service unit
       (``tor@default`` first, then ``tor``).
    2. Verify that a ``tor`` process actually exists — guards against
       the Debian multi-instance master which reports *active (exited)*
       even though no daemon is running.
    """
    service = _get_service_name()
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=10,
        )
        systemd_active = result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        systemd_active = False

    if not systemd_active:
        return False

    # Double-check: is there an actual tor process?
    try:
        result = subprocess.run(
            ["pgrep", "-x", "tor"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # pgrep not available — trust systemd.
        return systemd_active


def _check_config(torrc_path: Path | None = None) -> bool:
    """Return ``True`` if *torrc* contains ``TransPort 9040``, ``DNSPort 9053``, and ``ControlPort 9051``."""
    if torrc_path is None:
        torrc_path = TORRC_PATH
    try:
        content = torrc_path.read_text(encoding="utf-8")
    except OSError:
        return False

    has_transport = bool(re.search(r"^\s*TransPort\s+9040\b", content, re.MULTILINE))
    has_dnsport = bool(re.search(r"^\s*DNSPort\s+9053\b", content, re.MULTILINE))
    has_controlport = bool(
        re.search(r"^\s*ControlPort\s+9051\b", content, re.MULTILINE)
    )
    return has_transport and has_dnsport and has_controlport


def _detect_tor_user() -> str:
    """Return the system user that Tor runs as.

    Detection order:

    1. **Live process** — ``ps`` the running ``tor`` process and read
       its owner.  This is the only fully reliable method and handles
       every distro (``debian-tor``, ``toranon``, ``tor``, …).
    2. **``/etc/passwd``** — scan for well-known names as a static
       fallback when Tor is not running yet.
    3. Hard fallback to ``"tor"``.
    """
    # 1. Check the running process — most reliable.
    #    Use ``user:32`` to avoid ps truncating long names like
    #    ``debian-tor`` (10 chars) to ``debian-+`` (8 chars).
    try:
        result = subprocess.run(
            ["ps", "-eo", "user:32,comm"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[1].strip() == "tor":
                user = parts[0].strip()
                # Sanity: reject truncated names (contain ``+``).
                if "+" not in user:
                    return user
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 2. Static fallback — known distro usernames.
    _KNOWN_USERS = ("debian-tor", "toranon", "tor", "_tor")
    try:
        passwd = Path("/etc/passwd").read_text(encoding="utf-8")
        for user in _KNOWN_USERS:
            if re.search(rf"^{user}:", passwd, re.MULTILINE):
                return user
    except OSError:
        pass

    return "tor"


def is_selinux_enforcing() -> bool:
    """Return ``True`` if SELinux is in Enforcing mode."""
    if not shutil.which("getenforce"):
        return False
    try:
        result = subprocess.run(
            ["getenforce"], capture_output=True, text=True, timeout=5
        )
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
        # Look for typical Fedora family identifiers
        return any(
            x in content for x in ["fedora", "rhel", "centos", "rocky", "almalinux"]
        )
    except OSError:
        return False


def detect_tor() -> dict:
    """Run all detection checks and return a summary dictionary.

    Returns
    -------
    dict with keys:
        ``is_installed``  – bool
        ``is_running``    – bool
        ``is_configured`` – bool
        ``tor_user``      – str  (``"debian-tor"`` or ``"tor"``)
        ``version``       – str  (e.g. ``"0.4.8.10"``, or ``""``)
        ``service_name``  – str  (e.g. ``"tor@default"`` or ``"tor"``)
        ``is_fedora``     – bool
        ``selinux``       – bool (True if Enforcing)
    """
    installed = _check_installed()
    return {
        "is_installed": installed,
        "is_running": _check_running() if installed else False,
        "is_configured": _check_config() if installed else False,
        "tor_user": _detect_tor_user(),
        "version": _get_version() if installed else "",
        "service_name": _get_service_name() if installed else "tor",
        "is_fedora": is_fedora_family(),
        "selinux": is_selinux_enforcing(),
    }
