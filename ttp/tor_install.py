"""Tor installation and native service management.

This module handles Tor binary detection, package installation,
runtime torrc generation, and service lifecycle management.
Tor is managed via the OS native service manager (systemctl),
not as a direct subprocess.

OS-specific optimizations such as SELinux policy management are also
handled here.
"""

from __future__ import annotations

import importlib.resources
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from ttp.exceptions import TorError
from ttp.tor_detect import detect_tor

# Runtime paths (volatile, stored on tmpfs)
TOR_RUNTIME_DIR = Path("/run/tor/ttp")

# Persistent cache for Tor Entry Guards. This is the only path
# that survives reboots, reducing bootstrap from ~30s to ~3s.
TOR_CACHE_DIR = Path("/var/lib/tor/ttp")

# Volatile systemd unit for TTP's dedicated Tor instance.
# Lives in /run/ so it disappears on reboot.
TTP_SERVICE_NAME = "ttp-tor"
TTP_SERVICE_PATH = Path(f"/run/systemd/system/{TTP_SERVICE_NAME}.service")

_PKG_COMMANDS = ["apt-get", "dnf", "pacman", "zypper"]

logger = logging.getLogger("ttp")

PT_MAP = {
    "obfs4": {
        "binary": "obfs4proxy",
        "apt-get": "obfs4proxy",
        "dnf": "obfs4",
        "pacman": "obfs4proxy",
        "zypper": "obfs4proxy",
    },
    "meek_lite": {
        "binary": "obfs4proxy",
        "apt-get": "obfs4proxy",
        "dnf": "obfs4",
        "pacman": "obfs4proxy",
        "zypper": "obfs4proxy",
    },
    "snowflake": {
        "binary": "snowflake-client",
        "apt-get": "snowflake-client",
        "dnf": "snowflake-client",
        "pacman": "snowflake-client",
        "zypper": "snowflake-client",
    },
}


def ensure_pluggable_transports(required_transports: list[str]) -> None:
    """Verify that required pluggable transport helper binaries are installed.

    If a binary is missing, attempt to automatically install it via the local
    package manager.
    """
    for pt in required_transports:
        pt = pt.lower()
        if pt not in PT_MAP:
            raise TorError(f"Unsupported pluggable transport: '{pt}'")

        pt_info = PT_MAP[pt]
        binary = pt_info["binary"]

        # Check if binary is in PATH
        if shutil.which(binary):
            continue

        # Try to install
        pm = detect_package_manager()
        if pm is None:
            raise TorError(
                f"Pluggable transport helper '{binary}' for '{pt}' is missing, "
                "and no supported package manager was found to install it."
            )

        pkg = pt_info.get(pm)
        if not pkg:
            raise TorError(
                f"Pluggable transport helper '{binary}' for '{pt}' is missing, "
                f"and the package name is not defined for package manager '{pm}'."
            )

        logger.info("Installing pluggable transport package '%s' via %s...", pkg, pm)
        cmd = []
        if pm == "apt-get":
            # Ensure apt cache is updated if installing a new package
            subprocess.run(["apt-get", "update"], capture_output=True, check=False)
            cmd = ["apt-get", "install", "-y", pkg]
        elif pm == "dnf":
            cmd = ["dnf", "install", "-y", pkg]
        elif pm == "pacman":
            cmd = ["pacman", "-Sy", "--noconfirm", pkg]
        elif pm == "zypper":
            cmd = ["zypper", "install", "-y", pkg]

        if not cmd:
            raise TorError(f"Unsupported package manager for installation: {pm}")

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info("Successfully installed '%s'.", pkg)
        except subprocess.CalledProcessError as e:
            err_output = (
                e.stderr.decode(errors="replace").strip() if e.stderr else str(e)
            )
            raise TorError(
                f"Failed to install pluggable transport package '{pkg}' via {pm}: {err_output}"
            ) from e

        # Double check
        if not shutil.which(binary):
            raise TorError(
                f"Pluggable transport helper '{binary}' was installed but is still not found in PATH."
            )


# Torrc generation


def generate_torrc(
    tor_user: str,
    transport_port: int = 9041,
    dns_port: int = 9054,
    block_doh: bool = True,
    use_bridges: bool = False,
    bridges: Optional[list[str]] = None,
) -> Path:
    """Generate a volatile ``torrc`` in ``/run/tor/ttp/torrc``.

    The ``DataDirectory`` points to the persistent cache so that
    Entry Guards are preserved across runs for fast bootstrap.

    Parameters
    ----------
    tor_user:
        System user Tor should run as (e.g. ``debian-tor``).
    transport_port:
        The customized or default TransPort port.
    dns_port:
        The customized or default DNSPort port.
    block_doh:
        If True, block DNS-over-HTTPS by resolving its canary domain to 0.0.0.0.

    Returns
    -------
    Path
        The path to the generated torrc file.
    """
    TOR_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    try:
        shutil.chown(TOR_RUNTIME_DIR, user=tor_user, group=tor_user)
    except (KeyError, ValueError, OSError):
        pass
    os.chmod(TOR_RUNTIME_DIR, 0o700)

    # Ensure parent directory of cache is owned by the Tor user and has correct permissions
    parent_dir = TOR_CACHE_DIR.parent
    if parent_dir.exists():
        try:
            shutil.chown(parent_dir, user=tor_user, group=tor_user)
            os.chmod(parent_dir, 0o700)
        except (KeyError, ValueError, OSError):
            pass

    # Persistent cache directory must be fixed on every run
    data_dir = str(TOR_CACHE_DIR)
    os.makedirs(data_dir, exist_ok=True)
    try:
        shutil.chown(data_dir, user=tor_user)
    except (KeyError, ValueError, OSError):
        pass
    os.chmod(data_dir, 0o700)

    from ttp.tor_detect import is_ipv6_supported

    ipv6_avail = is_ipv6_supported()

    torrc_path = TOR_RUNTIME_DIR / "torrc"
    lines = [
        "# Generated by TTP: runtime volatile config",
        "VirtualAddrNetworkIPv4 10.192.0.0/10",
        "AutomapHostsOnResolve 1",
        f"TransPort {transport_port}",
        f"DNSPort {dns_port}",
        "SocksPort 0",
        "ControlSocket /run/tor/ttp/control.sock",
        "ControlSocketsGroupWritable 1",
        "CookieAuthentication 1",
        f"CookieAuthFile {TOR_RUNTIME_DIR / 'auth_cookie'}",
        "CookieAuthFileGroupReadable 1",
        "ClientUseIPv4 1",
    ]

    if ipv6_avail:
        lines.extend(
            [
                f"TransPort [::1]:{transport_port}",
                f"DNSPort [::1]:{dns_port}",
                "ClientUseIPv6 1",
                "VirtualAddrNetworkIPv6 fc00::/7",
            ]
        )
    else:
        lines.append("ClientUseIPv6 0")

    lines.extend(
        [
            f"DataDirectory {TOR_CACHE_DIR}",
        ]
    )
    if block_doh:
        doh_domains = [
            "use-application-dns.net",  # Firefox canary
            "cloudflare-dns.com",
            "dns.google",
            "dns.quad9.net",
            "doh.opendns.com",
            "dns.adguard.com",
        ]
        for domain in doh_domains:
            lines.append(f"MapAddress {domain} 0.0.0.0")

    if use_bridges and bridges:
        lines.append("UseBridges 1")
        required_transports = []
        for b in bridges:
            parts = b.split()
            if parts:
                first_word = parts[0].lower()
                if first_word in PT_MAP:
                    if first_word not in required_transports:
                        required_transports.append(first_word)

        for pt in required_transports:
            binary = PT_MAP[pt]["binary"]
            binary_path = shutil.which(binary)
            if binary_path:
                lines.append(f"ClientTransportPlugin {pt} exec {binary_path}")
            else:
                lines.append(f"ClientTransportPlugin {pt} exec /usr/bin/{binary}")

        for b in bridges:
            lines.append(f"Bridge {b}")

    if tor_user != "root":
        lines.append(f"User {tor_user}")

    torrc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Generated runtime torrc at %s", torrc_path)
    return torrc_path


# Dedicated ttp-tor systemd service


def _write_service_unit(tor_user: str) -> None:
    """Write a volatile ``ttp-tor.service`` unit to ``/run/systemd/system/``.

    This creates a dedicated Tor instance for TTP that:

    * Reads our generated ``/run/tor/ttp/torrc`` directly.
    * Has **no sandboxing** (``ProtectSystem``, ``ReadWritePaths``),
      so it can freely write to ``/run/tor/ttp/`` and ``/var/lib/tor/ttp/``.
    * Does **not** interfere with the system's ``tor.service``.
    * Is fully volatile - the unit file lives in /run/ and
      evaporates on reboot.

    Tor starts as root and drops privileges via the ``User`` directive
    in the generated torrc.
    """
    tor_bin = shutil.which("tor") or "/usr/bin/tor"
    unit = f"""\
[Unit]
Description=TTP Managed Tor Instance
After=network.target

[Service]
Type=simple
# Ensure directories exist and have correct permissions via privileged ExecStartPre
ExecStartPre=+/bin/mkdir -p {TOR_CACHE_DIR} {TOR_RUNTIME_DIR}
ExecStartPre=+/bin/chown -R {tor_user}:{tor_user} {TOR_CACHE_DIR} {TOR_RUNTIME_DIR}
ExecStartPre=+/bin/chown {tor_user}:{tor_user} {TOR_CACHE_DIR.parent}
ExecStartPre=+/bin/chmod 0700 {TOR_CACHE_DIR.parent}

ExecStart={tor_bin} -f {TOR_RUNTIME_DIR / "torrc"} --RunAsDaemon 0
Restart=no
TimeoutStartSec=120
LimitNOFILE=32768
"""
    TTP_SERVICE_PATH.parent.mkdir(parents=True, exist_ok=True)
    TTP_SERVICE_PATH.write_text(unit, encoding="utf-8")
    logger.debug("Wrote volatile service unit to %s", TTP_SERVICE_PATH)


def start_tor_service(
    tor_user: str,
    transport_port: int = 9041,
    dns_port: int = 9054,
    block_doh: bool = True,
    use_bridges: bool = False,
    bridges: Optional[list[str]] = None,
) -> None:
    """Generate the runtime torrc and start a dedicated TTP Tor service.

    1. Generate volatile torrc in ``/run/tor/ttp/torrc``.
    2. Write a volatile ``ttp-tor.service`` unit to ``/run/systemd/system/``.
    3. Reload systemd and start the service.

    This approach avoids hijacking the system's ``tor.service`` (which
    may have restrictive sandboxing via ``ProtectSystem``/``ReadWritePaths``
    that blocks access to TTP paths).

    Parameters
    ----------
    tor_user:
        System user Tor should run as.
    transport_port:
        The customized or default TransPort port.
    dns_port:
        The customized or default DNSPort port.
    block_doh:
        If True, block DNS-over-HTTPS via canary mapping.
    use_bridges:
        True to globally enable Tor bridges.
    bridges:
        List of bridge lines to append.
    """
    generate_torrc(
        tor_user,
        transport_port=transport_port,
        dns_port=dns_port,
        block_doh=block_doh,
        use_bridges=use_bridges,
        bridges=bridges,
    )
    _write_service_unit(tor_user)

    try:
        subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True,
            text=True,
            check=True,
        )
        subprocess.run(
            ["systemctl", "restart", TTP_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise TorError(
            f"Failed to start '{TTP_SERVICE_NAME}': {e.stderr.strip()}"
        ) from e
    logger.info("TTP Tor service started with dedicated config.")


def stop_tor_service() -> None:
    """Stop the dedicated TTP Tor service and remove the volatile unit.

    Uses ``check=False`` since the service may already be stopped
    (idempotent).
    """
    subprocess.run(
        ["systemctl", "stop", TTP_SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    # Clean up the volatile unit
    TTP_SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(
        ["systemctl", "daemon-reload"],
        capture_output=True,
        text=True,
        check=False,
    )
    logger.info("TTP Tor service stopped and unit removed.")


# Package installation


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


# SELinux policy management


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


# Main entry point


def ensure_tor_ready(
    transport_port: int = 9041,
    dns_port: int = 9054,
    block_doh: bool = True,
    use_bridges: bool = False,
    bridges: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Ensure Tor is installed and start it via the OS native service.

    Returns a dictionary with detection info. The Tor service is
    managed by systemd and survives the exit of the TTP process.
    """
    info = detect_tor(transport_port=transport_port, dns_port=dns_port)

    if not info["is_installed"]:
        pm = detect_package_manager()
        if pm is None:
            raise TorError("No supported package manager found.")
        install_tor(pm)
        info = detect_tor(transport_port=transport_port, dns_port=dns_port)

    if not info["is_installed"]:
        raise TorError("Tor binary not found after installation attempt.")

    tor_user = info.get("tor_user", "debian-tor")

    # If bridges are requested, ensure the corresponding pluggable transports are installed
    if use_bridges and bridges:
        required_transports = []
        for b in bridges:
            parts = b.split()
            if parts:
                first_word = parts[0].lower()
                if first_word in PT_MAP:
                    if first_word not in required_transports:
                        required_transports.append(first_word)
        if required_transports:
            ensure_pluggable_transports(required_transports)

    # Start Tor via the dedicated ttp-tor service
    start_tor_service(
        tor_user,
        transport_port=transport_port,
        dns_port=dns_port,
        block_doh=block_doh,
        use_bridges=use_bridges,
        bridges=bridges,
    )

    return info
