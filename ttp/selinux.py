# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""SELinux policy management for Tor dynamic port bindings."""

import importlib.resources
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("ttp")


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
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath("ttp_tor_policy.te")

    with importlib.resources.as_file(traversable) as te_path:
        if not te_path.exists():
            logger.warning(f"SELinux policy source missing at {te_path}. Skipping.")
            return

        if not shutil.which("checkmodule") or not shutil.which("semodule_package"):
            logger.warning(
                "checkmodule or semodule_package not found. Cannot compile SELinux policy. "
                "Please install checkpolicy and policycoreutils manually."
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
            logger.warning(f"SELinux policy installation failed: {e}. Tor might have permission issues.")


def label_ports_selinux(transport_port: int, dns_port: int) -> None:
    """Label our specific TransPort and DNSPort as tor_port_t in SELinux if semanage is available."""
    if not shutil.which("semanage"):
        logger.debug("semanage not available, skipping dynamic SELinux port labeling.")
        return

    for port, proto in [(transport_port, "tcp"), (dns_port, "udp")]:
        try:
            logger.debug("Adding SELinux port label tor_port_t for %s/%s", port, proto)
            subprocess.run(
                [
                    "semanage",
                    "port",
                    "-a",
                    "-t",
                    "tor_port_t",
                    "-p",
                    proto,
                    str(port),
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except subprocess.CalledProcessError:
            # If the port mapping already exists, modify it instead
            try:
                subprocess.run(
                    [
                        "semanage",
                        "port",
                        "-m",
                        "-t",
                        "tor_port_t",
                        "-p",
                        proto,
                        str(port),
                    ],
                    capture_output=True,
                    check=True,
                    timeout=10,
                )
            except subprocess.CalledProcessError as e_mod:
                logger.warning(
                    "Failed to label port %d/%s as tor_port_t: %s",
                    port,
                    proto,
                    e_mod.stderr.decode().strip(),
                )


def unlabel_ports_selinux(transport_port: int, dns_port: int) -> None:
    """Remove our specific TransPort and DNSPort labels from SELinux if semanage is available."""
    if not shutil.which("semanage"):
        return

    for port, proto in [(transport_port, "tcp"), (dns_port, "udp")]:
        try:
            logger.debug("Removing SELinux port label for %s/%s", port, proto)
            subprocess.run(
                ["semanage", "port", "-d", "-p", proto, str(port)],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except subprocess.CalledProcessError:
            # Non-fatal if removal fails (e.g. was never added or already removed)
            pass


def remove_selinux_module() -> None:
    """Remove the custom TTP SELinux policy module."""
    # PATH lookup, not a hardcoded /usr/sbin: semodule sits in different places
    # across distributions, and this matches how the module probes checkmodule
    # and semodule_package above.
    if not shutil.which("semodule"):
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
