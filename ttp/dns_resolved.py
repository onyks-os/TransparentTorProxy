# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Systemd-resolved configuration management for TTP.

Provides utilities to configure systemd-resolved to forward DNS queries
to Tor's DNSPort (with IPv6 fallback if available) and restore the original
DNS configuration upon session teardown.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("ttp")

RESOLVED_CONF_DIR = Path("/run/systemd/resolved.conf.d")
RESOLVED_CONF_FILE = RESOLVED_CONF_DIR / "ttp.conf"


def is_resolved_active() -> bool:
    """Return True if systemd-resolved is active (running)."""
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "systemd-resolved"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return res.stdout.strip() == "active"
    except Exception:
        return False


def apply_resolved(dns_port: int, disable_ipv6: bool = False) -> bool:
    """Write volatile resolved configuration and restart systemd-resolved.

    Parameters
    ----------
    dns_port:
        The port Tor's DNSPort is listening on.
    disable_ipv6:
        If True, do not configure IPv6 DNS address.

    Returns
    -------
    bool
        True if systemd-resolved was active and successfully configured.
    """
    if not is_resolved_active():
        return False

    from ttp.system_info import is_ipv6_supported

    dns_servers = f"127.0.0.1:{dns_port}"
    if is_ipv6_supported() and not disable_ipv6:
        dns_servers += f" [::1]:{dns_port}"

    config_content = (
        "[Resolve]\n"
        f"DNS={dns_servers}\n"
        "FallbackDNS=\n"
        "Domains=~.\n"
        "DNSOverTLS=no\n"
        "MulticastDNS=no\n"
        "LLMNR=no\n"
        "Cache=no-negative\n"
    )

    try:
        RESOLVED_CONF_DIR.mkdir(parents=True, exist_ok=True)
        RESOLVED_CONF_FILE.write_text(config_content, encoding="utf-8")

        subprocess.run(
            ["systemctl", "restart", "systemd-resolved"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        subprocess.run(
            ["resolvectl", "flush-caches"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        logger.info("Configured systemd-resolved for Tor DNS redirection.")
        return True
    except Exception as e:
        logger.error("Failed to apply systemd-resolved configuration: %s", e)
        # Attempt immediate cleanup if we failed partially
        restore_resolved()
        raise


def restore_resolved() -> None:
    """Remove volatile resolved configuration and restart systemd-resolved."""
    try:
        if RESOLVED_CONF_FILE.exists():
            RESOLVED_CONF_FILE.unlink()
    except OSError as e:
        logger.warning("Failed to remove systemd-resolved drop-in: %s", e)

    try:
        subprocess.run(
            ["systemctl", "restart", "systemd-resolved"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except Exception as e:
        logger.warning("Failed to restart systemd-resolved during restore: %s", e)

    try:
        subprocess.run(
            ["resolvectl", "flush-caches"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except Exception as e:
        logger.debug("Failed to flush systemd-resolved caches: %s", e)
