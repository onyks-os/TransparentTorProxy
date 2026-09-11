# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tor systemd service lifecycle management module."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from ttp.exceptions import TorError
from ttp.paths import resolve, resolve_optional
from ttp.selinux import label_ports_selinux
from ttp.tor_config import TOR_CACHE_DIR, TOR_RUNTIME_DIR, generate_torrc

# Volatile systemd unit for TTP's dedicated Tor instance.
# Lives in /run/ so it disappears on reboot.
TTP_SERVICE_NAME = "ttp-tor"
TTP_SERVICE_PATH = Path(f"/run/systemd/system/{TTP_SERVICE_NAME}.service")

logger = logging.getLogger("ttp")


def _build_service_unit_content(tor_user: str, tor_bin: str) -> str:
    """Build and return the volatile systemd ttp-tor.service unit content.

    This is a **pure function** with no side-effects.

    Args:
        tor_user: Username running the Tor daemon.
        tor_bin: Absolute path to the Tor executable binary.

    Returns:
        str: Rendered systemd service unit file definition.
    """
    return f"""\
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


def _write_service_unit(tor_user: str) -> None:
    """Write a volatile ``ttp-tor.service`` unit to ``/run/systemd/system/``.

    Creates a dedicated systemd service definition for TTP in volatile memory.

    Args:
        tor_user: Username running the Tor process.
    """
    # This path is written into the systemd unit's ExecStart and then run as
    # root by systemd. `shutil.which` consults $PATH, so a caller-controlled
    # environment could have decided which program the unit launches - for the
    # lifetime of the unit file, not just the current process.
    tor_bin = resolve_optional("tor") or "/usr/bin/tor"
    unit = _build_service_unit_content(tor_user, tor_bin)
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
    disable_ipv6: bool = False,
) -> None:
    """Generate the runtime torrc and start a dedicated TTP Tor systemd service.

    Sequence:
        1. Generate volatile torrc in ``/run/tor/ttp/torrc``.
        2. Label SELinux ports if SELinux is enforcing.
        3. Write a volatile ``ttp-tor.service`` unit to ``/run/systemd/system/``.
        4. Reload systemd daemon and start the service.

    Args:
        tor_user: System user designated to run Tor.
        transport_port: Local TCP port for Tor TransPort redirection.
        dns_port: Local UDP/TCP port for Tor DNSPort redirection.
        block_doh: If True, maps canary DoH domains to 0.0.0.0.
        use_bridges: If True, configures Tor to route via Pluggable Transports.
        bridges: Optional list of bridge configuration strings.
        disable_ipv6: If True, forces IPv6 client routing off.

    Raises:
        TorError: If systemd daemon reload or service restart fails.
    """
    generate_torrc(
        tor_user,
        transport_port=transport_port,
        dns_port=dns_port,
        block_doh=block_doh,
        use_bridges=use_bridges,
        bridges=bridges,
        disable_ipv6=disable_ipv6,
    )
    label_ports_selinux(transport_port, dns_port)
    _write_service_unit(tor_user)

    try:
        subprocess.run(
            [resolve("systemctl"), "daemon-reload"],
            capture_output=True,
            text=True,
            check=True,
        )
        subprocess.run(
            [resolve("systemctl"), "restart", TTP_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise TorError(f"Failed to start '{TTP_SERVICE_NAME}': {e.stderr.strip()}") from e
    logger.info("TTP Tor service started with dedicated config.")


def stop_tor_service() -> None:
    """Stop the dedicated TTP Tor service and remove the volatile systemd unit."""
    subprocess.run(
        [resolve("systemctl"), "stop", TTP_SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    # Clean up the volatile unit
    TTP_SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(
        [resolve("systemctl"), "daemon-reload"],
        capture_output=True,
        text=True,
        check=False,
    )
    logger.info("TTP Tor service stopped and unit removed.")
