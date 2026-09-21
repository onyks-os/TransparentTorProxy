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
# Type=notify, not simple: a simple unit reports success the moment the process
# is forked, so a Tor that dies while parsing its config - an unbindable
# listener, an unusable DataDirectory - was reported as a successful start and
# only surfaced 60s later as a bootstrap stuck at 0%. Tor signals readiness
# through sd_notify when run with --RunAsDaemon 0, which is how ExecStart below
# already invokes it, and which is what the stock tor.service on Fedora and
# Debian relies on. NotifyAccess mirrors that unit.
#
# The trade-off: a Tor built without systemd support never sends the signal, so
# `systemctl restart` waits out TimeoutStartSec and fails. That is a loud,
# named failure carrying the journal, rather than a session built on a daemon
# that is not there.
Type=notify
NotifyAccess=all
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


#: How much of the unit's journal to quote when a start fails. Enough to carry
#: Tor's own [warn]/[err] lines, short enough to read in a terminal.
_JOURNAL_TAIL_LINES = 20


def _recent_journal(unit: str = TTP_SERVICE_NAME, lines: int = _JOURNAL_TAIL_LINES) -> str:
    """Return the last lines the unit logged, or ``""`` if they cannot be read.

    Strictly best-effort: this decorates an error that has already happened, so
    every failure of its own - no journalctl, a non-systemd log stack, a
    timeout - degrades to a less informative message and never replaces the
    failure being reported.
    """
    journalctl = resolve_optional("journalctl")
    if not journalctl:
        return ""
    try:
        result = subprocess.run(
            [journalctl, "-u", f"{unit}.service", "-n", str(lines), "--no-pager", "-o", "cat"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    return result.stdout.strip()


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
        detail = (e.stderr or "").strip()
        message = f"Failed to start '{TTP_SERVICE_NAME}': {detail}"
        # systemctl says only that the job failed. The reason Tor refused to
        # run is in its own journal, and it is the whole point of failing here
        # rather than 60s later: "Could not bind to 127.0.0.1:9054: Permission
        # denied" tells an operator what to do, "Job for ttp-tor.service
        # failed" does not.
        journal = _recent_journal()
        if journal:
            message += f"\nLast lines from the Tor journal:\n{journal}"
        raise TorError(message) from e
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
