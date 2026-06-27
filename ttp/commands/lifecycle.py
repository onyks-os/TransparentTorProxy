# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Session lifecycle: graceful stop and signal handling."""

from __future__ import annotations

import shutil
import signal
import subprocess
import sys
import time

from ttp import dns, firewall, state, tor_install
from ttp.commands._common import (
    _PREFIX,
    console,
    get_uid_from_port,
    logger,
)


def do_stop() -> None:
    """Internal stop logic - shared by ``stop`` command and signal handler."""
    lock = state.read_lock()
    if lock is None:
        return

    is_external = lock.get("external_daemon", False)

    if not is_external:
        console.print(f"{_PREFIX} Stopping watchdog daemon...")
        from ttp import watchdog as wd

        try:
            wd.stop_watchdog()
        except Exception:
            pass

    import pwd

    tor_uid = lock.get("tor_uid")
    if tor_uid is None:
        transport_port = lock.get("transport_port", 9041)
        tor_uid = get_uid_from_port(transport_port)
        if tor_uid is None:
            for fallback_user in ("tor", "debian-tor"):
                try:
                    tor_uid = pwd.getpwnam(fallback_user).pw_uid
                    break
                except KeyError:
                    continue

    console.print(f"{_PREFIX} Applying teardown lockdown...")
    firewall.apply_teardown_lockdown(tor_uid)

    if not is_external:
        console.print(f"{_PREFIX} Gracefully shutting down Tor circuits...")
        from ttp import tor_control

        tor_control.graceful_shutdown(timeout=10)

        console.print(f"{_PREFIX} Stopping Tor service...")
        tor_install.stop_tor_service()

    console.print(
        f"{_PREFIX} Executing active socket slaughter (Zero-Leak teardown)..."
    )
    firewall.apply_active_socket_slaughter()
    console.print(f"{_PREFIX} Waiting 300ms for pending connections to crash...")
    time.sleep(0.3)

    conntrack_path = shutil.which("conntrack")
    if conntrack_path:
        console.print(f"{_PREFIX} Flushing connection tracking table...")
        try:
            subprocess.run(
                [conntrack_path, "-F"], capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Failed to flush conntrack table: %s",
                e.stderr.strip() if e.stderr else str(e),
            )
    else:
        logger.debug("conntrack binary not found, skipping flush.")

    console.print(f"{_PREFIX} Removing nftables rules...")
    firewall.destroy_rules()

    console.print(f"{_PREFIX} Restoring DNS...")
    dns.restore_dns(lock.get("dns_backup"))

    state.delete_lock()
    console.print(f"{_PREFIX} [bold red]Session terminated. Traffic in cleartext.[/]")


def signal_handler(signum: int, frame) -> None:
    """Handle SIGINT/SIGTERM - clean up and exit."""
    console.print(f"\n{_PREFIX} Signal received, restoring network...")
    do_stop()
    sys.exit(0)


def register_signal_handlers() -> None:
    """Register SIGINT/SIGTERM handlers for safe session cleanup."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
