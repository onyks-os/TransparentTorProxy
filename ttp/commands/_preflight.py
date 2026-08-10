# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Pre-flight checks and validations for the TTP CLI start command."""

from __future__ import annotations

import typer

from ttp import state, tor_install
from ttp.commands._common import (
    print_error as _print_error,
)
from ttp.exceptions import StateError


def validate_ports(transport_port: int, dns_port: int, external_daemon: bool) -> None:
    """Validate port ranges, equality, and availability/listening status."""
    from ttp.commands import start as start_mod

    if not (1024 <= transport_port <= 65535):
        _print_error(
            "Invalid Port",
            f"TransPort {transport_port} must be between 1024 and 65535.",
        )
        raise typer.Exit(code=1)

    if not (1024 <= dns_port <= 65535):
        _print_error(
            "Invalid Port",
            f"DNSPort {dns_port} must be between 1024 and 65535.",
        )
        raise typer.Exit(code=1)

    if transport_port == dns_port:
        _print_error(
            "Port Conflict",
            f"TransPort and DNSPort cannot be the same ({transport_port}).",
        )
        raise typer.Exit(code=1)

    if not external_daemon:
        for port, name in [(transport_port, "TransPort"), (dns_port, "DNSPort")]:
            if start_mod._is_port_in_use(port):
                _print_error(
                    "Port In Use",
                    f"The {name} port {port} is already in use by another process.",
                )
                raise typer.Exit(code=1)
    else:
        if not start_mod._is_port_listening_tcp(transport_port) or not start_mod._is_port_listening_udp(dns_port):
            _print_error(
                "Tor Not Running",
                f"Tor is not running on the requested TransPort ({transport_port}) or DNSPort ({dns_port}).\n"
                "Please start your Tor daemon before running TTP.",
            )
            raise typer.Exit(code=1)


def check_session_state() -> dict | None:
    """Check for active or orphaned TTP sessions. Handles auto-recovery for orphans."""
    from ttp import dns, firewall
    from ttp.commands._common import _PREFIX, console

    lock = state.read_lock()
    if lock:
        if state.is_orphan():
            console.print(f"{_PREFIX} [yellow]Orphaned session detected (PID {lock.get('pid')}). Auto-recovering...[/]")
            state.attempt_recovery(firewall.destroy_rules, dns.restore_dns)
            console.print(f"{_PREFIX} Recovery complete. Starting new session...")
        else:
            _print_error(
                "Concurrency Error",
                f"Another TTP process (PID {lock['pid']}) is currently running.",
            )
            raise typer.Exit(code=1)
    return lock


def preflight_checks() -> None:
    """Run pre-flight checks (tmpfs space verification and SELinux setup)."""
    try:
        state.check_tmpfs_space()
    except StateError as exc:
        _print_error("Pre-flight Failed", str(exc))
        raise typer.Exit(code=1)

    tor_install.setup_selinux_if_needed()
