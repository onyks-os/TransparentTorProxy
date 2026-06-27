from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer

from ttp import dns, firewall, state, tor_install
from ttp.commands._common import (
    _PREFIX,
    console,
    require_root as _require_root,
    require_systemd,
)
from ttp.commands.lifecycle import do_stop as _do_stop
from ttp.commands.start import start_command


def stop_command(
    restore_only: bool = typer.Option(
        False,
        "--restore-only",
        help="Force network restoration even if TTP is crashed or no session is active.",
    ),
) -> None:
    """Stop the transparent Tor proxy and restore the network."""
    _require_root()

    if restore_only:
        console.print(f"{_PREFIX} Forcing network restoration (restore-only)...")

        # Stop watchdog first
        from ttp import watchdog as wd

        try:
            wd.stop_watchdog()
        except Exception:
            pass

        # Graceful shutdown even in restore-only mode
        from ttp import tor_control

        tor_control.graceful_shutdown(timeout=10)
        tor_install.stop_tor_service()
        firewall.destroy_rules()

        lock = state.read_lock()
        if lock:
            dns.restore_dns(lock.get("dns_backup"))
        else:
            dns.restore_dns(None)

        state.delete_lock()
        console.print(f"{_PREFIX} [bold red]Network restored. Traffic in cleartext.[/]")
        raise typer.Exit(code=0)

    if state.read_lock() is None:
        console.print(f"{_PREFIX} No active session found.")
        raise typer.Exit(code=0)

    _do_stop()


def restart_command(
    interface: Optional[str] = typer.Option(
        None,
        "--interface",
        "-i",
        help="Network interface to configure DNS on (auto-detected if omitted).",
    ),
    bootstrap_timeout: int = typer.Option(
        180,
        "--bootstrap-timeout",
        help="Timeout in seconds to wait for Tor to bootstrap.",
    ),
    transport_port: int = typer.Option(
        9041,
        "--transport-port",
        "-t",
        help="Port for Tor's TransPort redirect.",
    ),
    dns_port: int = typer.Option(
        9054,
        "--dns-port",
        "-d",
        help="Port for Tor's DNSPort redirect.",
    ),
    allow_root: bool = typer.Option(
        False,
        "--allow-root",
        help="Allow root processes to bypass Tor routing (not recommended, increases leak risk).",
    ),
    no_lan_bypass: bool = typer.Option(
        False,
        "--no-lan-bypass",
        help="Do not bypass Tor routing for local subnets (RFC 1918 & Link-Local).",
    ),
    watchdog: bool = typer.Option(
        False,
        "--watchdog",
        "-w",
        help="Start the background watchdog daemon to monitor session integrity.",
    ),
    bypass_user: Optional[list[str]] = typer.Option(
        None,
        "--bypass-user",
        help="System user(s) to bypass Tor routing.",
    ),
    bypass_group: Optional[list[str]] = typer.Option(
        None,
        "--bypass-group",
        help="System group(s) to bypass Tor routing.",
    ),
    use_bridges: bool = typer.Option(
        False,
        "--use-bridges",
        help="Globally enable Tor bridges support.",
    ),
    bridge_file: Optional[Path] = typer.Option(
        None,
        "--bridge-file",
        help="Path to a file containing Tor bridge lines.",
    ),
    bridge: Optional[list[str]] = typer.Option(
        None,
        "--bridge",
        help="Individual Tor bridge line. Can be specified multiple times.",
    ),
    external_daemon: bool = typer.Option(
        False,
        "--external-daemon",
        help="Run TTP in BYOD mode, delegating Tor lifecycle management to the host.",
    ),
    tor_uid: Optional[str] = typer.Option(
        None,
        "--tor-uid",
        help="Specify the numeric UID or username of the Tor process manually in BYOD mode.",
    ),
    no_ipv6: bool = typer.Option(
        False,
        "--no-ipv6",
        help="Force disable all IPv6 traffic (drops outgoing IPv6 to prevent leaks).",
    ),
) -> None:
    """Restart the transparent Tor proxy session."""
    _require_root()

    require_systemd()

    if state.read_lock() is not None:
        console.print(f"{_PREFIX} Stopping current session...")
        _do_stop()
        time.sleep(1)
    else:
        console.print(f"{_PREFIX} No active session found, starting a new one...")

    kwargs_start = {}
    if bypass_user is not None:
        kwargs_start["bypass_user"] = bypass_user
    if bypass_group is not None:
        kwargs_start["bypass_group"] = bypass_group
    if use_bridges:
        kwargs_start["use_bridges"] = use_bridges
    if bridge_file is not None:
        kwargs_start["bridge_file"] = bridge_file
    if bridge is not None:
        kwargs_start["bridge"] = bridge

    start_command(
        interface=interface,
        bootstrap_timeout=bootstrap_timeout,
        transport_port=transport_port,
        dns_port=dns_port,
        allow_root=allow_root,
        no_lan_bypass=no_lan_bypass,
        watchdog=watchdog,
        external_daemon=external_daemon,
        tor_uid=tor_uid,
        no_ipv6=no_ipv6,
        **kwargs_start,
    )
