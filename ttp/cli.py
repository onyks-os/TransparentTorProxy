#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""CLI entry point - Typer application for TTP.

This module provides the command-line interface and coordinates the interaction
between specialized modules (firewall, dns, tor_install, etc.).

ARCHITECTURE NOTE:
- This file handles high-level execution flow and CLI orchestration.
- It handles UI (Rich/Typer) and high-level logic flow.
- It should NOT contain low-level system interaction code (that goes into modules).

Exposes commands: ``start``, ``stop``, ``refresh``, ``status``, ``uninstall``, ``logs``, ``diagnose``.
All commands require root privileges, except for ttp --help. Signal handlers guarantee that the
network state is restored even on SIGINT/SIGTERM.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)

from ttp import dns, firewall, state, tor_install
from ttp.exceptions import FirewallError, DNSError, StateError, TorError

app = typer.Typer(
    name="ttp",
    help="TTP - Transparent Tor Proxy. Route all traffic through Tor.\n\nTo view specific options for a command, run: ttp <command> --help (e.g., ttp start --help)",
    add_completion=False,
)
console = Console()

_PREFIX = "[bold cyan]\\[TTP][/bold cyan]"
err_console = Console(stderr=True)


class CLIState:
    verbose: bool = False
    quiet: bool = False
    log_format: str = "text"
    bypass_users: list[str] = []
    bypass_groups: list[str] = []


cli_state = CLIState()


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug output."),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress all output except errors."
    ),
    log_format: str = typer.Option(
        "text", "--log-format", help="Log format: 'text' or 'json'."
    ),
):
    cli_state.verbose = verbose
    cli_state.quiet = quiet
    cli_state.log_format = log_format.lower()
    if quiet:
        console.quiet = True
    _setup_logging()


def _print_error(title: str, msg: str) -> None:
    """Print a styled error message using a Rich Panel."""
    err_console.print(
        Panel(msg, title=f"[bold red]{title}[/bold red]", border_style="red")
    )


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        log_obj = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


_LOG_PATH = Path("/run/ttp/ttp.log")
logger = logging.getLogger("ttp")


def _setup_logging() -> None:
    """Configure logging based on the CLI state."""
    from logging.handlers import RotatingFileHandler
    import logging

    for h in list(logger.handlers):
        logger.removeHandler(h)

    try:
        state.ensure_runtime_dir()
    except OSError:
        # Runtime dir might not be writeable if run without root privileges (e.g. for sub-commands help).
        pass

    try:
        # Volatile log, capped at 1MB to avoid filling RAM
        handler = RotatingFileHandler(_LOG_PATH, maxBytes=1048576, backupCount=1)
        if cli_state.log_format == "json":
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if cli_state.verbose else logging.INFO)
    except OSError:
        # Non-fatal - logging is best-effort.
        pass

    if not cli_state.quiet:
        if cli_state.log_format == "json":
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(JSONFormatter())
            console_handler.setLevel(
                logging.DEBUG if cli_state.verbose else logging.INFO
            )
            logger.addHandler(console_handler)
            logger.setLevel(logging.DEBUG if cli_state.verbose else logging.INFO)
        elif cli_state.verbose:
            from rich.logging import RichHandler

            rich_handler = RichHandler(console=console, show_path=False)
            rich_handler.setLevel(logging.DEBUG)
            logger.addHandler(rich_handler)
            logger.setLevel(logging.DEBUG)


# Helpers


def _is_port_in_use(port: int) -> bool:
    """Return True if the port is already in use (bound) on localhost (IPv4/IPv6)."""
    import socket
    import errno

    # Check IPv4 TCP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
    except OSError:
        return True
    # Check IPv4 UDP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
    except OSError:
        return True

    # Check IPv6 TCP
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("::1", port))
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    return True
    except OSError:
        pass

    # Check IPv6 UDP
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("::1", port))
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    return True
    except OSError:
        pass

    return False


def _validate_bridge_line(line: str) -> None:
    """Perform basic format validation on a bridge configuration line."""
    parts = line.split()
    if not parts:
        raise ValueError("Empty bridge line")

    # Check if first field is ip:port (vanilla bridge)
    if ":" in parts[0]:
        return

    # Check if second field exists and is ip:port (PT bridge)
    if len(parts) >= 2 and ":" in parts[1]:
        first_word = parts[0].lower()
        if first_word in {"obfs4", "snowflake", "meek", "meek_lite"}:
            return
        else:
            raise ValueError(f"Unsupported pluggable transport: '{parts[0]}'")

    raise ValueError(
        "Invalid bridge format. Expected '<ip>:<port>' or '<transport> <ip>:<port>'"
    )


def _require_root() -> None:
    """Exit with an error if the process is not running as root."""
    if os.geteuid() != 0:
        _print_error(
            "Permission Denied", "This command must be run as root (use sudo)."
        )
        raise typer.Exit(code=1)


def _verify_tor(timeout: int = 180) -> tuple[bool, str]:
    """Verify that traffic is actually routed through Tor, with UI."""
    from ttp import tor_control

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(
            f"{_PREFIX} Waiting for Tor to bootstrap...", total=100
        )

        try:
            tor_control.wait_for_bootstrap(
                progress_callback=lambda val: progress.update(task_id, completed=val),
                timeout=timeout,
            )
            progress.stop()
            console.print(f"{_PREFIX} Tor is 100% bootstrapped.")
        except (TorError, RuntimeError) as e:
            progress.stop()
            _print_error("Bootstrap Error", str(e))
            return False, "unknown"

    # Settling delay: give Tor circuits a moment to stabilize after bootstrap.
    time.sleep(2)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"{_PREFIX} Verifying Tor routing...", total=None)
        return tor_control.verify_tor()


def _do_stop() -> None:
    """Internal stop logic - shared by ``stop`` command and signal handler."""
    lock = state.read_lock()
    if lock is None:
        return

    # Preventive shutdown of the watchdog to avoid triggering emergency killswitch
    console.print(f"{_PREFIX} Stopping watchdog daemon...")
    from ttp import watchdog as wd

    try:
        wd.stop_watchdog()
    except Exception:
        pass

    # Graceful circuit teardown BEFORE touching the firewall.
    # This ensures Tor closes all circuits cryptographically so no
    # cleartext RST packets leak when nftables rules are removed.
    console.print(f"{_PREFIX} Gracefully shutting down Tor circuits...")
    from ttp import tor_control

    tor_control.graceful_shutdown(timeout=10)

    console.print(f"{_PREFIX} Stopping Tor service...")
    tor_install.stop_tor_service()

    console.print(f"{_PREFIX} Removing nftables rules...")
    firewall.destroy_rules()

    console.print(f"{_PREFIX} Restoring DNS...")
    dns.restore_dns(lock.get("dns_backup"))

    state.delete_lock()
    console.print(f"{_PREFIX} [bold red]Session terminated. Traffic in cleartext.[/]")


def _signal_handler(signum: int, frame) -> None:
    """Handle SIGINT/SIGTERM - clean up and exit."""
    console.print(f"\n{_PREFIX} Signal received, restoring network...")
    _do_stop()
    sys.exit(0)


# Commands


@app.command()
def start(
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
) -> None:
    """Start the transparent Tor proxy session."""
    _require_root()

    # Resolve and validate bypass users and groups
    import pwd
    import grp

    users = []
    if bypass_user:
        for u in bypass_user:
            users.extend([item.strip() for item in u.split(",") if item.strip()])

    groups = []
    if bypass_group:
        for g in bypass_group:
            groups.extend([item.strip() for item in g.split(",") if item.strip()])

    cli_state.bypass_users = users
    cli_state.bypass_groups = groups

    # Resolve and validate bridges
    bridge_lines = []
    if bridge_file:
        if not bridge_file.exists():
            _print_error("Bridge File Missing", f"File '{bridge_file}' not found.")
            raise typer.Exit(code=1)
        try:
            for line in bridge_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        _validate_bridge_line(line)
                        bridge_lines.append(line)
                    except ValueError as exc:
                        _print_error(
                            "Invalid Bridge Line",
                            f"Line '{line}' in file '{bridge_file}': {exc}",
                        )
                        raise typer.Exit(code=1)
        except OSError as exc:
            _print_error("Failed to read bridge file", str(exc))
            raise typer.Exit(code=1)

    if bridge:
        for b in bridge:
            b = b.strip()
            if b:
                try:
                    _validate_bridge_line(b)
                    bridge_lines.append(b)
                except ValueError as exc:
                    _print_error("Invalid Bridge Line", f"Bridge '{b}': {exc}")
                    raise typer.Exit(code=1)

    if use_bridges and not bridge_lines:
        _print_error(
            "No Bridges Provided",
            "Bridges are enabled but no bridge lines or bridge files were specified.",
        )
        raise typer.Exit(code=1)

    if bridge_lines:
        use_bridges = True

    bypass_uids = []
    for u in users:
        try:
            if u.isdigit():
                uid = int(u)
                pwd.getpwuid(uid)
            else:
                uid = pwd.getpwnam(u).pw_uid
            bypass_uids.append(uid)
        except KeyError:
            _print_error("Invalid User", f"User '{u}' does not exist on this system.")
            raise typer.Exit(code=1)

    bypass_gids = []
    for g in groups:
        try:
            if g.isdigit():
                gid = int(g)
                grp.getgrgid(gid)
            else:
                gid = grp.getgrnam(g).gr_gid
            bypass_gids.append(gid)
        except KeyError:
            _print_error("Invalid Group", f"Group '{g}' does not exist on this system.")
            raise typer.Exit(code=1)

    # Ports validation
    if not (1024 <= transport_port <= 65535):
        _print_error(
            "Invalid Port",
            f"TransPort {transport_port} must be between 1024 and 65535.",
        )
        raise typer.Exit(code=1)

    if not (1024 <= dns_port <= 65535):
        _print_error(
            "Invalid Port", f"DNSPort {dns_port} must be between 1024 and 65535."
        )
        raise typer.Exit(code=1)

    if transport_port == dns_port:
        _print_error(
            "Port Conflict",
            f"TransPort and DNSPort cannot be the same ({transport_port}).",
        )
        raise typer.Exit(code=1)

    # Pre-flight check if ports are already in use
    for port, name in [(transport_port, "TransPort"), (dns_port, "DNSPort")]:
        if _is_port_in_use(port):
            _print_error(
                "Port In Use",
                f"The {name} port {port} is already in use by another process.",
            )
            raise typer.Exit(code=1)

    # Register signal handlers for safe cleanup.
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    lock = state.read_lock()
    if lock:
        if state.is_orphan():
            console.print(
                f"{_PREFIX} [yellow]Orphaned session detected (PID {lock.get('pid')}). "
                f"Auto-recovering...[/]"
            )
            state.attempt_recovery(firewall.destroy_rules, dns.restore_dns)
            console.print(f"{_PREFIX} Recovery complete. Starting new session...")
        else:
            _print_error(
                "Concurrency Error",
                f"Another TTP process (PID {lock['pid']}) is currently running.",
            )
            raise typer.Exit(code=1)

    # Step 0a - Pre-flight: verify /run has enough space for tmpfs I/O.
    try:
        state.check_tmpfs_space()
    except StateError as exc:
        _print_error("Pre-flight Failed", str(exc))
        raise typer.Exit(code=1)

    # Step 0b - SELinux optimization (for Fedora/RHEL).
    # This ensures the kernel policy allows Tor to bind to our ports.
    # It only runs once and has zero overhead on subsequent calls.
    tor_install.setup_selinux_if_needed()

    # Step 1 - Detect / install Tor.
    console.print(f"{_PREFIX} Detecting Tor...", end=" ")
    try:
        info = tor_install.ensure_tor_ready(
            transport_port=transport_port,
            dns_port=dns_port,
            use_bridges=use_bridges,
            bridges=bridge_lines,
        )
    except TorError as exc:
        logger.error("Tor detection/install failed: %s", exc)
        console.print("[bold red]failed.[/]")
        _print_error("Tor Startup Failed", str(exc))
        raise typer.Exit(code=1)

    version = info.get("version", "")
    tor_user = info.get("tor_user", "debian-tor")
    console.print(
        f"found (v{version}), managed via system service (user: {tor_user})."
        if version
        else f"found, managed via system service (user: {tor_user})."
    )

    if info.get("firewalld"):
        console.print(
            f"{_PREFIX} [bold yellow]Warning: firewalld is active.[/bold yellow]"
        )
        console.print(
            "  [yellow]firewalld can interfere with TTP's nftables rules and cause connectivity issues.[/yellow]"
        )
        console.print(
            "  [yellow]If Tor fails to bootstrap, consider stopping it: sudo systemctl stop firewalld[/yellow]\n"
        )

    lan_bypass = not no_lan_bypass

    # Step 2 - Apply stateless firewall rules.
    try:
        kwargs_fw = {}
        if bypass_uids:
            kwargs_fw["bypass_uids"] = bypass_uids
        if bypass_gids:
            kwargs_fw["bypass_gids"] = bypass_gids

        firewall.apply_rules(
            tor_user=tor_user,
            transport_port=transport_port,
            dns_port=dns_port,
            allow_root=allow_root,
            lan_bypass=lan_bypass,
            **kwargs_fw,
        )
    except FirewallError as exc:
        _print_error("Firewall Setup Failed", str(exc))
        tor_install.stop_tor_service()
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    console.print(f"{_PREFIX} Stateless nftables rules applied (Table: inet ttp).")

    # Step 3 - Modify DNS.
    if interface is None:
        interface = dns.detect_active_interface()
    try:
        dns_backup = dns.apply_dns(interface)
    except DNSError as exc:
        logger.error("DNS setup failed: %s", exc)
        _print_error("DNS Setup Failed", str(exc))
        tor_install.stop_tor_service()
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    except Exception as exc:
        logger.error("Unexpected DNS error: %s", exc)
        _print_error(
            "DNS Setup Failed", "An unexpected error occurred during DNS configuration."
        )
        tor_install.stop_tor_service()
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    logger.info("Session started: interface=%s", interface)
    console.print(f"{_PREFIX} DNS set via overlay on interface {interface}.")

    # Step 4 - Write lock file.
    try:
        kwargs_lock = {}
        if users:
            kwargs_lock["bypass_users"] = users
        if groups:
            kwargs_lock["bypass_groups"] = groups
        if use_bridges:
            kwargs_lock["use_bridges"] = use_bridges
        if bridge_file:
            kwargs_lock["bridge_file"] = str(bridge_file)
        if bridge_lines:
            kwargs_lock["bridges"] = bridge_lines

        state.write_lock(
            dns_backup=dns_backup,
            transport_port=transport_port,
            dns_port=dns_port,
            allow_root=allow_root,
            lan_bypass=lan_bypass,
            interface=interface,
            **kwargs_lock,
        )
    except StateError as exc:
        logger.error("Failed to write lock: %s", exc)
        _print_error("Session Tracking Failed", str(exc))
        # Emergency cleanup since we can't track this session
        tor_install.stop_tor_service()
        firewall.destroy_rules()
        dns.restore_dns(dns_backup)
        raise typer.Exit(code=1)

    # Step 5 - Verify Tor is working.
    is_tor, exit_ip = _verify_tor(timeout=bootstrap_timeout)
    if is_tor:
        console.print(f"{_PREFIX} [bold green]Session active. Exit IP: {exit_ip}[/]")
    else:
        console.print(
            f"{_PREFIX} [bold yellow]Session active but Tor verification failed.[/]"
        )
        console.print(
            f"{_PREFIX} [yellow]Traffic may NOT be routed through Tor. "
            f"Check Tor service and try 'ttp stop' then 'ttp start'.[/]"
        )
        if exit_ip != "unknown":
            console.print(f"{_PREFIX} [yellow]Detected IP: {exit_ip}[/]")

    if watchdog:
        console.print(f"{_PREFIX} Starting session watchdog daemon...")
        from ttp import watchdog as wd

        try:
            wd.start_watchdog()
        except Exception as e:
            _print_error("Watchdog Error", f"Failed to start session watchdog: {e}")

    console.print(f"{_PREFIX} Use 'ttp stop' to terminate. 'ttp refresh' to change IP.")

    # One-time discrete message to encourage GitHub stars.
    if state.should_show_star_message():
        console.print(
            "\n[dim]Thanks for using TTP! Starring the repo on GitHub helps the project grow.[/]"
        )
        state.mark_star_message_shown()


@app.command()
def stop(
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


@app.command()
def restart(
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
) -> None:
    """Restart the transparent Tor proxy session."""
    _require_root()

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

    start(
        interface=interface,
        bootstrap_timeout=bootstrap_timeout,
        transport_port=transport_port,
        dns_port=dns_port,
        allow_root=allow_root,
        no_lan_bypass=no_lan_bypass,
        watchdog=watchdog,
        **kwargs_start,
    )


@app.command()
def refresh() -> None:
    """Request a new Tor circuit (new exit IP)."""
    _require_root()

    if state.read_lock() is None:
        console.print(f"{_PREFIX} No active session. Start one first with 'ttp start'.")
        raise typer.Exit(code=1)

    console.print(f"{_PREFIX} Requesting new Tor circuit...")
    from ttp import tor_control

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"{_PREFIX} Waiting for new circuit...", total=None)
        try:
            ip_changed, new_ip = tor_control.request_new_circuit()
        except TorError as exc:
            progress.stop()
            _print_error(
                "Connection Failed",
                f"{exc}\nCheck that Tor is running and ControlSocket / ControlPort is enabled.",
            )
            raise typer.Exit(code=1)

    if ip_changed:
        console.print(f"{_PREFIX} [bold green]New exit IP: {new_ip}[/]")
    else:
        console.print(
            f"{_PREFIX} [yellow]Circuit rotated but IP may not have changed yet. "
            f"Current IP: {new_ip}[/]"
        )


@app.command()
def status() -> None:
    """Show current TTP session status."""
    import urllib.request

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as response:
            current_ip = response.read().decode("utf-8").strip()
    except Exception:
        current_ip = "Unknown"

    lock = state.read_lock()
    if lock is None:
        console.print(f"{_PREFIX} Status: [bold red]INACTIVE[/]")
        console.print(f"{_PREFIX} Current IP: {current_ip}")
        console.print(f"{_PREFIX} No active session. Traffic is in cleartext.")
        raise typer.Exit(code=0)

    from ttp import tor_control

    exit_ip = tor_control.get_exit_ip()
    console.print(f"{_PREFIX} Status: [bold green]ACTIVE[/]")
    console.print(f"{_PREFIX} TransPort: {lock.get('transport_port', 9041)}")
    console.print(f"{_PREFIX} DNSPort: {lock.get('dns_port', 9054)}")
    console.print(
        f"{_PREFIX} LAN Bypass: {'[green]Enabled[/]' if lock.get('lan_bypass', True) else '[red]Disabled[/]'}"
    )
    console.print(
        f"{_PREFIX} Allow Root: {'[red]Yes[/]' if lock.get('allow_root', False) else '[green]No[/]'}"
    )

    wd_active = lock.get("watchdog_active", False)
    wd_pid = lock.get("watchdog_pid")
    wd_status_str = (
        f"[green]Active (PID {wd_pid})[/]" if wd_active else "[red]Inactive[/]"
    )
    console.print(f"{_PREFIX} Watchdog: {wd_status_str}")

    console.print(f"{_PREFIX} Exit IP: {exit_ip}")
    console.print(f"{_PREFIX} Session started: {lock.get('timestamp', 'unknown')}")
    console.print(f"{_PREFIX} Process PID: {lock.get('pid', 'unknown')}")


@app.command(name="check")
def check() -> None:
    """Quickly verify Tor network connection and circuit state."""
    import time
    from ttp import tor_control

    console.print(f"{_PREFIX} Checking Tor network connection...")

    start_time = time.time()
    # Call the highly resilient verify_tor() which retries 5 times across multiple endpoints
    is_tor, ip = tor_control.verify_tor()
    latency = round((time.time() - start_time) * 1000)

    if ip == "unknown":
        console.print(
            f"{_PREFIX} [bold red]Failed to reach any IP verification endpoint.[/bold red] "
            "Please check your internet connection or Tor service state."
        )
        raise typer.Exit(code=1)

    ctrl = tor_control.get_controller()
    circuit_stable = ctrl is not None

    lock = state.read_lock()
    transport_port = lock.get("transport_port", 9041) if lock else 9041
    dns_port = lock.get("dns_port", 9054) if lock else 9054

    console.print(f"  [cyan]-[/cyan] Current IP:      {ip}")
    console.print(f"  [cyan]-[/cyan] TransPort:       {transport_port}")
    console.print(f"  [cyan]-[/cyan] DNSPort:         {dns_port}")
    console.print(
        f"  [cyan]-[/cyan] LAN Bypass:      {'[bold green]Enabled[/]' if lock and lock.get('lan_bypass', True) else '[bold red]Disabled[/]'}"
    )
    console.print(
        f"  [cyan]-[/cyan] Allow Root:      {'[bold red]Yes[/]' if lock and lock.get('allow_root', False) else '[bold green]No[/]'}"
    )
    console.print(
        f"  [cyan]-[/cyan] Tor Network:     {'[bold green]Yes (IsTor=True)[/]' if is_tor else '[bold red]No[/]'}"
    )
    wd_active = lock.get("watchdog_active", False) if lock else False
    console.print(
        f"  [cyan]-[/cyan] Watchdog:        {'[bold green]Active[/]' if wd_active else '[bold red]Inactive[/]'}"
    )
    console.print(f"  [cyan]-[/cyan] API Latency:     {latency} ms")
    console.print(
        f"  [cyan]-[/cyan] Circuit Stable:  {'[bold green]Yes (Controller connected)[/]' if circuit_stable else '[bold red]No (ControlPort/Socket unreachable)[/]'}"
    )


def _parse_txt_dig_ipv4(dig_stdout: str) -> Optional[str]:
    """Return the first plausible IPv4 from ``dig +short TXT`` output (quotes stripped)."""
    for raw_line in dig_stdout.strip().splitlines():
        line = raw_line.strip().strip('"').strip("'").strip()
        if not line:
            continue
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
            return line
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        if m:
            return m.group(1)
    return None


@app.command(name="check-leak")
def check_leak() -> None:
    """Check for network leaks using Tor Project API and optional DNS probes."""
    import json
    import shutil
    import subprocess
    import urllib.error
    import urllib.request

    lock = state.read_lock()
    if lock is None:
        console.print(f"{_PREFIX} Cannot check for leaks: TTP is INACTIVE.")
        raise typer.Exit(code=1)

    has_leaks = False
    console.print(f"{_PREFIX} Running leak tests...")

    # 1. Authoritative Tor exit check (stdlib only - no curl).
    try:
        req = urllib.request.Request(
            "https://check.torproject.org/api/ip",
            headers={"User-Agent": "ttp"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        if not data.get("IsTor", False):
            has_leaks = True
            if cli_state.verbose:
                logger.debug(
                    "check.torproject.org reports IsTor=False (payload keys: %s)",
                    list(data.keys()),
                )
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        has_leaks = True
        if cli_state.verbose:
            logger.debug("Tor API check failed: %s", e, exc_info=True)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        has_leaks = True
        if cli_state.verbose:
            logger.debug("Tor API returned invalid JSON: %s", e, exc_info=True)

    dig_bin = shutil.which("dig")
    if not dig_bin:
        has_leaks = True
        if cli_state.verbose:
            logger.debug("dig not found in PATH; cannot verify DNS path.")
    else:
        # 2. Basic DNS resolution through the tunnel (must resolve check.torproject.org).
        cmd_a = [dig_bin, "+short", "A", "check.torproject.org"]
        try:
            res_a = subprocess.run(
                cmd_a, capture_output=True, text=True, timeout=10, check=False
            )
            out_a = res_a.stdout.strip()
            if cli_state.verbose:
                console.print(f"[dim]> {' '.join(cmd_a)}\n{out_a}[/dim]")
            if not out_a:
                has_leaks = True
                if cli_state.verbose:
                    logger.debug(
                        "Empty dig A output for check.torproject.org (returncode=%s).",
                        res_a.returncode,
                    )
        except Exception as e:
            has_leaks = True
            if cli_state.verbose:
                logger.debug("dig A check.torproject.org failed: %s", e, exc_info=True)

        # 3. Akamai TXT: resolver identity (exit-side resolver) - presence of an IP is NOT a leak.
        cmd_txt = [dig_bin, "+short", "TXT", "whoami.ipv4.akahelp.net"]
        try:
            res_txt = subprocess.run(
                cmd_txt, capture_output=True, text=True, timeout=10, check=False
            )
            out_txt = res_txt.stdout.strip()
            if cli_state.verbose:
                console.print(f"[dim]> {' '.join(cmd_txt)}\n{out_txt}[/dim]")
            resolver_ip = _parse_txt_dig_ipv4(out_txt) if out_txt else None
            if cli_state.verbose and resolver_ip:
                console.print(
                    f"{_PREFIX} [dim]Akamai resolver probe (informational): {resolver_ip}[/dim]"
                )
        except Exception as e:
            has_leaks = True
            if cli_state.verbose:
                logger.debug(
                    "dig TXT whoami.ipv4.akahelp.net failed: %s", e, exc_info=True
                )

    if has_leaks:
        console.print(
            f"{_PREFIX} [bold red]Leaks detected![/bold red] Use -v for details."
        )
        raise typer.Exit(code=1)

    console.print(f"{_PREFIX} [bold green]No leaks detected.[/bold green]")


@app.command()
def diagnose() -> None:
    """Run a system diagnostic and print a report for troubleshooting."""
    _require_root()
    from ttp.system_info import collect_diagnostics
    from rich.text import Text

    console.print(f"{_PREFIX} Running system diagnostics...\n")

    data = collect_diagnostics()

    console.print(
        Panel(Text(data["os"]), title="[bold cyan]1. System[/]", border_style="cyan")
    )

    console.print(
        Panel(
            Text(data["tor_service"]),
            title="[bold blue]2. Tor Service (ttp-tor)[/]",
            border_style="blue",
        )
    )

    console.print(
        Panel(
            Text(data["torrc"]),
            title="[bold blue]3. Active Tor Config (/run/tor/ttp/torrc)[/]",
            border_style="blue",
        )
    )

    console.print(
        Panel(
            Text(data["nftables"]),
            title="[bold magenta]4. nftables Ruleset[/]",
            border_style="magenta",
        )
    )

    console.print(
        Panel(
            Text(data["dns"]),
            title="[bold magenta]5. DNS Configuration[/]",
            border_style="magenta",
        )
    )

    console.print(
        Panel(
            Text(data["control_interface"]),
            title="[bold green]6. Tor Control Interface[/]",
            border_style="green",
        )
    )

    console.print(
        Panel(
            Text(data["ttp_state"]),
            title="[bold yellow]7. TTP Internal State[/]",
            border_style="yellow",
        )
    )

    console.print(f"{_PREFIX} Diagnostic complete.")


@app.command()
def uninstall() -> None:
    """Fully remove TTP and clean up system state (including SELinux)."""
    _require_root()

    # 1. Stop any active session first.
    if state.read_lock():
        console.print(f"{_PREFIX} Active session detected. Stopping...")
        _do_stop()

    # 2. Remove the SELinux module if it was installed.
    from ttp.tor_detect import is_selinux_module_installed

    if is_selinux_module_installed():
        console.print(f"{_PREFIX} Purging SELinux policy module...")
        tor_install.remove_selinux_module()

    # (Log file and runtime state are in tmpfs /run/ttp and evaporate on reboot/stop)

    # 3. Clean up the star notification sentinel.
    state.delete_star_sentinel()

    console.print(f"{_PREFIX} [bold green]Uninstallation complete.[/]")
    console.print(
        f"{_PREFIX} Note: To remove application files, run the provided 'scripts/uninstall.sh'."
    )


@app.command(name="logs")
def logs() -> None:
    """View recent TTP logs from the volatile log file."""
    if not _LOG_PATH.exists():
        console.print(f"{_PREFIX} No log file found at {_LOG_PATH}.")
        raise typer.Exit(code=1)

    console.print(f"{_PREFIX} Displaying logs from [bold]{_LOG_PATH}[/bold]...")
    console.print(_LOG_PATH.read_text(encoding="utf-8"))


watchdog_app = typer.Typer(
    name="watchdog",
    help="Manage the TTP background session watchdog.",
    add_completion=False,
)
app.add_typer(watchdog_app)


@watchdog_app.command(name="start")
def watchdog_start() -> None:
    """Start the background session watchdog manually."""
    _require_root()
    if state.read_lock() is None:
        _print_error("Session Error", "No active TTP session found. Start TTP first.")
        raise typer.Exit(code=1)
    from ttp import watchdog as wd

    wd.start_watchdog()
    console.print(f"{_PREFIX} Watchdog daemon started successfully.")


@watchdog_app.command(name="stop")
def watchdog_stop() -> None:
    """Stop the background session watchdog manually."""
    _require_root()
    from ttp import watchdog as wd

    wd.stop_watchdog()
    console.print(f"{_PREFIX} Watchdog daemon stopped successfully.")


@watchdog_app.command(name="status")
def watchdog_status() -> None:
    """Show the background session watchdog status."""
    lock = state.read_lock()
    if lock is None:
        console.print(f"{_PREFIX} Status: [bold red]INACTIVE[/] (TTP is not running)")
        raise typer.Exit(code=0)

    active = lock.get("watchdog_active", False)
    pid = lock.get("watchdog_pid")

    if active:
        console.print(f"{_PREFIX} Watchdog Status: [bold green]ACTIVE[/]")
        console.print(f"{_PREFIX} Watchdog PID: {pid or 'unknown'}")
    else:
        console.print(f"{_PREFIX} Watchdog Status: [bold red]INACTIVE[/]")


@watchdog_app.command(name="run", hidden=True)
def watchdog_run(
    interval: int = typer.Option(15, "--interval", help="Check interval in seconds."),
) -> None:
    """Internal entrypoint for running the watchdog daemon loop."""
    _require_root()
    from ttp import watchdog as wd

    try:
        wd.run_watchdog_loop(interval_seconds=interval)
    except Exception as e:
        logger.critical("Watchdog loop crashed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    app()
