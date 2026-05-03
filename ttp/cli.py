#!/usr/bin/env python3
"""CLI entry point — Typer application for TTP.

This module acts as the primary orchestrator for the entire application.
It defines the command-line interface and coordinates the interaction
between specialized modules (firewall, dns, tor_install, etc.).

ARCHITECTURE NOTE:
- This file should remain a "pure orchestrator."
- It handles UI (Rich/Typer) and high-level logic flow.
- It should NOT contain low-level system interaction code (that goes into modules).

Exposes five commands: ``start``, ``stop``, ``refresh``, ``status``, ``uninstall``.
All commands require root privileges. Signal handlers guarantee that the
network state is restored even on SIGINT/SIGTERM.
"""

from __future__ import annotations

import logging
import os
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
    help="TTP — Transparent Tor Proxy. Route all traffic through Tor.",
    add_completion=False,
)
console = Console()

_PREFIX = "[bold cyan]\\[TTP][/bold cyan]"
err_console = Console(stderr=True)


class CLIState:
    verbose: bool = False
    quiet: bool = False


cli_state = CLIState()


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug output."),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress all output except errors."
    ),
):
    cli_state.verbose = verbose
    cli_state.quiet = quiet
    if quiet:
        console.quiet = True
    _setup_logging()


def _print_error(title: str, msg: str) -> None:
    """Print a styled error message using a Rich Panel."""
    err_console.print(
        Panel(msg, title=f"[bold red]{title}[/bold red]", border_style="red")
    )


_LOG_PATH = Path("/var/log/ttp.log")
logger = logging.getLogger("ttp")


def _setup_logging() -> None:
    """Configure logging based on the CLI state."""
    try:
        handler = logging.FileHandler(_LOG_PATH)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if cli_state.verbose else logging.INFO)
    except OSError:
        # Non-fatal — logging is best-effort.
        pass

    if cli_state.verbose and not cli_state.quiet:
        from rich.logging import RichHandler

        rich_handler = RichHandler(console=console, show_path=False)
        rich_handler.setLevel(logging.DEBUG)
        logger.addHandler(rich_handler)
        logger.setLevel(logging.DEBUG)


# ── Helpers ────────────────────────────────────────────────────────


def _require_root() -> None:
    """Exit with an error if the process is not running as root."""
    if os.geteuid() != 0:
        _print_error(
            "Permission Denied", "This command must be run as root (use sudo)."
        )
        raise typer.Exit(code=1)


def _verify_tor() -> tuple[bool, str]:
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
                progress_callback=lambda val: progress.update(task_id, completed=val)
            )
            progress.stop()
            console.print(f"{_PREFIX} Tor is 100% bootstrapped.")
        except RuntimeError as e:
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
    """Internal stop logic — shared by ``stop`` command and signal handler."""
    lock = state.read_lock()
    if lock is None:
        return

    console.print(f"{_PREFIX} Removing nftables rules...")
    firewall.destroy_rules()

    console.print(f"{_PREFIX} Restoring DNS...")
    dns.restore_dns(lock.get("dns_mode", ""), lock.get("dns_backup"))

    state.delete_lock()
    console.print(
        f"{_PREFIX} [bold red]🔴 Session terminated. Traffic in cleartext.[/]"
    )


def _signal_handler(signum: int, frame) -> None:
    """Handle SIGINT/SIGTERM — clean up and exit."""
    console.print(f"\n{_PREFIX} Signal received, restoring network...")
    _do_stop()
    sys.exit(0)


# ── Commands ───────────────────────────────────────────────────────


@app.command()
def start(
    interface: Optional[str] = typer.Option(
        None,
        "--interface",
        "-i",
        help="Network interface to configure DNS on (auto-detected if omitted).",
    ),
) -> None:
    """Start the transparent Tor proxy session."""
    _require_root()

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

    # Step 0 — SELinux optimization (for Fedora/RHEL).
    # This ensures the kernel policy allows Tor to bind to our ports.
    # It only runs once and has zero overhead on subsequent calls.
    tor_install.setup_selinux_if_needed()

    # Step 1 — Detect / install Tor.
    console.print(f"{_PREFIX} Detecting Tor...", end=" ")
    try:
        info = tor_install.ensure_tor_ready()
    except TorError as exc:
        logger.error("Tor detection/install failed: %s", exc)
        console.print("[bold red]failed.[/]")
        _print_error("Tor Startup Failed", str(exc))
        raise typer.Exit(code=1)

    version = info.get("version", "")
    tor_user = info.get("tor_user", "debian-tor")
    console.print(
        f"found (v{version}), service active (user: {tor_user})."
        if version
        else f"found, service active (user: {tor_user})."
    )

    # Step 2 — Apply stateless firewall rules.
    try:
        firewall.apply_rules(tor_user=tor_user)
    except FirewallError as exc:
        _print_error("Firewall Setup Failed", str(exc))
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    console.print(f"{_PREFIX} Stateless nftables rules applied (Table: inet ttp).")

    # Step 3 — Modify DNS.
    dns_mode = dns.detect_dns_mode()
    if interface is None:
        interface = dns.detect_active_interface()
    try:
        dns_backup = dns.apply_dns(dns_mode, interface)
    except DNSError as exc:
        logger.error("DNS setup failed: %s", exc)
        _print_error("DNS Setup Failed", str(exc))
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    except Exception as exc:
        logger.error("Unexpected DNS error: %s", exc)
        _print_error(
            "DNS Setup Failed", "An unexpected error occurred during DNS configuration."
        )
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    logger.info("Session started — mode=%s, interface=%s", dns_mode, interface)
    console.print(f"{_PREFIX} DNS set via {dns_mode} on interface {interface}.")

    # Step 4 — Write lock file.
    try:
        state.write_lock(
            dns_backup=dns_backup,
            dns_mode=dns_mode,
        )
    except StateError as exc:
        logger.error("Failed to write lock: %s", exc)
        _print_error("Session Tracking Failed", str(exc))
        # Emergency cleanup since we can't track this session
        firewall.destroy_rules()
        dns.restore_dns(dns_mode, dns_backup)
        raise typer.Exit(code=1)

    # Step 5 — Verify Tor is working.
    is_tor, exit_ip = _verify_tor()
    if is_tor:
        console.print(f"{_PREFIX} [bold green]✅ Session active. Exit IP: {exit_ip}[/]")
    else:
        console.print(
            f"{_PREFIX} [bold yellow]⚠ Session active but Tor verification failed.[/]"
        )
        console.print(
            f"{_PREFIX} [yellow]Traffic may NOT be routed through Tor. "
            f"Check Tor service and try 'ttp stop' then 'ttp start'.[/]"
        )
        if exit_ip != "unknown":
            console.print(f"{_PREFIX} [yellow]Detected IP: {exit_ip}[/]")
    console.print(f"{_PREFIX} Use 'ttp stop' to terminate. 'ttp refresh' to change IP.")

    # One-time discrete message to encourage GitHub stars.
    if state.should_show_star_message():
        console.print(
            "\n[dim]Thanks for using TTP! Starring the repo on GitHub helps the project grow.[/]"
        )
        state.mark_star_message_shown()


@app.command()
def stop() -> None:
    """Stop the transparent Tor proxy and restore the network."""
    _require_root()

    if state.read_lock() is None:
        console.print(f"{_PREFIX} No active session found.")
        raise typer.Exit(code=0)

    _do_stop()


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
    lock = state.read_lock()
    if lock is None:
        console.print(f"{_PREFIX} Status: [bold red]INACTIVE[/]")
        console.print(f"{_PREFIX} No active session. Traffic is in cleartext.")
        raise typer.Exit(code=0)

    from ttp import tor_control

    exit_ip = tor_control.get_exit_ip()
    console.print(f"{_PREFIX} Status: [bold green]ACTIVE[/]")
    console.print(f"{_PREFIX} Exit IP: {exit_ip}")
    console.print(f"{_PREFIX} Session started: {lock.get('timestamp', 'unknown')}")
    console.print(f"{_PREFIX} Process PID: {lock.get('pid', 'unknown')}")


@app.command()
def diagnose() -> None:
    """Run a system diagnostic and print a report for troubleshooting."""
    _require_root()
    from ttp.system_info import collect_diagnostics
    from ttp.tor_detect import _get_service_name

    console.print(f"{_PREFIX} Running system diagnostics...\n")

    data = collect_diagnostics()
    service = _get_service_name()

    console.print(
        Panel(data["os"], title="[bold cyan]1. System[/]", border_style="cyan")
    )

    console.print(
        Panel(
            data["tor_service"],
            title=f"[bold blue]2. Tor Service ({service})[/]",
            border_style="blue",
        )
    )

    console.print(
        Panel(
            data["torrc"],
            title="[bold blue]3. Active Tor Config (/etc/tor/torrc)[/]",
            border_style="blue",
        )
    )

    console.print(
        Panel(
            data["nftables"],
            title="[bold magenta]4. nftables Ruleset[/]",
            border_style="magenta",
        )
    )

    console.print(
        Panel(
            data["dns"],
            title="[bold magenta]5. DNS Configuration[/]",
            border_style="magenta",
        )
    )

    console.print(
        Panel(
            data["control_interface"],
            title="[bold green]6. Tor Control Interface[/]",
            border_style="green",
        )
    )

    console.print(
        Panel(
            data["ttp_state"],
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

    # 3. Clean up the log file.
    if _LOG_PATH.exists():
        try:
            _LOG_PATH.unlink()
            console.print(f"{_PREFIX} Removed log file.")
        except OSError:
            pass

    # 4. Clean up the star notification sentinel.
    state.delete_star_sentinel()

    console.print(f"{_PREFIX} [bold green]Uninstallation complete.[/]")
    console.print(
        f"{_PREFIX} Note: To remove application files, run the provided 'scripts/uninstall.sh'."
    )


if __name__ == "__main__":
    app()
