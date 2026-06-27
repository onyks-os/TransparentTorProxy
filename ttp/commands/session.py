from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from ttp import state
from ttp.commands._common import (
    _PREFIX,
    cli_state,
    console,
    logger,
    parse_txt_dig_ipv4 as _parse_txt_dig_ipv4,
    print_error as _print_error,
    require_root as _require_root,
)
from ttp.exceptions import TorError


def refresh_command() -> None:
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


def status_command() -> None:
    """Show current TTP session status."""
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
    from ttp.tor_detect import is_ipv6_supported

    ipv6_supported = is_ipv6_supported()
    if lock.get("no_ipv6", False):
        ipv6_status = "[red]Disabled (Force Dropped)[/]"
    elif ipv6_supported:
        ipv6_status = "[green]Enabled (Redirected)[/]"
    else:
        ipv6_status = "[yellow]Disabled (Not supported by host)[/]"
    console.print(f"{_PREFIX} IPv6 Traffic: {ipv6_status}")

    wd_active = lock.get("watchdog_active", False)
    wd_pid = lock.get("watchdog_pid")
    wd_status_str = (
        f"[green]Active (PID {wd_pid})[/]" if wd_active else "[red]Inactive[/]"
    )
    console.print(f"{_PREFIX} Watchdog: {wd_status_str}")

    console.print(f"{_PREFIX} Exit IP: {exit_ip}")
    console.print(f"{_PREFIX} Session started: {lock.get('timestamp', 'unknown')}")
    console.print(f"{_PREFIX} Process PID: {lock.get('pid', 'unknown')}")


def check_command() -> None:
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
    from ttp.tor_detect import is_ipv6_supported

    ipv6_supported = is_ipv6_supported()
    if lock and lock.get("no_ipv6", False):
        ipv6_status = "[bold red]Disabled (Force Dropped)[/]"
    elif ipv6_supported:
        ipv6_status = "[bold green]Enabled (Redirected)[/]"
    else:
        ipv6_status = "[bold yellow]Disabled (Not supported)[/]"
    console.print(f"  [cyan]-[/cyan] IPv6 Traffic:    {ipv6_status}")
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


def check_leak_command() -> None:
    """Check for network leaks using Tor Project API and optional DNS probes."""
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
