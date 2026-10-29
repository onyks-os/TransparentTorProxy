from __future__ import annotations

import subprocess

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from ttp import state
from ttp.commands._common import (
    _PREFIX,
    console,
)
from ttp.commands._common import (
    parse_txt_dig_ipv4 as _parse_txt_dig_ipv4,
)
from ttp.commands._common import (
    print_error as _print_error,
)
from ttp.commands._common import (
    require_root as _require_root,
)
from ttp.exceptions import TorError
from ttp.paths import resolve_optional


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
        console.print(f"{_PREFIX} [yellow]Circuit rotated but IP may not have changed yet. Current IP: {new_ip}[/]")


def status_command(json_output: bool = typer.Option(False, "--json", help="Print structured observations.")) -> None:
    """Observe the recorded session without changing it or probing the internet."""
    import json

    from ttp.exceptions import StateError
    from ttp.session_report import observe_session
    from ttp.settings import SettingsError

    try:
        report = observe_session()
    except (StateError, SettingsError) as exc:
        _print_error("Observation Failed", str(exc))
        raise typer.Exit(code=1)
    if json_output:
        typer.echo(json.dumps(report, indent=2))
        return
    if report["phase"] == "absent":
        console.print(f"{_PREFIX} Status: INACTIVE (no recorded TTP session)")
        return
    console.print(f"{_PREFIX} Session: {report['phase']}; health: {report['health']}")
    console.print(f"{_PREFIX} TransPort: {report['transport_port']}; DNSPort: {report['dns_port']}")
    console.print(f"{_PREFIX} LAN Bypass configured: {report['lan_bypass']}; Allow Root: {report['allow_root']}")
    console.print(f"{_PREFIX} IPv6 configuration: {report['ipv6']}")
    if report["rejected_packets"] is not None:
        console.print(f"{_PREFIX} Packets rejected by TTP: {report['rejected_packets']}")
    console.print(
        f"{_PREFIX} Watchdog requested: {report['watchdog_requested']}; observation: {report['watchdog']['value']}"
    )
    verification = report["verification"]
    console.print(f"{_PREFIX} Tor verification: {verification['state']} (recorded measurement)")
    if "age_seconds" in verification:
        console.print(
            f"{_PREFIX} Measurement age: {verification['age_seconds']:.1f} seconds; IP: {verification.get('ip') or 'unknown'}"
        )
    emergency = report["emergency"]
    console.print(
        f"{_PREFIX} Killswitch requested: {emergency['requested']}; application: {emergency['applied']}; verified now: {emergency['verified']}"
    )
    console.print(f"{_PREFIX} Session started: {report['started']}")
    console.print(
        f"{_PREFIX} Notifications: {report['notifications']['state']} (acceptance is not proof of display or reading)"
    )
    for diagnostic in report["diagnostics"]:
        console.print(f"{_PREFIX} {diagnostic['reason']}: {diagnostic['message']}", markup=False)
    # Successful status collection is distinct from the health it describes.


def check_command() -> None:
    """Explicit bounded Tor verification, with independent degraded-state causes."""
    from ttp.exceptions import StateError
    from ttp.session_report import check_session
    from ttp.session_safety import STOP_ADVICE
    from ttp.settings import SettingsError

    _require_root()
    console.print(f"{_PREFIX} Checking Tor network connection...")
    try:
        verification, result = check_session()
    except (StateError, SettingsError) as exc:
        _print_error("Check Failed", str(exc))
        raise typer.Exit(code=1)
    console.print(f"{_PREFIX} Tor verification: {verification.state.value}; reason: {verification.reason}")
    lock = state.read_lock()
    if lock:
        from ttp.tor_detect import is_ipv6_supported

        console.print(f"{_PREFIX} TransPort: {lock.get('transport_port', 9041)}; DNSPort: {lock.get('dns_port', 9054)}")
        ipv6 = (
            "Disabled (Force Dropped)"
            if lock.get("no_ipv6")
            else ("Enabled (Redirect configured)" if is_ipv6_supported() else "Not supported by host")
        )
        console.print(f"{_PREFIX} IPv6 configuration: {ipv6}")
    if verification.confirmed:
        console.print(f"{_PREFIX} Tor Network: Yes (IsTor=True at this observation)")
    if verification.ip:
        console.print(f"{_PREFIX} Observed IP: {verification.ip}")
    for diagnostic in result.diagnostics:
        if diagnostic.active:
            _print_error(diagnostic.reason, diagnostic.message)
    if int(result.exit_code) in (7, 8):
        _print_error("Emergency", STOP_ADVICE)
    if result.exit_code:
        raise typer.Exit(code=int(result.exit_code))


def check_leak_command() -> None:
    """Check for network leaks using Tor Project API and optional DNS probes."""
    lock = state.read_lock()
    if lock is None:
        console.print(f"{_PREFIX} Cannot check for leaks: TTP is INACTIVE.")
        raise typer.Exit(code=1)

    # A failed probe is inconclusive, never proof of a leak. The shared check
    # also applies the required containment policy for a valid negative result.
    check_command()
    console.print(f"{_PREFIX} Tor confirmed for this request; this is not proof that every application is leak-free.")
    dig_bin = resolve_optional("dig")
    if not dig_bin:
        console.print(f"{_PREFIX} Optional DNS observation unavailable: dig not found.")
        return
    for query_type, name in (("A", "check.torproject.org"), ("TXT", "whoami.ipv4.akahelp.net")):
        try:
            response = subprocess.run(
                [dig_bin, "+short", query_type, name], capture_output=True, text=True, timeout=10, check=False
            )
            if response.returncode or not response.stdout.strip():
                console.print(f"{_PREFIX} DNS {query_type} observation inconclusive (exit {response.returncode}).")
            elif query_type == "TXT":
                resolver = _parse_txt_dig_ipv4(response.stdout)
                console.print(f"{_PREFIX} Resolver observation (informational): {resolver or 'unknown'}")
            else:
                console.print(f"{_PREFIX} DNS A response received; it does not prove the DNS traffic path.")
        except (OSError, subprocess.SubprocessError) as exc:
            console.print(f"{_PREFIX} DNS {query_type} observation unavailable ({type(exc).__name__}).")
