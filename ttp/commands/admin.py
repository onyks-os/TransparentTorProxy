from __future__ import annotations

import os
import shutil
import subprocess

import typer
from rich.panel import Panel
from rich.text import Text

from ttp import state, tor_install
from ttp.commands._common import (
    _LOG_PATH,
    _PREFIX,
    console,
    print_error as _print_error,
    require_root as _require_root,
    require_systemd,
)
from ttp.commands.lifecycle import do_stop as _do_stop


def diagnose_command() -> None:
    """Run a system diagnostic and print a report for troubleshooting."""
    _require_root()
    from ttp.system_info import collect_diagnostics

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


def uninstall_command() -> None:
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


def logs_command() -> None:
    """View recent TTP logs from the volatile log file."""
    if not _LOG_PATH.exists():
        console.print(f"{_PREFIX} No log file found at {_LOG_PATH}.")
        raise typer.Exit(code=1)

    console.print(f"{_PREFIX} Displaying logs from [bold]{_LOG_PATH}[/bold]...")
    console.print(_LOG_PATH.read_text(encoding="utf-8"))


def bypass_command(
    command: list[str] = typer.Argument(
        ...,
        help="The command and arguments to execute with Tor bypass.",
    ),
) -> None:
    """Execute a command bypassing the Tor transparent proxy.

    This command runs the target process and its children inside a systemd transient scope
    configured under 'ttp-bypass.slice', de-escalating privileges to the invoking user.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    if os.geteuid() != 0 or not sudo_uid or not sudo_gid:
        _print_error(
            "Invalid Execution Context",
            "This command must be run with sudo to safely delegate privileges via systemd-run.",
        )
        raise typer.Exit(code=1)

    require_systemd()

    lock = state.read_lock()
    if lock is None:
        _print_error(
            "No Active Session",
            "TTP transparent proxy is not active. Bypass is not required.",
        )
        raise typer.Exit(code=1)

    # Resolve systemd-run path
    systemd_run_bin = shutil.which("systemd-run")
    if not systemd_run_bin:
        _print_error(
            "systemd-run Missing",
            "The 'systemd-run' command is required for transient scope execution but was not found.",
        )
        raise typer.Exit(code=1)

    # Construct the systemd-run command
    run_cmd = [
        systemd_run_bin,
        f"--uid={sudo_uid}",
        f"--gid={sudo_gid}",
        "--slice=ttp-bypass",
        "--scope",
        "--",
    ] + command

    try:
        # Run systemd-run, passing through stdin, stdout, and stderr
        res = subprocess.run(run_cmd, check=False)
        return_code = res.returncode
    except Exception as e:
        _print_error("Execution Failure", f"Failed to execute bypass command: {e}")
        raise typer.Exit(code=1)

    raise typer.Exit(code=return_code)
