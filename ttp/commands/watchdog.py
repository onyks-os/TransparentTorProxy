from __future__ import annotations

import typer

from ttp import state
from ttp.commands._common import (
    _PREFIX,
    console,
    logger,
)
from ttp.commands._common import (
    print_error as _print_error,
)
from ttp.commands._common import (
    require_root as _require_root,
)
from ttp.commands._common import (
    require_root_or_watchdog_user as _require_root_or_watchdog_user,
)

watchdog_app = typer.Typer(
    name="watchdog",
    help="Manage the TTP background session watchdog.",
    add_completion=False,
)


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

    # Re-probe rather than trusting the lock: the daemon may have exited on
    # the killswitch path, been OOM-killed, or been stopped directly.
    from ttp.watchdog.service import watchdog_liveness

    active, pid = watchdog_liveness()

    if active:
        console.print(f"{_PREFIX} Watchdog Status: [bold green]ACTIVE[/]")
        console.print(f"{_PREFIX} Watchdog PID: {pid or 'unknown'}")
    else:
        console.print(f"{_PREFIX} Watchdog Status: [bold red]INACTIVE[/]")


@watchdog_app.command(name="run", hidden=True)
def watchdog_run(
    interval: int = typer.Option(15, "--interval", help="Check interval in seconds."),
) -> None:
    """Internal entrypoint for running the watchdog daemon loop.

    Invoked by systemd via the generated ttp-watchdog.service unit, which
    drops to the ttp-watchdog account when that account exists. Requiring
    euid 0 here contradicted the unit's own privilege separation and left the
    daemon unable to start at all.
    """
    _require_root_or_watchdog_user()
    from ttp import watchdog as wd

    try:
        wd.run_watchdog_loop(interval_seconds=interval)
    except Exception as e:
        logger.critical("Watchdog loop crashed: %s", e)
        raise typer.Exit(code=1)
