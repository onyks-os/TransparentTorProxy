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
from ttp.evidence import Diagnostic, ExitCode
from ttp.session_safety import request_emergency, supervision_terminated

watchdog_app = typer.Typer(
    name="watchdog",
    help="Manage the TTP background session watchdog.",
    add_completion=False,
)


@watchdog_app.command(name="start")
def watchdog_start() -> None:
    """Start the background session watchdog manually."""
    _require_root()
    lock = state.read_lock(strict=True)
    if lock is None:
        _print_error("Session Error", "No active TTP session found. Start TTP first.")
        raise typer.Exit(code=1)
    import uuid

    from ttp.commands._preflight import require_watchdog_dependency
    from ttp.runtime_records import session_store
    from ttp.settings import Settings, SettingsError, load_settings

    try:
        settings = Settings.from_snapshot(lock["settings"]) if lock.get("settings") else load_settings().settings
        selected = settings.select(watchdog=True)
        session_id = lock.get("session_id") or str(uuid.uuid4())
        session_store().prepare()
        state.update_lock_keys(session_id=session_id, settings=selected.snapshot(), watchdog_requested=True)
    except (SettingsError, OSError) as exc:
        _print_error("Watchdog Configuration Error", str(exc))
        raise typer.Exit(code=5)
    try:
        require_watchdog_dependency()
        from ttp import watchdog as wd

        wd.start_watchdog()
    except Exception as exc:
        lock = state.read_lock(strict=True) or {}
        result = request_emergency(
            lock,
            Diagnostic(
                ExitCode.WATCHDOG_UNAVAILABLE,
                "watchdog.start_failed",
                "watchdog",
                "start",
                "Requested supervisor could not start",
            ),
        )
        _print_error("Required Watchdog Unavailable", str(exc))
        raise typer.Exit(code=int(result.exit_code))
    console.print(f"{_PREFIX} Watchdog daemon started successfully.")


@watchdog_app.command(name="stop")
def watchdog_stop() -> None:
    """Stop the background session watchdog manually."""
    _require_root()
    lock = state.read_lock(strict=True)
    if lock and lock.get("watchdog_requested") and lock.get("phase") != "stopping":
        _print_error(
            "Supervision Required", "This session requires its watchdog. Use 'sudo ttp stop' to terminate the session."
        )
        raise typer.Exit(code=int(ExitCode.WATCHDOG_UNAVAILABLE))
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
def watchdog_run() -> None:
    """Internal entrypoint for running the watchdog daemon loop.

    Invoked by systemd via the generated ttp-watchdog.service unit, which
    drops to the ttp-watchdog account when that account exists. Requiring
    euid 0 here contradicted the unit's own privilege separation and left the
    daemon unable to start at all.
    """
    _require_root_or_watchdog_user()
    from ttp.watchdog.supervisor import run_supervisor

    try:
        run_supervisor()
    except Exception as e:
        logger.critical("Watchdog loop crashed: %s", e)
        raise typer.Exit(code=1)


@watchdog_app.command(name="terminated", hidden=True)
def watchdog_terminated(session: str | None = typer.Option(None, "--session")) -> None:
    """Independent systemd termination hook; never called by the dying loop."""
    _require_root_or_watchdog_user()
    result = supervision_terminated(session)
    raise typer.Exit(code=int(result.exit_code))
