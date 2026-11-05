# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Interactive, passive view of the session evidence already used by status."""

from __future__ import annotations

import signal
import sys
import time
from datetime import datetime

import typer
from rich.live import Live

from ttp.commands._common import cli_state, console, print_error, require_root
from ttp.evidence import boottime
from ttp.monitor import MonitorView, render_monitor
from ttp.session_report import observe_session


class _MonitorExit(Exception):
    """Leave the view on SIGTERM without touching the active TTP session."""


def _terminal_available() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def monitor_command(
    interval: float = typer.Option(
        5.0, "--interval", min=2.0, max=60.0, help="Seconds between observations (2 to 60)."
    ),
) -> None:
    """Watch local session evidence and changes seen while this view is open."""
    require_root()
    if cli_state.quiet:
        print_error("Monitor Unavailable", "The interactive monitor cannot run with --quiet.")
        raise typer.Exit(code=2)
    if not _terminal_available():
        print_error("Monitor Unavailable", "A terminal is required. Use 'ttp status --json' for scripts.")
        raise typer.Exit(code=2)

    view = MonitorView()
    previous_term_handler = signal.getsignal(signal.SIGTERM)

    def leave_on_term(_signum: int, _frame: object) -> None:
        raise _MonitorExit

    signal.signal(signal.SIGTERM, leave_on_term)
    try:
        with Live(render_monitor(view), console=console, screen=True, auto_refresh=False) as live:
            while True:
                try:
                    report = observe_session()
                    sampled_at = datetime.now().astimezone()
                    view.accept(report, sampled_at, boot_now=boottime())
                except _MonitorExit:
                    raise
                except Exception as exc:
                    view.unavailable(datetime.now().astimezone(), f"{type(exc).__name__}: {exc}")
                live.update(render_monitor(view), refresh=True)
                time.sleep(interval)
    except (KeyboardInterrupt, _MonitorExit):
        pass
    finally:
        signal.signal(signal.SIGTERM, previous_term_handler)
