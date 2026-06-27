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


import typer

from ttp.commands._common import (
    cli_state,
    console,
    get_uid_from_port,
    is_port_in_use,
    is_port_listening_tcp,
    is_port_listening_udp,
    parse_txt_dig_ipv4,
    print_error,
    require_root,
    setup_logging,
    validate_bridge_line,
    verify_tor,
)
from ttp.commands.lifecycle import do_stop, signal_handler
from ttp.commands.admin import (
    bypass_command,
    diagnose_command,
    logs_command,
    uninstall_command,
)
from ttp.commands.session import (
    check_command,
    check_leak_command,
    refresh_command,
    status_command,
)
from ttp.commands.start import start_command
from ttp.commands.stop_restart import restart_command, stop_command
from ttp.commands.watchdog import watchdog_app

# Backward-compatible aliases for tests and external callers
_setup_logging = setup_logging
_print_error = print_error
_require_root = require_root
_validate_bridge_line = validate_bridge_line
_get_uid_from_port = get_uid_from_port
_is_port_in_use = is_port_in_use
_is_port_listening_tcp = is_port_listening_tcp
_is_port_listening_udp = is_port_listening_udp
_verify_tor = verify_tor
_do_stop = do_stop
_signal_handler = signal_handler
_parse_txt_dig_ipv4 = parse_txt_dig_ipv4

app = typer.Typer(
    name="ttp",
    help="TTP - Transparent Tor Proxy. Route all traffic through Tor.\n\nTo view specific options for a command, run: ttp <command> --help (e.g., ttp start --help)",
    add_completion=False,
)


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


# Commands


app.command("start")(start_command)
app.command("stop")(stop_command)
app.command("restart")(restart_command)


app.command("refresh")(refresh_command)
app.command("status")(status_command)
app.command("check")(check_command)
app.command("check-leak")(check_leak_command)


app.command("diagnose")(diagnose_command)
app.command("uninstall")(uninstall_command)
app.command("logs")(logs_command)
app.command("bypass")(bypass_command)

app.add_typer(watchdog_app)


if __name__ == "__main__":
    app()
