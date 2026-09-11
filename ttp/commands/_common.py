# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Shared CLI state, console singletons, and backward-compatible re-exports.

This module owns the **global singletons** that must be shared across all CLI
submodules:

- ``cli_state`` — mutable runtime flags (verbose, quiet, log format, bypass lists)
- ``console`` / ``err_console`` — Rich ``Console`` instances
- ``logger`` — the root ``ttp`` Python logger
- ``_PREFIX`` / ``_LOG_PATH`` — shared constants

All other utilities (logging setup, port probing, validation) have been
extracted to dedicated submodules and are **re-exported here** so that
existing ``from ttp.commands._common import ...`` call-sites continue to
work without modification.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()
err_console = Console(stderr=True)
_PREFIX = "[bold cyan]\\[TTP][/bold cyan]"
_LOG_PATH = Path("/run/ttp/ttp.log")
logger = logging.getLogger("ttp")

# Exit code for "the session was established, but Tor could not be verified".
#
# It has to be distinguishable from both neighbours: 0 means traffic is
# confirmed to be flowing through Tor, 1 means start gave up and left the host
# in cleartext. Neither describes a session that is up and holding everything
# fail-closed while Tor is unreachable - and a caller scripting `ttp start` has
# to tell those three apart. 3 rather than 2 because Click already spends 2 on
# usage errors, and a script must not confuse a mistyped flag with a blocked
# network.
EXIT_UNVERIFIED = 3


class CLIState:
    verbose: bool = False
    quiet: bool = False
    log_format: str = "text"
    bypass_users: list[str] = []
    bypass_groups: list[str] = []


cli_state = CLIState()


def print_error(title: str, msg: str) -> None:
    """Print a styled error message using a Rich Panel."""
    err_console.print(Panel(msg, title=f"[bold red]{title}[/bold red]", border_style="red"))


# ---------------------------------------------------------------------------
# Backward-compatible re-exports from extracted submodules
# ---------------------------------------------------------------------------

from ttp.commands._logging import JSONFormatter, setup_logging  # noqa: E402, F401
from ttp.commands._ports import (  # noqa: E402, F401
    get_uid_from_port,
    is_port_in_use,
    is_port_listening_tcp,
    is_port_listening_udp,
)
from ttp.commands._validation import (  # noqa: E402, F401
    parse_txt_dig_ipv4,
    require_root,
    require_systemd,
    validate_bridge_line,
    verify_tor,
)
