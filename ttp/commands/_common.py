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


class CLIState:
    verbose: bool = False
    quiet: bool = False
    log_format: str = "text"
    bypass_users: list[str] = []
    bypass_groups: list[str] = []


cli_state = CLIState()


def print_error(title: str, msg: str) -> None:
    """Print a styled error message using a Rich Panel."""
    err_console.print(
        Panel(msg, title=f"[bold red]{title}[/bold red]", border_style="red")
    )


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
