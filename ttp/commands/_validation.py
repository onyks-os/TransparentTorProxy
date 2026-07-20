# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Validation and guard utilities for the TTP CLI.

Contains input validators (bridge lines, IPv4 addresses), runtime guards
(root check, systemd check), and the high-level ``verify_tor()`` helper
that drives the bootstrap progress UI.
"""

from __future__ import annotations

import os
import re
import sys
import time

import typer
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from ttp.exceptions import TorError


def validate_bridge_line(line: str) -> None:
    """Perform basic format validation on a bridge configuration line."""
    parts = line.split()
    if not parts:
        raise ValueError("Empty bridge line")

    if ":" in parts[0]:
        return

    if len(parts) >= 2 and ":" in parts[1]:
        first_word = parts[0].lower()
        if first_word in {"obfs4", "snowflake", "meek", "meek_lite"}:
            return
        raise ValueError(f"Unsupported pluggable transport: '{parts[0]}'")

    raise ValueError(
        "Invalid bridge format. Expected '<ip>:<port>' or '<transport> <ip>:<port>'"
    )


def require_root() -> None:
    """Exit with an error if the process is not running as root."""
    from ttp.commands._common import print_error

    if os.geteuid() != 0:
        print_error("Permission Denied", "This command must be run as root (use sudo).")
        raise typer.Exit(code=1)


def require_systemd() -> None:
    """Exit if systemd runtime directory is not present."""
    if not os.path.exists("/run/systemd/system"):
        sys.exit("TTP explicitly requires systemd.")


def verify_tor(timeout: int = 180) -> tuple[bool, str]:
    """Verify that traffic is routed through Tor, with bootstrap progress UI."""
    from ttp import tor_control
    from ttp.commands._common import _PREFIX, console, print_error

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
                progress_callback=lambda val: progress.update(task_id, completed=val),
                timeout=timeout,
            )
            progress.stop()
            console.print(f"{_PREFIX} Tor is 100% bootstrapped.")
        except (TorError, RuntimeError) as e:
            progress.stop()
            print_error("Bootstrap Error", str(e))
            return False, "unknown"

    time.sleep(2)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"{_PREFIX} Verifying Tor routing...", total=None)
        return tor_control.verify_tor()


def parse_txt_dig_ipv4(dig_stdout: str) -> str | None:
    """Return the first plausible IPv4 from ``dig +short TXT`` output."""
    for raw_line in dig_stdout.strip().splitlines():
        line = raw_line.strip().strip('"').strip("'").strip()
        if not line:
            continue
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", line):
            return line
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        if m:
            return m.group(1)
    return None
