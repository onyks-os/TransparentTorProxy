# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Shared CLI utilities: logging, console output, port checks, validation."""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from ttp import state
from ttp.exceptions import TorError

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


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        log_obj = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logging() -> None:
    """Configure logging based on the CLI state."""
    from logging.handlers import RotatingFileHandler

    for h in list(logger.handlers):
        logger.removeHandler(h)

    try:
        state.ensure_runtime_dir()
    except OSError:
        pass

    try:
        handler = RotatingFileHandler(_LOG_PATH, maxBytes=1048576, backupCount=1)
        if cli_state.log_format == "json":
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if cli_state.verbose else logging.INFO)
    except OSError:
        pass

    if not cli_state.quiet:
        if cli_state.log_format == "json":
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(JSONFormatter())
            console_handler.setLevel(
                logging.DEBUG if cli_state.verbose else logging.INFO
            )
            logger.addHandler(console_handler)
            logger.setLevel(logging.DEBUG if cli_state.verbose else logging.INFO)
        elif cli_state.verbose:
            from rich.logging import RichHandler

            rich_handler = RichHandler(console=console, show_path=False)
            rich_handler.setLevel(logging.DEBUG)
            logger.addHandler(rich_handler)
            logger.setLevel(logging.DEBUG)


def is_port_in_use(port: int) -> bool:
    """Return True if the port is already in use (bound) on localhost (IPv4/IPv6)."""
    import errno
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
    except OSError:
        return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
    except OSError:
        return True

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("::1", port))
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    return True
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("::1", port))
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    return True
    except OSError:
        pass

    return False


def is_port_listening_tcp(port: int) -> bool:
    """Return True if a service is actively listening on localhost TCP port."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("127.0.0.1", port))
            return True
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("::1", port))
            return True
    except OSError:
        pass
    return False


def is_port_listening_udp(port: int) -> bool:
    """Return True if a service has bound the localhost UDP port."""
    import errno
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", port))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return True
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", port))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return True
    return False


def get_uid_from_port(target_port: int) -> int | None:
    """Find the socket owner UID for target_port TCP_LISTEN from /proc/net/tcp."""
    hex_port = f"{target_port:04X}"
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_file, "r") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 8:
                        local_address = parts[1]
                        if local_address.endswith(f":{hex_port}"):
                            if parts[3] == "0A":
                                return int(parts[7])
        except (FileNotFoundError, PermissionError):
            continue
    return None


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
