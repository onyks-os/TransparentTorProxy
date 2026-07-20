# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Logging configuration for the TTP CLI.

Provides ``setup_logging()`` which configures the ``ttp`` logger with a
rotating file handler (always) and an optional Rich/JSON console handler
(based on ``cli_state``).  Also provides ``JSONFormatter`` for structured
log output.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path


# Re-imported here to avoid circular imports for callers that import from _logging
_LOG_PATH = Path("/run/ttp/ttp.log")


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
    """Configure logging based on the CLI state.

    Must be called once early in the CLI lifecycle (e.g., in the Typer
    callback) before any logging calls are made.
    """
    from logging.handlers import RotatingFileHandler

    from ttp.commands._common import cli_state, console, logger

    for h in list(logger.handlers):
        logger.removeHandler(h)

    try:
        from ttp import state

        state.ensure_runtime_dir()
    except OSError:
        pass

    try:
        # Pre-create the log file with mode 0o600 if it does not exist,
        # or chmod it to 0o600 if it already exists.
        if not _LOG_PATH.exists():
            try:
                fd = os.open(_LOG_PATH, os.O_WRONLY | os.O_CREAT, 0o600)
                os.close(fd)
            except OSError:
                pass
        else:
            try:
                os.chmod(_LOG_PATH, 0o600)
            except OSError:
                pass

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
