# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ``ttp.commands._logging``.

This module was at 70% and untested where it matters. TTP's log records the
active interface, the ports in use, the bypassed UIDs and GIDs, and the bridge
configuration - the metadata of a privacy session. It is created ``0600`` on a
deliberate `os.open`, and nothing asserted that until now.

The rest is about the CLI staying usable: a failure to configure logging must
never take down a command that is about to reroute the user's traffic, and
re-running setup must not double every log line.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from ttp.commands._common import cli_state, logger
from ttp.commands._logging import JSONFormatter, setup_logging


@pytest.fixture
def log_path(tmp_path: Path):
    """Redirect the log file and restore the logger and CLI flags afterwards."""
    path = tmp_path / "ttp.log"
    saved = (cli_state.verbose, cli_state.quiet, cli_state.log_format)
    saved_handlers = list(logger.handlers)
    saved_level = logger.level
    with (
        patch("ttp.commands._logging._LOG_PATH", path),
        patch("ttp.state.ensure_runtime_dir"),
    ):
        yield path
    for h in list(logger.handlers):
        logger.removeHandler(h)
    for h in saved_handlers:
        logger.addHandler(h)
    logger.setLevel(saved_level)
    cli_state.verbose, cli_state.quiet, cli_state.log_format = saved


def _file_handlers() -> list[logging.Handler]:
    return [h for h in logger.handlers if isinstance(h, logging.FileHandler)]


# ---------------------------------------------------------------------------
# File permissions — the log holds session metadata
# ---------------------------------------------------------------------------


def test_new_log_file_is_created_private(log_path: Path) -> None:
    """0600. The log names the interface, the ports and the bypassed UIDs."""
    cli_state.quiet = True
    setup_logging()
    assert log_path.exists()
    assert log_path.stat().st_mode & 0o077 == 0


def test_an_existing_world_readable_log_is_tightened(log_path: Path) -> None:
    """
    A log left behind by an older version, or created before this hardening,
    must not stay readable just because it already exists.
    """
    log_path.write_text("previous session\n")
    log_path.chmod(0o644)
    cli_state.quiet = True
    setup_logging()
    assert log_path.stat().st_mode & 0o077 == 0


def test_an_existing_private_log_is_left_alone(log_path: Path) -> None:
    log_path.write_text("previous session\n")
    log_path.chmod(0o600)
    cli_state.quiet = True
    setup_logging()
    assert log_path.read_text() == "previous session\n"


# ---------------------------------------------------------------------------
# Failure must not take the CLI down
# ---------------------------------------------------------------------------


def test_an_unwritable_runtime_dir_does_not_raise(log_path: Path) -> None:
    with patch("ttp.state.ensure_runtime_dir", side_effect=OSError("read-only")):
        cli_state.quiet = True
        setup_logging()  # must not raise


def test_a_log_file_that_cannot_be_created_does_not_raise(log_path: Path) -> None:
    """`ttp start` must still run when /run is full or read-only."""
    with patch("os.open", side_effect=OSError("no space left on device")):
        cli_state.quiet = True
        setup_logging()


def test_a_chmod_failure_does_not_raise(log_path: Path) -> None:
    log_path.write_text("x")
    with patch("os.chmod", side_effect=PermissionError("not owner")):
        cli_state.quiet = True
        setup_logging()


# ---------------------------------------------------------------------------
# Handler lifecycle
# ---------------------------------------------------------------------------


def test_repeated_setup_does_not_duplicate_handlers(log_path: Path) -> None:
    """Without the removeHandler loop, every call doubles each log line."""
    cli_state.quiet = True
    setup_logging()
    first = len(logger.handlers)
    setup_logging()
    setup_logging()
    assert len(logger.handlers) == first


def test_quiet_adds_no_console_handler(log_path: Path) -> None:
    cli_state.quiet = True
    cli_state.verbose = False
    setup_logging()
    assert len(logger.handlers) == len(_file_handlers())


def test_verbose_adds_a_console_handler_at_debug(log_path: Path) -> None:
    cli_state.quiet = False
    cli_state.verbose = True
    cli_state.log_format = "text"
    setup_logging()
    assert len(logger.handlers) > len(_file_handlers())
    assert logger.level == logging.DEBUG


def test_non_verbose_text_mode_logs_at_info(log_path: Path) -> None:
    cli_state.quiet = True
    cli_state.verbose = False
    cli_state.log_format = "text"
    setup_logging()
    assert logger.level == logging.INFO


def test_json_format_adds_a_console_handler_even_when_not_verbose(log_path: Path) -> None:
    """JSON output is for machines: it is requested explicitly, so it is emitted."""
    cli_state.quiet = False
    cli_state.verbose = False
    cli_state.log_format = "json"
    setup_logging()
    console = [h for h in logger.handlers if not isinstance(h, logging.FileHandler)]
    assert console
    assert isinstance(console[0].formatter, JSONFormatter)


def test_json_format_reaches_the_file_handler_too(log_path: Path) -> None:
    cli_state.quiet = True
    cli_state.log_format = "json"
    setup_logging()
    handlers = _file_handlers()
    assert handlers
    assert isinstance(handlers[0].formatter, JSONFormatter)


def test_a_message_actually_lands_in_the_file(log_path: Path) -> None:
    """End to end: the handler is wired, not merely constructed."""
    cli_state.quiet = True
    cli_state.log_format = "text"
    setup_logging()
    logger.info("session started on eth0")
    for h in _file_handlers():
        h.flush()
    assert "session started on eth0" in log_path.read_text()


# ---------------------------------------------------------------------------
# JSONFormatter
# ---------------------------------------------------------------------------


def _record(**kwargs) -> logging.LogRecord:  # type: ignore[no-untyped-def]
    defaults = {
        "name": "ttp",
        "level": logging.INFO,
        "pathname": __file__,
        "lineno": 1,
        "msg": "hello",
        "args": (),
        "exc_info": None,
    }
    defaults.update(kwargs)
    return logging.LogRecord(**defaults)  # type: ignore[arg-type]


def test_json_formatter_emits_one_valid_json_object() -> None:
    payload = json.loads(JSONFormatter().format(_record()))
    assert payload["level"] == "INFO"
    assert payload["logger"] == "ttp"
    assert payload["message"] == "hello"
    assert payload["timestamp"].endswith("+00:00")


def test_json_formatter_interpolates_arguments() -> None:
    payload = json.loads(JSONFormatter().format(_record(msg="port %d", args=(9041,))))
    assert payload["message"] == "port 9041"


def test_json_formatter_stays_single_line() -> None:
    """A multi-line record would break line-oriented log shipping."""
    out = JSONFormatter().format(_record(msg="line one\nline two"))
    assert "\n" not in out
    assert json.loads(out)["message"] == "line one\nline two"


def test_json_formatter_includes_the_traceback() -> None:
    try:
        raise ValueError("nft failed")
    except ValueError:
        import sys

        payload = json.loads(JSONFormatter().format(_record(exc_info=sys.exc_info())))
    assert "ValueError: nft failed" in payload["exception"]


def test_json_formatter_omits_exception_when_there_is_none() -> None:
    assert "exception" not in json.loads(JSONFormatter().format(_record()))
