# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Unit tests for ``ttp.commands._validation``.

This is the module that decides whether user input reaches the rest of TTP. A
bridge line that validates but is malformed reaches ``torrc`` and Tor fails to
start with a message about a file the user never wrote; a bridge line rejected
too eagerly locks someone out of a censored network. It sat at 58%.

``parse_txt_dig_ipv4`` deserves special attention: it reads the answer that TTP
uses to tell the user their traffic is proxied. Getting it wrong means reporting
the wrong exit IP, which is a privacy claim, not a cosmetic one.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import typer

from ttp.commands._validation import (
    parse_txt_dig_ipv4,
    require_root,
    require_systemd,
    validate_bridge_line,
    verify_tor,
)
from ttp.exceptions import TorError

# ---------------------------------------------------------------------------
# validate_bridge_line
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "192.0.2.10:9001",
        "192.0.2.10:9001 0123456789ABCDEF0123456789ABCDEF01234567",
        "[2001:db8::1]:9001",
        "obfs4 192.0.2.10:9001 CERT=abc iat-mode=0",
        "snowflake 192.0.2.10:9001",
        "meek 192.0.2.10:443",
        "meek_lite 192.0.2.10:443",
        "OBFS4 192.0.2.10:9001",  # transport names are case-insensitive
    ],
)
def test_accepted_bridge_lines(line: str) -> None:
    validate_bridge_line(line)


def test_empty_line_is_rejected() -> None:
    with pytest.raises(ValueError, match="Empty bridge line"):
        validate_bridge_line("   ")


def test_unknown_transport_is_rejected() -> None:
    """An unsupported transport must fail here, not inside Tor's own parser."""
    with pytest.raises(ValueError, match="Unsupported pluggable transport"):
        validate_bridge_line("wireguard 192.0.2.10:9001")


@pytest.mark.parametrize(
    "line",
    [
        "192.0.2.10",  # no port
        "obfs4",  # transport only
        "obfs4 192.0.2.10",  # transport, no port
        "just some words here",
    ],
)
def test_malformed_bridge_lines_are_rejected(line: str) -> None:
    with pytest.raises(ValueError, match="Invalid bridge format"):
        validate_bridge_line(line)


# ---------------------------------------------------------------------------
# require_root / require_systemd
# ---------------------------------------------------------------------------


def test_require_root_passes_as_root() -> None:
    with patch("os.geteuid", return_value=0):
        require_root()


def test_require_root_exits_for_a_normal_user() -> None:
    with (
        patch("os.geteuid", return_value=1000),
        patch("ttp.commands._common.print_error") as print_error,
        pytest.raises(typer.Exit) as exc,
    ):
        require_root()
    assert exc.value.exit_code == 1
    assert "Permission Denied" in print_error.call_args[0][0]


def test_require_systemd_passes_when_present() -> None:
    with patch("os.path.exists", return_value=True):
        require_systemd()


def test_require_systemd_exits_without_systemd() -> None:
    with (
        patch("os.path.exists", return_value=False),
        patch("ttp.commands._common.print_error") as print_error,
        pytest.raises(typer.Exit) as exc,
    ):
        require_systemd()
    assert exc.value.exit_code == 1
    assert "Systemd Required" in print_error.call_args[0][0]


def test_require_systemd_checks_the_runtime_directory() -> None:
    with patch("os.path.exists", return_value=True) as exists:
        require_systemd()
    exists.assert_called_once_with("/run/systemd/system")


# ---------------------------------------------------------------------------
# parse_txt_dig_ipv4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ('"203.0.113.7"', "203.0.113.7"),
        ("203.0.113.7", "203.0.113.7"),
        ("'203.0.113.7'", "203.0.113.7"),
        ("  203.0.113.7  \n", "203.0.113.7"),
        ('"Your IP is 203.0.113.7 today"', "203.0.113.7"),
        ("\n\n203.0.113.7\n", "203.0.113.7"),
    ],
)
def test_dig_output_yields_the_address(stdout: str, expected: str) -> None:
    assert parse_txt_dig_ipv4(stdout) == expected


def test_first_plausible_address_wins() -> None:
    assert parse_txt_dig_ipv4('"198.51.100.1"\n"203.0.113.7"') == "198.51.100.1"


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "   \n  \n",
        '"no answer"',
        ";; connection timed out; no servers could be reached",
    ],
)
def test_output_without_an_address_yields_none(stdout: str) -> None:
    assert parse_txt_dig_ipv4(stdout) is None


def test_ipv6_only_answer_yields_none() -> None:
    """The caller wants an IPv4 exit address; an AAAA answer is not one."""
    assert parse_txt_dig_ipv4('"2001:db8::1"') is None


def test_a_bare_line_is_preferred_over_an_embedded_match() -> None:
    assert parse_txt_dig_ipv4("some text 10.1.2.3 here\n203.0.113.7") == "10.1.2.3"


# ---------------------------------------------------------------------------
# verify_tor
# ---------------------------------------------------------------------------


def test_verify_tor_returns_the_control_port_result() -> None:
    with (
        patch("ttp.tor_control.wait_for_bootstrap") as bootstrap,
        patch("ttp.tor_control.verify_tor", return_value=(True, "203.0.113.7")),
        patch("time.sleep"),
    ):
        assert verify_tor(timeout=1) == (True, "203.0.113.7")
    bootstrap.assert_called_once()


def test_verify_tor_reports_a_bootstrap_failure_without_claiming_an_ip() -> None:
    """
    A failed bootstrap must not return an address. Returning a stale or guessed
    one would tell the user they are proxied when they are not.
    """
    with (
        patch("ttp.tor_control.wait_for_bootstrap", side_effect=TorError("stalled at 25%")),
        patch("ttp.tor_control.verify_tor") as verify,
        patch("ttp.commands._common.print_error") as print_error,
        patch("time.sleep"),
    ):
        result = verify_tor(timeout=1)
    assert result == (False, "unknown")
    assert "Bootstrap Error" in print_error.call_args[0][0]
    verify.assert_not_called()


def test_verify_tor_handles_a_runtime_error_from_the_control_port() -> None:
    with (
        patch("ttp.tor_control.wait_for_bootstrap", side_effect=RuntimeError("refused")),
        patch("ttp.commands._common.print_error"),
        patch("time.sleep"),
    ):
        assert verify_tor(timeout=1) == (False, "unknown")


def test_verify_tor_forwards_the_timeout() -> None:
    with (
        patch("ttp.tor_control.wait_for_bootstrap") as bootstrap,
        patch("ttp.tor_control.verify_tor", return_value=(True, "203.0.113.7")),
        patch("time.sleep"),
    ):
        verify_tor(timeout=42)
    assert bootstrap.call_args.kwargs["timeout"] == 42


def test_verify_tor_feeds_bootstrap_progress_to_the_bar() -> None:
    """The progress callback is the only thing the user sees during a slow bootstrap."""
    seen: list[int] = []

    def bootstrap(progress_callback, timeout):  # type: ignore[no-untyped-def]
        for value in (10, 50, 100):
            progress_callback(value)
            seen.append(value)

    with (
        patch("ttp.tor_control.wait_for_bootstrap", side_effect=bootstrap),
        patch("ttp.tor_control.verify_tor", return_value=(True, "203.0.113.7")),
        patch("time.sleep"),
    ):
        verify_tor(timeout=1)
    assert seen == [10, 50, 100]
