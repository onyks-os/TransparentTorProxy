# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Unit tests for the stimulus send-outcome reporter.

The NSE ruleset suite needs root and a network namespace, so the scripts it
injects into the sandbox are unreachable from the ordinary test run. The
fragment built here decides whether a probe's failure to send is *visible*,
which is the difference between a positive-control failure that names its
cause and one that only says "the sniffer saw nothing" -- the reading that
left #35 unresolved for two CI cycles.

These tests run the generated fragment with the local interpreter: no
namespace, no sniffer, no privileges, and no traffic beyond loopback.
"""

from __future__ import annotations

import subprocess
import sys

from tests.nse_stimuli import SEND_OK, reporting_send


def _run(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)


def test_a_send_that_leaves_the_socket_is_reported_as_sent() -> None:
    result = _run(
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        + reporting_send("s.sendto(b'probe', ('127.0.0.1', 9))")
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == SEND_OK


def test_a_refused_send_is_reported_with_the_kernel_s_reason() -> None:
    """A refusal must name itself: this is the line that says *why* no packet appeared."""
    result = _run(
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.close()\n" + reporting_send("s.sendto(b'probe', ('127.0.0.1', 9))")
    )
    assert result.stdout.strip() != SEND_OK
    assert "Bad file descriptor" in result.stdout


def test_a_refused_send_does_not_fail_the_probe() -> None:
    """With TTP's rules loaded a refusal is the firewall working, not a broken harness."""
    result = _run(
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.close()\n" + reporting_send("s.sendto(b'probe', ('127.0.0.1', 9))")
    )
    assert result.returncode == 0, result.stderr


def test_a_broken_probe_still_crashes() -> None:
    """Only OSError is a legitimate outcome; a bug in the script must stay loud."""
    result = _run(reporting_send("undefined_socket.sendto(b'probe', ('127.0.0.1', 9))"))
    assert result.returncode != 0
    assert "NameError" in result.stderr
