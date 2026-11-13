# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""DNS socket observations and externally measured containment.

Timeouts, error rcodes, TXT answers and aggregate redirect counters do not
identify the network path. Containment tests consume the completed calibrated
report produced outside the protected netns by scripts/vm/leak_boundary.py.
The report describes the protected interval, finalized after explicit stop.
"""

from __future__ import annotations

import socket

import pytest

from tests.leak.oracle import Observation, Outcome, assert_contained, measured_observation, session_is_active

_QUERY = (
    b"\xaa\xbb"  # Transaction ID
    b"\x01\x00"  # Flags: standard query, recursion desired
    b"\x00\x01"  # Questions: 1
    b"\x00\x00\x00\x00\x00\x00"  # Answer/Authority/Additional RRs: 0
    b"\x07example\x03com\x00"
    b"\x00\x10"  # Type: TXT
    b"\x00\x01"  # Class: IN
)
_TXID = _QUERY[:2]


def _classify(data: bytes, peer_addr: str) -> tuple[Outcome, str]:
    if len(data) < 12 or data[:2] != _TXID or not data[2] & 0x80:
        return Outcome.UNREACHABLE, f"Unmatched or malformed DNS response from {peer_addr}"
    return (
        Outcome.ANSWERED,
        f"DNS rcode {data[3] & 15}, answers {int.from_bytes(data[6:8], 'big')} from {peer_addr}; path unproven",
    )


def _probe(family: int, resolver: str, probe_name: str, *, port: int = 53, timeout: float = 5) -> Observation:
    """Diagnostic only: socket behavior alone never establishes containment."""
    active = session_is_active()
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_QUERY, (resolver, port))
        data, peer = sock.recvfrom(1232)
        outcome, detail = _classify(data, peer[0])
    except OSError as exc:
        outcome, detail = Outcome.UNREACHABLE, f"DNS socket observation is inconclusive: {exc!r}"
    finally:
        if sock is not None:
            sock.close()
    return Observation(probe_name, f"{resolver}:{port}", outcome, active, detail)


@pytest.mark.leak
@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("mode", ["drop", "servfail", "notimp", "refused", "answer"])
def test_dns_leak_prevention(family, mode):
    assert_contained(measured_observation(f"dns_{mode}_ipv{family}"))
