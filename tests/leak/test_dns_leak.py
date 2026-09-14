# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Offensive DNS leak verification.

Sends a raw DNS query straight at a public resolver and reports what came back.

What this probe can and cannot prove
------------------------------------

It can prove containment when the packet is **refused or dropped**: nothing
answered, so nothing left.

It cannot prove containment when an answer *does* come back. Under a working
session the query is DNAT'd to Tor's DNSPort and Tor answers it; with the
ruleset absent the query reaches the public resolver and the resolver answers
it. Both replies carry the same transaction ID and the same response bit, and
the NAT translation is undone on the way back, so the source address matches in
both cases too. The previous version of this file asserted on exactly those
fields and called the result "safely intercepted" - an assertion that was true
in both worlds and therefore distinguished neither.

That case is now reported as INCONCLUSIVE, which is red. Issue #38 covers the
discriminator that would make it decisive: a counter on the redirect rule.
"""

from __future__ import annotations

import socket

import pytest

from tests.leak.oracle import Observation, Outcome, assert_contained, session_is_active

# A minimal A-record query for check.torproject.org, hand-packed to avoid a
# dnspython dependency in a test whose whole job is to not trust its tools.
_QUERY = (
    b"\xaa\xbb"  # Transaction ID
    b"\x01\x00"  # Flags: standard query
    b"\x00\x01"  # Questions: 1
    b"\x00\x00\x00\x00\x00\x00"  # Answer/Authority/Additional RRs: 0
    b"\x05check\x0atorproject\x03org\x00"
    b"\x00\x01"  # Type: A
    b"\x00\x01"  # Class: IN
)
_TXID = _QUERY[:2]


def _probe(family: int, resolver: str, probe_name: str) -> Observation:
    """Send the query and record what happened, without deciding what it means."""
    session_active = session_is_active()
    target = f"{resolver}:53"
    outcome = Outcome.NOT_ATTEMPTED
    detail = ""

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(_QUERY, (resolver, 53))
        data, peer = sock.recvfrom(512)

        well_formed = len(data) >= 12 and data[:2] == _TXID and bool(data[2] & 0x80)
        outcome = Outcome.ANSWERED
        detail = (
            f"{len(data)} bytes from {peer[0]}, "
            f"{'well-formed' if well_formed else 'MALFORMED'} reply to our transaction id"
        )
    except TimeoutError:
        outcome = Outcome.BLOCKED
        detail = "no reply within 5s: the query was dropped before leaving the host"
    except OSError as exc:
        outcome = Outcome.BLOCKED
        detail = f"socket error, i.e. an active refusal: {exc!r}"
    finally:
        sock.close()

    return Observation(
        probe=probe_name,
        target=target,
        outcome=outcome,
        session_active=session_active,
        detail=detail,
    )


@pytest.mark.leak
def test_dns_leak_prevention():
    """A cleartext UDP/53 query to a public resolver must not escape."""
    assert_contained(_probe(socket.AF_INET, "1.1.1.1", "dns_udp53_ipv4"))


@pytest.mark.leak
def test_dns_leak_prevention_ipv6():
    """The same, over IPv6, where the redirect is a separate rule."""
    from ttp.tor_detect import is_ipv6_supported

    if not is_ipv6_supported():
        pytest.skip("IPv6 loopback not supported by the environment.")

    assert_contained(_probe(socket.AF_INET6, "2606:4700:4700::1111", "dns_udp53_ipv6"))
