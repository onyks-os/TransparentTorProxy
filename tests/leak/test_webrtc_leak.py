# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Offensive WebRTC/STUN leak verification.

Sends a raw STUN binding request (RFC 5389) to a public STUN server, which is
how a browser discovers its own public address before opening a peer connection.

Unlike the DNS probe, this one is decisive in both directions. TTP redirects TCP
and DNS; it does not redirect UDP/19302 at all, it rejects it. So **any** STUN
reply is proof the packet left the machine in cleartext - there is no benign
path that produces one. That makes it the closest thing this suite has to a
built-in negative control, and the reason its verdict mapping is
``ESCAPED -> LEAK`` rather than the DNS probe's ``ANSWERED -> INCONCLUSIVE``.
"""

from __future__ import annotations

import socket

import pytest

from tests.leak.oracle import Observation, Outcome, assert_contained, session_is_active

# Binding Request: type 0x0001, length 0, magic cookie 0x2112A442, zero txid.
_STUN_BINDING_REQUEST = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + (b"\x00" * 12)


def _probe(family: int, host: str, port: int, probe_name: str) -> Observation:
    session_active = session_is_active()
    outcome = Outcome.NOT_ATTEMPTED
    detail = ""

    try:
        info = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)
        addr = info[0][4]
    except socket.gaierror as exc:
        # Under a live session this resolves through Tor's DNSPort, so a failure
        # here means the DNS path is broken - which says nothing about whether
        # UDP is contained. The old version called this a test failure; it is a
        # probe that could not run.
        return Observation(
            probe=probe_name,
            target=f"{host}:{port}",
            outcome=Outcome.UNREACHABLE,
            session_active=session_active,
            detail=f"could not resolve the STUN host: {exc!r}",
        )

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    try:
        sock.sendto(_STUN_BINDING_REQUEST, addr)
        data, peer = sock.recvfrom(512)
        outcome = Outcome.ESCAPED
        detail = f"STUN replied: {len(data)} bytes from {peer[0]}:{peer[1]}"
    except TimeoutError:
        outcome = Outcome.BLOCKED
        detail = "no STUN reply within 5s: the datagram was dropped"
    except OSError as exc:
        outcome = Outcome.BLOCKED
        detail = f"socket error, i.e. an active refusal: {exc!r}"
    finally:
        sock.close()

    return Observation(
        probe=probe_name,
        target=f"{addr[0]}:{port}",
        outcome=outcome,
        session_active=session_active,
        detail=detail,
    )


@pytest.mark.leak
def test_webrtc_stun_leak_prevention():
    """A STUN binding request over IPv4 must never be answered."""
    assert_contained(_probe(socket.AF_INET, "stun.l.google.com", 19302, "stun_udp19302_ipv4"))


@pytest.mark.leak
def test_webrtc_stun_leak_prevention_ipv6():
    """The same over IPv6, where a missing drop rule is the classic leak."""
    from ttp.tor_detect import is_ipv6_supported

    if not is_ipv6_supported():
        pytest.skip("IPv6 loopback not supported by the environment.")

    assert_contained(_probe(socket.AF_INET6, "stun.l.google.com", 19302, "stun_udp19302_ipv6"))
