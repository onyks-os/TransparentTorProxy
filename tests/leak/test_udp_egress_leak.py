# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Offensive verification that arbitrary UDP cannot reach the WAN.

The payload is a STUN binding request (RFC 5389), which is how a browser
discovers its own public address before opening a WebRTC peer connection. The
port, 19302, is a realistic choice and nothing more: any WAN-bound UDP port
exercises the same rule.

**What this proves.** Tor's ``TransPort`` is TCP-only, so TTP does not proxy UDP
- it rejects it. ``nat output`` redirects TCP (``builder.py:142``) and DNS on
port 53; every other datagram falls through to the catch-all ``reject`` at the
bottom of ``filter_out``. This probe is the check on that catch-all, which is
the difference between "UDP is blocked" and "UDP goes out in cleartext".

**What it does not prove, despite the payload.** It is not a WebRTC leak test
and this file used to be named as though it were. WebRTC's serious leaks are not
network traffic at all: host ICE candidates carrying private addresses, mDNS
candidates, and local interface enumeration are all produced *inside* the
browser and handed to a web page through a JavaScript API. A firewall cannot see
them, so TTP cannot prevent them, and a green result here says nothing about
them. Those are mitigated in the browser. See ``docs/decisions/0012``.

Unlike the DNS probe, this one is decisive in both directions: **any** reply is
proof the datagram left the machine in cleartext, because nothing benign
produces one. That makes it the suite's built-in negative control, and the
reason its verdict mapping is ``ESCAPED -> LEAK`` rather than the DNS probe's
``ANSWERED -> INCONCLUSIVE``.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence

import pytest

from tests.leak.oracle import Observation, Outcome, assert_contained, session_is_active

# Binding Request: type 0x0001, length 0, magic cookie 0x2112A442, zero txid.
_STUN_BINDING_REQUEST = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + (b"\x00" * 12)

#: Public STUN servers, tried in order until one resolves.
#:
#: The target has to be a real STUN server and not an arbitrary routable
#: address: this probe detects a leak by *receiving a reply*, so pointing it
#: somewhere nothing answers would turn it into a test that cannot fail.
#:
#: More than one of them, because resolution happens through Tor's DNSPort and
#: therefore through whichever exit Tor has picked. One exit returning no AAAA
#: for one hostname made this probe INCONCLUSIVE and reddened main, for a
#: reason with nothing to do with whether UDP is contained.
_STUN_HOSTS = ("stun.l.google.com", "stun1.l.google.com", "stun.cloudflare.com")


def _probe(family: int, hosts: Sequence[str], port: int, probe_name: str) -> Observation:
    session_active = session_is_active()
    outcome = Outcome.NOT_ATTEMPTED
    detail = ""

    addr = None
    failures: list[str] = []
    for host in hosts:
        try:
            addr = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)[0][4]
            break
        except socket.gaierror as exc:
            failures.append(f"{host}: {exc!r}")

    if addr is None:
        # Under a live session this resolves through Tor's DNSPort, so a failure
        # here means the DNS path is broken - which says nothing about whether
        # UDP is contained. The old version called this a test failure; it is a
        # probe that could not run.
        return Observation(
            probe=probe_name,
            target=f"{', '.join(hosts)}:{port}",
            outcome=Outcome.UNREACHABLE,
            session_active=session_active,
            detail=f"could not resolve the STUN host: {'; '.join(failures)}",
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
def test_arbitrary_udp_to_wan_is_rejected():
    """A WAN-bound datagram must never be answered. STUN is just the payload."""
    assert_contained(_probe(socket.AF_INET, _STUN_HOSTS, 19302, "udp_wan_egress_ipv4"))


@pytest.mark.leak
def test_arbitrary_udp_to_wan_is_rejected_over_ipv6():
    """The same over IPv6, where a missing drop rule is the classic leak."""
    from ttp.tor_detect import is_ipv6_supported

    if not is_ipv6_supported():
        pytest.skip("IPv6 loopback not supported by the environment.")

    assert_contained(_probe(socket.AF_INET6, _STUN_HOSTS, 19302, "udp_wan_egress_ipv6"))
