# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Offensive DNS leak verification.

Sends a raw DNS query straight at a public resolver and reports what came back.

The discriminator
-----------------

An A-record query cannot decide anything. Under a working session it is DNAT'd
to Tor's ``DNSPort`` and Tor answers it; with the ruleset absent it reaches the
public resolver and the resolver answers it. Both replies carry the same
transaction id and the same response bit, and the NAT translation is undone on
the way back, so even the source address matches. An earlier version of this
file asserted on exactly those fields and called the result "safely
intercepted" - an assertion that was true in both worlds and therefore
distinguished neither.

This version asks for a **TXT** record instead, because Tor's ``DNSPort`` cannot
answer one. From tor(1), DNSPort:

    This port only handles A, AAAA, and PTR requests - it doesn't handle
    arbitrary DNS request types.

So the reply type is the discriminator, and it needs no root, no counter and no
privileged observation point:

* an **error rcode** (NOTIMP, REFUSED, SERVFAIL, ...) is something only a
  resolver that refuses arbitrary types produces. That is Tor. ``CONTAINED``.
* **no reply at all** means the packet was dropped before it left. ``CONTAINED``.
* a **NOERROR reply carrying answer records** is a real TXT answer, which only a
  full recursive resolver can produce. The packet reached ``1.1.1.1`` in
  cleartext. ``LEAK`` - and this is the first DNS outcome that can be one.
* a **NOERROR reply with no answer records** is the one ambiguous case left: it
  is what a resolver returns for a name that genuinely has no TXT record, and it
  is also a plausible shape for a refusal. It stays ``INCONCLUSIVE``.

``example.com`` is the target because its TXT record (``v=spf1 -all``) is served
by IANA and has been stable for years, and the discriminator above is only sound
while the name actually has a TXT record to return.
"""

from __future__ import annotations

import socket

import pytest

from tests.leak.oracle import Observation, Outcome, assert_contained, redirect_delta, session_is_active

# A TXT query for example.com, hand-packed to avoid a dnspython dependency in a
# test whose whole job is to not trust its tools.
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

#: Offsets into the 12-byte DNS header (RFC 1035 s4.1.1).
_HEADER_LEN = 12
_RCODE_MASK = 0x0F
_QR_BIT = 0x80


def _classify(data: bytes, peer_addr: str) -> tuple[Outcome, str]:
    """Decide what a reply proves, from the reply alone."""
    if len(data) < _HEADER_LEN or data[:2] != _TXID or not data[2] & _QR_BIT:
        return (
            Outcome.UNREACHABLE,
            f"{len(data)} bytes from {peer_addr} that are not a response to our query",
        )

    rcode = data[3] & _RCODE_MASK
    answers = int.from_bytes(data[6:8], "big")

    if rcode != 0:
        return (
            Outcome.ANSWERED_BY_PROXY,
            f"rcode {rcode} from {peer_addr}: the responder refuses TXT, which a public recursive resolver does not",
        )
    if answers > 0:
        return (
            Outcome.ESCAPED,
            f"NOERROR with {answers} answer record(s) from {peer_addr}: only a full "
            "recursive resolver answers TXT, so the query left the host in cleartext",
        )
    return (
        Outcome.ANSWERED,
        f"NOERROR with no answer records from {peer_addr}: indistinguishable from a "
        "name that has no TXT record, so this reply decides nothing",
    )


def _redirect_count() -> int | None:
    """Packets matched by the DNS redirect rule, or ``None`` if unreadable.

    ``None`` rather than 0 on failure: a caller that read a missing counter as
    zero would treat "could not measure" as "did not redirect", which is the
    inference this probe exists to stop making.
    """
    from ttp.firewall import read_counters

    return read_counters().get("dns_redirected")


def _probe(family: int, resolver: str, probe_name: str) -> Observation:
    """Send the query and record what happened, without deciding what it means."""
    session_active = session_is_active()
    target = f"{resolver}:53"
    outcome = Outcome.NOT_ATTEMPTED
    detail = ""

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    # Read the redirect counter before and after. A reply alone cannot say
    # where it came from: under a correct session the query is DNAT'd to Tor's
    # DNSPort and Tor answers it, under no session Cloudflare answers it, and
    # the NAT translation is undone on the way back -- so from inside the
    # socket the two are identical. The counter is a direct, local observation
    # of whether the packet actually traversed the redirect.
    before = _redirect_count()

    try:
        sock.sendto(_QUERY, (resolver, 53))
        data, peer = sock.recvfrom(1232)
        outcome, detail = _classify(data, peer[0])
        redirected = redirect_delta(before, _redirect_count())
        if redirected:
            # Decisive, and it outranks the shape-based guess above: the packet
            # is *known* to have gone through the redirect.
            #
            # The counter is global to the rule, not to this socket, so DNS
            # traffic from another process during the probe window also
            # increments it. That is tolerable here because the rule is keyed
            # on `udp dport 53` alone: it cannot match someone else's query
            # while missing ours. A bypassed process is accepted above the
            # redirect and so increments nothing. What this cannot survive is
            # a future redirect keyed on the sender - at which point the
            # attribution has to become per-flow.
            outcome = Outcome.ANSWERED_BY_PROXY
            detail = (
                f"the DNS redirect rule matched {redirected} packet(s) during this "
                f"probe, so the query reached Tor's DNSPort rather than {peer[0]}"
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
