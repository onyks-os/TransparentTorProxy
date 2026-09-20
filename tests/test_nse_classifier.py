# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Unit tests for the containment classifier.

The NSE ruleset suite needs root and a network namespace, so its verdict
function was previously unreachable from the ordinary test run. These tests
exercise it directly with synthetic packets: no namespace, no sniffer, no
privileges.

The class that matters most here is routable ICMPv6. The sniffer's BPF filter
used to exclude all of ICMPv6 in the kernel, so an echo to a global address
never reached userspace to be classified at all -- there was no test for that
leak class, and the reason was invisible from the test file. Asserting it here
means a future filter that goes broad again is caught by a failing positive
control rather than by a class quietly ceasing to be covered.
"""

from __future__ import annotations

from typing import Any

import pytest

scapy_inet = pytest.importorskip("scapy.layers.inet")
scapy_inet6 = pytest.importorskip("scapy.layers.inet6")

from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6ND_NS, IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402

from tests.nse_classifier import canary_seen, is_cleartext_leak  # noqa: E402

# ---------------------------------------------------------------------------
# IPv6: the direction the BPF filter used to hide
# ---------------------------------------------------------------------------


def test_icmpv6_echo_to_a_global_address_is_a_leak() -> None:
    """`ping6 2001:4860:4860::8888` outside Tor is exactly what this detects."""
    pkt = Ether() / IPv6(dst="2001:4860:4860::8888") / ICMPv6EchoRequest()
    assert is_cleartext_leak(pkt) is True


def test_neighbour_solicitation_is_not_a_leak() -> None:
    """ND is link-local by construction and dies at the first router."""
    pkt = Ether() / IPv6(dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="fe80::1")
    assert is_cleartext_leak(pkt) is False


@pytest.mark.parametrize(
    "dst",
    [
        pytest.param("::1", id="loopback"),
        pytest.param("fe80::1", id="link-local"),
        pytest.param("ff02::fb", id="mdns-multicast"),
        pytest.param("ff02::1:3", id="llmnr-multicast"),
        pytest.param("fd00:1::5", id="sandbox-ula"),
    ],
)
def test_unroutable_ipv6_destinations_are_not_leaks(dst: str) -> None:
    assert is_cleartext_leak(Ether() / IPv6(dst=dst) / UDP(dport=53)) is False


@pytest.mark.parametrize(
    "dst",
    [
        pytest.param("2001:4860:4860::8888", id="google-dns"),
        pytest.param("2606:4700:4700::1111", id="cloudflare-dns"),
        pytest.param("fc00::1", id="other-ula-is-still-off-link"),
    ],
)
def test_routable_ipv6_destinations_are_leaks(dst: str) -> None:
    assert is_cleartext_leak(Ether() / IPv6(dst=dst) / UDP(dport=53)) is True


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dst",
    [
        pytest.param("127.0.0.1", id="loopback"),
        pytest.param("10.0.1.7", id="sandbox-lan"),
        pytest.param("224.0.0.251", id="mdns-multicast"),
        pytest.param("239.255.255.250", id="ssdp-multicast"),
    ],
)
def test_unroutable_ipv4_destinations_are_not_leaks(dst: str) -> None:
    assert is_cleartext_leak(Ether() / IP(dst=dst) / UDP(dport=53)) is False


@pytest.mark.parametrize(
    "dst",
    [
        pytest.param("8.8.8.8", id="google-dns"),
        pytest.param("1.1.1.1", id="cloudflare-dns"),
        pytest.param("223.255.255.255", id="just-below-multicast"),
        pytest.param("240.0.0.1", id="just-above-multicast"),
        pytest.param("192.168.1.1", id="other-rfc1918-is-still-off-link"),
    ],
)
def test_routable_ipv4_destinations_are_leaks(dst: str) -> None:
    assert is_cleartext_leak(Ether() / IP(dst=dst) / UDP(dport=53)) is True


# ---------------------------------------------------------------------------
# Neither family
# ---------------------------------------------------------------------------


def test_arp_is_not_a_leak() -> None:
    """ARP carries no payload off-link and has no IP layer to judge."""
    assert is_cleartext_leak(Ether() / ARP(pdst="10.0.1.1")) is False


def test_a_bare_ethernet_frame_is_not_a_leak() -> None:
    assert is_cleartext_leak(Ether()) is False


# ---------------------------------------------------------------------------
# The canary predicate.
#
# The canary is what makes a containment assertion mean something: it rides in
# the same capture session as the assertion, so observing it proves the sniffer
# was measuring during that exact window. A predicate that matched too eagerly
# would defeat the whole mechanism -- it would report "the instrument works"
# for a capture that contains anything at all.
# ---------------------------------------------------------------------------

CANARY_HOST = "10.0.1.1"
CANARY_PORT = 9999


def _canary() -> Any:
    return Ether() / IP(dst=CANARY_HOST) / UDP(dport=CANARY_PORT)


def test_the_canary_is_recognised() -> None:
    assert canary_seen([_canary()], CANARY_HOST, CANARY_PORT) is True


def test_an_empty_capture_has_no_canary() -> None:
    """The case the canary exists to catch: a sniffer that saw nothing."""
    assert canary_seen([], CANARY_HOST, CANARY_PORT) is False


def test_the_canary_is_found_among_other_traffic() -> None:
    noise = [
        Ether() / IP(dst="8.8.8.8") / UDP(dport=53),
        Ether() / IPv6(dst="2001:4860:4860::8888") / UDP(dport=53),
    ]
    assert canary_seen([*noise, _canary()], CANARY_HOST, CANARY_PORT) is True


@pytest.mark.parametrize(
    "pkt",
    [
        pytest.param(Ether() / IP(dst=CANARY_HOST) / UDP(dport=53), id="right-host-wrong-port"),
        pytest.param(Ether() / IP(dst="8.8.8.8") / UDP(dport=CANARY_PORT), id="wrong-host"),
        pytest.param(Ether() / IP(dst=CANARY_HOST), id="no-udp-layer"),
        pytest.param(Ether() / IPv6(dst="fd00:1::1") / UDP(dport=CANARY_PORT), id="v6-not-v4"),
    ],
)
def test_near_misses_are_not_the_canary(pkt: Any) -> None:
    """A loose predicate would report a working instrument for any capture."""
    assert canary_seen([pkt], CANARY_HOST, CANARY_PORT) is False


def test_the_canary_is_not_itself_counted_as_a_leak() -> None:
    """It targets the veth peer, which the classifier already excludes.

    If it were a leak, every containment assertion would fail on its own marker.
    """
    assert is_cleartext_leak(_canary()) is False
