# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Which captured packets count as a cleartext leak.

This lives apart from ``tests/test_nse_rules.py`` on purpose. That module
skips itself unless the process is root and the network-sandbox-engine is
installed, so anything defined inside it cannot be exercised by the ordinary
unit suite. The classification rule is the instrument's verdict function -- it
decides what the zero-leak claim means -- and it should be readable and
testable without a namespace, a sniffer or privileges.

It is also the layer that must carry the link-local exclusion. The sniffer's
BPF filter runs in the kernel, so anything it drops never reaches userspace to
be classified: a rule expressed there is invisible from the test file and
cannot be unit-tested at all.
"""

from __future__ import annotations

from typing import Any

#: Destinations that cannot reach a remote observer, so they are not leaks.
#: - 127.0.0.0/8 is loopback; 10.0.1.0/24 is the sandbox's own LAN.
#: - 224-239 is IPv4 multicast (mDNS, SSDP, LLMNR).
_LOCAL_V4_PREFIXES = ("127.", "10.0.1.")
_V4_MULTICAST = range(224, 240)

#: - ::1 is loopback; fd00:1:: is the sandbox ULA; fe80:: is link-local
#:   (Neighbour Discovery, Router Solicitation/Advertisement); ff00::/8 is
#:   multicast (mDNS, LLMNR). None of these is routable off-link.
_LOCAL_V6_PREFIXES = ("fd00:1::", "fe80:", "ff")


def is_cleartext_leak(pkt: Any) -> bool:
    """True if *pkt* is a WAN-bound cleartext packet, i.e. a leak."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if pkt.haslayer(IP):
        dst = pkt[IP].dst
        if dst.startswith(_LOCAL_V4_PREFIXES):
            return False
        try:
            if int(dst.split(".")[0]) in _V4_MULTICAST:
                return False
        except (ValueError, IndexError):
            pass
        return True
    if pkt.haslayer(IPv6):
        dst = pkt[IPv6].dst
        return not (dst == "::1" or dst.startswith(_LOCAL_V6_PREFIXES))
    return False


def canary_seen(captured: list, host: str, port: int) -> bool:
    """True if the canary packet is among *captured*.

    The canary is the marker that proves a capture session was actually
    measuring. It is checked with the same kind of predicate as a leak, and for
    the same reason: "no leak" and "no packets at all" look identical from the
    outside, and only one of them is containment.
    """
    from scapy.layers.inet import IP, UDP

    return any(
        pkt.haslayer(IP) and pkt[IP].dst == host and pkt.haslayer(UDP) and pkt[UDP].dport == port for pkt in captured
    )
