# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Guest-side leak probe for the lifecycle VM (#30).

Runs inside the guest as an ordinary, non-bypassed user and keeps trying to
reach PROBE_DST in cleartext: a UDP datagram to port 53 and a TCP connection to
port 80, every INTERVAL seconds, until killed.

PROBE_DST is in 198.51.100.0/24 (TEST-NET-2, RFC 5737): it cannot be a Tor relay
and nothing on the guest talks to it on its own, so any packet to it in the
host-side capture is this probe escaping, and nothing else. With TTP active the
UDP is redirected to Tor's DNSPort and the TCP to its TransPort, so neither may
appear on the wire; with TTP inactive both must, which is the positive control.
"""

from __future__ import annotations

import socket
import sys
import time

PROBE_DST = "198.51.100.7"
INTERVAL = 0.2


def main() -> int:
    while True:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.sendto(b"ttp-lifecycle-probe", (PROBE_DST, 53))
        except OSError:
            pass  # rejected locally: the firewall working, not the probe failing
        finally:
            udp.close()
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setblocking(False)
        try:
            tcp.connect_ex((PROBE_DST, 80))
        finally:
            tcp.close()
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
