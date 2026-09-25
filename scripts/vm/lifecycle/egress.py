# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Summarise what a lifecycle-VM guest sent, from a pcap written by QEMU.

Streams the file one record at a time with the standard library only, so its
memory use does not depend on the capture's size. An earlier analysis loaded a
whole capture with scapy's rdpcap and exhausted the host's memory; nothing here
may hold more than one packet at once.

Usage: egress.py <file.pcap> [--net 10.0.2.0/24] [--hits ADDR]
Prints one line per (destination, protocol, port) with a packet count, then a
total. The SSH control channel (guest tcp/22 to the QEMU gateway) is excluded.

There is deliberately no time filter: QEMU stamps records with its own clock,
which was an hour off the host's in practice, so phases are separated by
writing one capture file per phase instead.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import struct
import sys
from collections.abc import Iterator

# QEMU user networking numbers a subnet the same way every time: the gateway is
# .2, its DNS forwarder .3 and the guest's lease .15. --net selects the subnet.
GATEWAY = "10.0.2.2"
GUEST_V4 = "10.0.2.15"


def use_subnet(cidr: str) -> None:
    global GATEWAY, GUEST_V4
    net = ipaddress.ip_network(cidr)
    GATEWAY, GUEST_V4 = str(net.network_address + 2), str(net.network_address + 15)


#: QEMU's own addresses. Replies from the Internet keep their real source address
#: through QEMU's NAT, so "not from the gateway" does not mean "sent by the guest".
QEMU_V6 = {"fe80::2", "fec0::2", "fec0::3"}


def sent_by_guest(src: str) -> bool:
    """IPv4 from the guest's lease or DHCP's 0.0.0.0; IPv6 from the guest's own prefixes."""
    if ":" not in src:
        return src in (GUEST_V4, "0.0.0.0")
    return src not in QEMU_V6 and (src.startswith(("fe80:", "fec0:")) or src == "::")


def records(path: str) -> Iterator[tuple[float, bytes]]:
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return
        magic = struct.unpack("<I", header[:4])[0]
        endian = {0xA1B2C3D4: "<", 0xD4C3B2A1: ">", 0xA1B23C4D: "<", 0x4D3CB2A1: ">"}.get(magic)
        if endian is None:
            raise SystemExit(f"{path}: not a pcap file (magic {magic:#x})")
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            yield sec + frac / (1e9 if nano else 1e6), f.read(incl)


def parse(frame: bytes) -> tuple[str, str, str, int | None] | None:
    """(src, dst, proto, dport) for an IPv4/IPv6 frame, else None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    ip = frame[14:]
    if ethertype == 0x0800 and len(ip) >= 20:
        ihl = (ip[0] & 0x0F) * 4
        proto, src, dst, l4 = ip[9], ip[12:16], ip[16:20], ip[ihl:]
    elif ethertype == 0x86DD and len(ip) >= 40:
        proto, src, dst, l4 = ip[6], ip[8:24], ip[24:40], ip[40:]
    else:
        return None
    name = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(proto, f"proto{proto}")
    dport = struct.unpack("!H", l4[2:4])[0] if proto in (6, 17) and len(l4) >= 4 else None
    sport = struct.unpack("!H", l4[0:2])[0] if proto in (6, 17) and len(l4) >= 4 else None
    s, d = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
    if name == "tcp" and sport == 22 and d == GATEWAY:
        return None  # our own SSH control channel
    return s, d, name, dport


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--net", default="10.0.2.0/24", help="the QEMU user-network subnet of this capture")
    ap.add_argument("--hits", metavar="ADDR", help="print only how many guest packets went to ADDR")
    args = ap.parse_args()
    use_subnet(args.net)

    flows: collections.Counter[tuple[str, str, int | None]] = collections.Counter()
    for _ts, frame in records(args.pcap):
        parsed = parse(frame)
        if parsed is None or not sent_by_guest(parsed[0]):
            continue
        _src, dst, proto, dport = parsed
        flows[(dst, proto, dport)] += 1

    if args.hits:
        print(sum(n for (dst, _proto, _dport), n in flows.items() if dst == args.hits))
        return 0

    for (dst, proto, dport), n in sorted(flows.items(), key=lambda kv: -kv[1]):
        print(f"{n:6} {proto:7} {dst}:{dport if dport is not None else '-'}")
    print(f"total {sum(flows.values())} guest-originated packet(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
