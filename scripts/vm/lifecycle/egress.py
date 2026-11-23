# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Summarise what a lifecycle-VM guest sent, from a pcap written by QEMU.

Streams the file one record at a time with the standard library only, so its
memory use does not depend on the capture's size. An earlier analysis loaded a
whole capture with scapy's rdpcap and exhausted the host's memory; nothing here
may hold more than one packet at once.

Usage: egress.py <file.pcap> [--net 10.0.2.0/24] [--hits ADDR] [--require-control]
Prints one line per (destination, protocol, port) with a packet count, then a
total. The SSH control channel (guest tcp/22 to the QEMU gateway) is counted
separately, not as egress.

A capture that cannot support a verdict is never summarised as clean. The
script prints ``INCONCLUSIVE: <reason>`` on stderr and exits 2 when:

* the file is empty, its header is short or corrupt, or it is not Ethernet;
* a record or its frame is cut short, or its lengths are impossible;
* a frame was snapped (QEMU's ``maxlen``) below the bytes that name its
  destination, or is too short or malformed to read them;
* a frame uses a layout this reader does not parse (a VLAN tag, an unknown
  EtherType): a probe could be hiding in it;
* with ``--require-control``, no guest-originated SSH control packet is in the
  capture, so it is not known to see the guest's egress at all (an empty
  window, a capture of replies only, the wrong NIC).

Snapping above those bytes is intentional (``vm_capture_start`` keeps 128
bytes per frame) and is not a reason: the destination address is all a
verdict needs. A port that lies beyond the snap, or in a non-first fragment,
is reported as ``-``.

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
from dataclasses import dataclass

# QEMU user networking numbers a subnet the same way every time: the gateway is
# .2, its DNS forwarder .3 and the guest's lease .15. --net selects the subnet.
GATEWAY = "10.0.2.2"
GUEST_V4 = "10.0.2.15"

LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP = 0x0800, 0x86DD, 0x0806

#: IPv6 extension headers walked to reach the transport header. A Fragment
#: header (44) is walked too; Authentication (51) counts its length in 4-byte
#: units rather than 8.
_IPV6_EXTENSIONS = {0, 43, 44, 51, 60}

_MAGIC = {0xA1B2C3D4: ("<", False), 0xD4C3B2A1: (">", False), 0xA1B23C4D: ("<", True), 0x4D3CB2A1: (">", True)}


class Inconclusive(Exception):
    """The capture cannot support a verdict; the message says why."""


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
    """Yield (timestamp, frame) for every record; raise Inconclusive on any damage."""
    try:
        f = open(path, "rb")  # noqa: SIM115 - closed below, the generator owns it
    except OSError as exc:
        raise Inconclusive(f"{path}: cannot be read ({exc.strerror})") from None
    with f:
        header = f.read(24)
        if len(header) < 24:
            raise Inconclusive(
                f"{path}: {'empty' if not header else 'truncated'} file header ({len(header)} of 24 bytes)"
            )
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in _MAGIC:
            raise Inconclusive(f"{path}: not a pcap file (magic {magic:#x})")
        endian, nano = _MAGIC[magic]
        major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(endian + "HHiIII", header[4:])
        if (major, minor) != (2, 4):
            raise Inconclusive(f"{path}: unsupported pcap version {major}.{minor}")
        if linktype != LINKTYPE_ETHERNET:
            raise Inconclusive(f"{path}: link type {linktype}, not Ethernet")
        index = 0
        while True:
            rec = f.read(16)
            if not rec:
                return
            index += 1
            if len(rec) < 16:
                raise Inconclusive(f"{path}: record {index} header cut short ({len(rec)} of 16 bytes)")
            sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
            if incl > orig or (snaplen and incl > snaplen):
                raise Inconclusive(f"{path}: record {index} claims {incl} bytes of {orig} (snap length {snaplen})")
            frame = f.read(incl)
            if len(frame) < incl:
                raise Inconclusive(f"{path}: record {index} frame cut short ({len(frame)} of {incl} bytes)")
            yield sec + frac / (1e9 if nano else 1e6), frame


@dataclass(frozen=True)
class Packet:
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None


_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}


def _ports(proto: int, l4: bytes) -> tuple[int | None, int | None]:
    if proto in (6, 17) and len(l4) >= 4:
        sport, dport = struct.unpack("!HH", l4[:4])
        return sport, dport
    return None, None


def parse(frame: bytes) -> Packet | None:
    """The addresses, protocol and ports of an IP frame; None for ARP.

    Raises Inconclusive for anything that could carry an IP packet this reader
    cannot read: a frame too short for its destination, a malformed header, a
    VLAN tag or an EtherType it does not know.
    """
    if len(frame) < 14:
        raise Inconclusive(f"a {len(frame)}-byte frame has no complete Ethernet header")
    ethertype = struct.unpack("!H", frame[12:14])[0]
    ip = frame[14:]
    if ethertype == ETHERTYPE_ARP:
        return None
    if ethertype == ETHERTYPE_IPV4:
        if len(ip) < 20:
            raise Inconclusive(f"an IPv4 frame was captured with {len(ip)} of the 20 header bytes")
        ihl = (ip[0] & 0x0F) * 4
        if ip[0] >> 4 != 4 or ihl < 20:
            raise Inconclusive(f"a malformed IPv4 header (version {ip[0] >> 4}, header length {ihl})")
        proto, src, dst = ip[9], ip[12:16], ip[16:20]
        first_fragment = struct.unpack("!H", ip[6:8])[0] & 0x1FFF == 0
        sport, dport = _ports(proto, ip[ihl:]) if first_fragment else (None, None)
    elif ethertype == ETHERTYPE_IPV6:
        if len(ip) < 40:
            raise Inconclusive(f"an IPv6 frame was captured with {len(ip)} of the 40 header bytes")
        proto, src, dst = ip[6], ip[8:24], ip[24:40]
        offset, first_fragment = 40, True
        while proto in _IPV6_EXTENSIONS and len(ip) >= offset + 8:
            ext = ip[offset : offset + 8]
            if proto == 44:
                first_fragment = first_fragment and struct.unpack("!H", ext[2:4])[0] >> 3 == 0
                length = 8
            else:
                length = (ext[1] + 2) * 4 if proto == 51 else (ext[1] + 1) * 8
            proto, offset = ext[0], offset + length
        # An extension chain cut by the snap length leaves the transport unknown;
        # the destination, which is all a verdict needs, is already read.
        if proto in _IPV6_EXTENSIONS or not first_fragment:
            sport, dport = None, None
        else:
            sport, dport = _ports(proto, ip[offset:])
    else:
        kind = "a VLAN-tagged frame" if ethertype in (0x8100, 0x88A8) else f"EtherType {ethertype:#06x}"
        raise Inconclusive(f"{kind} is not parsed by this reader and could carry a probe")
    name = _NAMES.get(proto, f"proto{proto}")
    return Packet(str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst)), name, sport, dport)


def is_control(packet: Packet) -> bool:
    """The guest's side of our own SSH control channel."""
    return packet.proto == "tcp" and packet.sport == 22 and packet.dst == GATEWAY


def summarise(path: str) -> tuple[collections.Counter[tuple[str, str, int | None]], int]:
    """Guest-originated flows and the number of guest SSH control packets."""
    flows: collections.Counter[tuple[str, str, int | None]] = collections.Counter()
    control = 0
    for index, (_ts, frame) in enumerate(records(path), start=1):
        try:
            packet = parse(frame)
        except Inconclusive as exc:
            raise Inconclusive(f"{path}: record {index}: {exc}") from None
        if packet is None or not sent_by_guest(packet.src):
            continue
        if is_control(packet):
            control += 1
            continue
        flows[(packet.dst, packet.proto, packet.dport)] += 1
    return flows, control


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--net", default="10.0.2.0/24", help="the QEMU user-network subnet of this capture")
    ap.add_argument("--hits", metavar="ADDR", help="print only how many guest packets went to ADDR")
    ap.add_argument(
        "--require-control",
        action="store_true",
        help="inconclusive unless the guest's SSH control channel appears in the capture",
    )
    args = ap.parse_args()
    use_subnet(args.net)

    try:
        flows, control = summarise(args.pcap)
        if args.require_control and not control:
            raise Inconclusive(
                f"{args.pcap}: no guest-originated SSH control packet, so the capture is not "
                f"known to see the guest's egress (empty window, replies only, or the wrong NIC)"
            )
    except Inconclusive as exc:
        print(f"INCONCLUSIVE: {exc}", file=sys.stderr)
        return 2

    if args.hits:
        print(sum(n for (dst, _proto, _dport), n in flows.items() if dst == args.hits))
        return 0

    for (dst, proto, dport), n in sorted(flows.items(), key=lambda kv: -kv[1]):
        print(f"{n:6} {proto:7} {dst}:{dport if dport is not None else '-'}")
    print(f"total {sum(flows.values())} guest-originated packet(s), {control} SSH control packet(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
