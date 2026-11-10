# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Network-independent control and strict capture inspection for disposable VMs.

QGA synchronization follows https://www.qemu.org/docs/master/interop/qemu-ga-ref.html.
No SSH exception is added to the firewall under test.
"""

from __future__ import annotations

import base64
import collections
import ipaddress
import json
import secrets
import socket
import struct
import time
from pathlib import Path


class Agent:
    def __init__(self, path: Path):
        self.path = path

    def call(self, command: str, arguments: dict | None = None):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(10)
            stream.connect(str(self.path))
            token = secrets.randbits(52)
            sync = {"execute": "guest-sync-delimited", "arguments": {"id": token}}
            stream.sendall(b"\xff" + json.dumps(sync).encode() + b"\n")
            data = bytearray()

            def receive():
                while b"\n" not in data:
                    block = stream.recv(65536)
                    if not block:
                        raise RuntimeError("QGA closed the control channel")
                    data.extend(block)
                    if len(data) > 16 * 1024 * 1024:
                        raise RuntimeError("QGA response too large")
                line, _, rest = data.partition(b"\n")
                data[:] = rest
                return line

            while True:
                line = receive()
                if b"\xff" not in line:
                    continue
                reply = json.loads(line.rsplit(b"\xff", 1)[1])
                if reply.get("return") == token:
                    break
            request = {"execute": command, "id": token}
            if arguments is not None:
                request["arguments"] = arguments
            stream.sendall(json.dumps(request).encode() + b"\n")
            while True:
                reply = json.loads(receive())
                if reply.get("id") != token:
                    continue
                if "error" in reply:
                    raise RuntimeError(f"{command}: {reply['error']}")
                return reply["return"]

    def run(self, script: str, *, timeout: int = 60, check: bool = True) -> tuple[int, str]:
        # Guest-side timeout also terminates commands if the host loses control.
        pid = self.call(
            "guest-exec",
            {
                "path": "/usr/bin/timeout",
                "arg": [str(timeout), "/bin/bash", "-se"],
                "input-data": base64.b64encode(script.encode()).decode(),
                "capture-output": True,
            },
        )["pid"]
        deadline = time.monotonic() + timeout + 15
        while time.monotonic() < deadline:
            result = self.call("guest-exec-status", {"pid": pid})
            if result.get("exited"):
                if result.get("out-truncated") or result.get("err-truncated"):
                    raise RuntimeError("QGA truncated command evidence")
                output = "".join(
                    base64.b64decode(result.get(key, ""), validate=True).decode(errors="replace")
                    for key in ("out-data", "err-data")
                )
                code = result.get("exitcode", 128 + result.get("signal", 0))
                if check and code:
                    raise RuntimeError(f"Guest command exited {code}:\n{output}")
                return code, output
            time.sleep(0.5)
        raise TimeoutError("Guest command did not finish")


def qmp(path: Path, command: str, arguments: dict | None = None):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(10)
        stream.connect(str(path))
        with stream.makefile("rb") as reader:
            json.loads(reader.readline())  # greeting
            for name, args in (("qmp_capabilities", {}), (command, arguments or {})):
                stream.sendall(json.dumps({"execute": name, "arguments": args, "id": name}).encode() + b"\n")
                while True:
                    reply = json.loads(reader.readline())
                    if reply.get("id") == name:
                        break
                if "error" in reply:
                    raise RuntimeError(f"{name}: {reply['error']}")
            return reply["return"]


def inspect_capture(path: Path, *, client_mac: bytes, endpoint: str) -> dict:
    """Fail on malformed/unknown client traffic, including empty/truncated pcaps.

    Only ARP, exact WG endpoint UDP and DHCPv4 are accepted. This qualification
    currently uses an IPv4-only underlay; IPv6 frames are failures, not ignored.
    The destination canary is a real listening server on the peer.
    """
    counts: collections.Counter[str] = collections.Counter()
    violations: collections.Counter[str] = collections.Counter()
    renewals: set[bytes] = set()
    acknowledgements: set[bytes] = set()
    with path.open("rb") as capture:
        header = capture.read(24)
        if len(header) != 24 or header[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("Missing/unsupported pcap header")
        if struct.unpack("<I", header[20:24])[0] != 1:
            raise ValueError("Capture must use Ethernet")
        while record := capture.read(16):
            if len(record) != 16:
                raise ValueError("Truncated pcap record")
            _, _, size, original = struct.unpack("<IIII", record)
            if size > 65536 or size > original:
                raise ValueError("Invalid pcap record length")
            frame = capture.read(size)
            if len(frame) != size or size < 14:
                raise ValueError("Truncated Ethernet record")
            outgoing = frame[6:12] == client_mac
            # Match a bound client's unicast DHCPREQUEST to the peer's DHCPACK,
            # not merely a Discover/retry or an unrelated broadcast lease.
            if frame[12:14] == b"\x08\x00" and len(frame) >= 42:
                ip = frame[14:]
                ihl = (ip[0] & 15) * 4
                if ihl >= 20 and ip[9] == 17 and len(ip) >= ihl + 248:
                    sport, dport = struct.unpack("!HH", ip[ihl : ihl + 4])
                    bootp = ip[ihl + 8 :]
                    if bootp[236:240] == b"\x63\x82\x53\x63" and bootp[28:34] == client_mac:
                        msgtype = None
                        options = bootp[240:]
                        offset = 0
                        while offset < len(options):
                            code = options[offset]
                            offset += 1
                            if code == 255:
                                break
                            if code == 0:
                                continue
                            if offset >= len(options):
                                break
                            size = options[offset]
                            offset += 1
                            value = options[offset : offset + size]
                            offset += size
                            if code == 53 and len(value) == size == 1:
                                msgtype = value[0]
                        xid = bootp[4:8]
                        if outgoing and (sport, dport, msgtype) == (68, 67, 3) and bootp[12:16] != bytes(4):
                            renewals.add(xid)
                        elif (
                            not outgoing
                            and (sport, dport, msgtype) == (67, 68, 5)
                            and str(ipaddress.ip_address(ip[12:16])) == endpoint
                        ):
                            acknowledgements.add(xid)
            if not outgoing:
                continue
            counts["outgoing"] += 1
            kind = struct.unpack("!H", frame[12:14])[0]
            if kind == 0x0806:
                counts["arp"] += 1
                continue
            if kind != 0x0800 or len(frame) < 34:
                violations[f"ethertype:{kind:#x}"] += 1
                continue
            ip = frame[14:]
            ihl = (ip[0] & 15) * 4
            if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl + 8:
                raise ValueError("Truncated/invalid IPv4 header")
            dst = str(ipaddress.ip_address(ip[16:20]))
            proto = ip[9]
            fragmented = struct.unpack("!H", ip[6:8])[0] & 0x3FFF
            sport, dport = struct.unpack("!HH", ip[ihl : ihl + 4])
            if proto == 17 and not fragmented and dst == endpoint and dport == 51820:
                counts["wireguard"] += 1
            elif proto == 17 and not fragmented and sport == 68 and dport == 67:
                counts["dhcp"] += 1
            else:
                violations[f"{dst}/proto{proto}/port{dport}"] += 1
    if not counts["outgoing"]:
        raise ValueError("No outgoing frames: observer is inconclusive")
    if renewals:
        counts["dhcp_renewals_acknowledged"] = len(renewals & acknowledgements)
    return {"counts": dict(counts), "violations": dict(violations)}
