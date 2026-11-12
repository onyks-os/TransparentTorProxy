#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Controlled DNS/UDP observations outside a disposable container's netns.

Run only inside the disposable integration VM. All fixture addresses are placed
on its Docker bridge and the container veth; no Internet responder is required.
The observer uses standard-library AF_PACKET, counts kernel capture drops, and
requires distinct Ethernet beacons bracketing every stimulus. These non-IP
beacons grant no IP firewall exception to the ordinary probe identity.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.leak.oracle import SCHEMA_VERSION, BoundaryEvidence, Observation, Outcome

HOST4, CLIENT4 = "198.51.100.53", "198.51.100.54"
HOST6, CLIENT6 = "2001:db8:5444::53", "2001:db8:5444::54"
PROBE_UID = 65534


def command(*args, timeout=45):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def execute(cid, script, *, user="0"):
    return command("docker", "exec", "--user", user, cid, "/venv/bin/python", "-c", script)


def udp_payload(frame: bytes) -> tuple[str, int, bytes] | None:
    """Parse the fixture's unfragmented Ethernet/IP/UDP frames strictly.

    Unsupported IP layouts are errors rather than silent negative evidence.
    This small controlled stimulus does not require fragmentation/extensions.
    """
    if len(frame) < 14:
        raise ValueError("Short Ethernet frame")
    kind = int.from_bytes(frame[12:14], "big")
    packet = frame[14:]
    if kind == 0x0800:
        if len(packet) < 20 or packet[0] >> 4 != 4:
            raise ValueError("Invalid IPv4")
        size = int.from_bytes(packet[2:4], "big")
        ihl = (packet[0] & 15) * 4
        if ihl < 20 or size < ihl or len(packet) < size or int.from_bytes(packet[6:8], "big") & 0x3FFF:
            raise ValueError("Truncated or fragmented IPv4")
        if packet[9] != 17:
            return None
        destination = str(ipaddress.ip_address(packet[16:20]))
        datagram = packet[ihl:size]
    elif kind == 0x86DD:
        if len(packet) < 40 or packet[0] >> 4 != 6:
            raise ValueError("Invalid IPv6")
        size = 40 + int.from_bytes(packet[4:6], "big")
        if len(packet) < size:
            raise ValueError("Truncated IPv6")
        next_header, offset = packet[6], 40
        extensions = 0
        while next_header in (0, 43, 60):
            extensions += 1
            if extensions > 8 or offset + 2 > size:
                raise ValueError("Invalid IPv6 extension chain")
            length = (packet[offset + 1] + 1) * 8
            if offset + length > size:
                raise ValueError("Truncated IPv6 extension")
            next_header, offset = packet[offset], offset + length
        if next_header in (44, 50, 51):
            raise ValueError("Unsupported IPv6 fragment/security layout")
        if next_header != 17:
            return None
        if extensions:
            raise ValueError("Unsupported UDP/IPv6 extension layout")
        destination = str(ipaddress.ip_address(packet[24:40]))
        datagram = packet[offset:size]
    elif kind in (0x8100, 0x88A8):
        raise ValueError("Unsupported VLAN layout")
    else:
        return None
    if len(datagram) < 8 or int.from_bytes(datagram[4:6], "big") != len(datagram):
        raise ValueError("Invalid UDP length")
    return destination, int.from_bytes(datagram[2:4], "big"), datagram[8:]


class Capture:
    def __init__(self, interface, mac, target, port, payload, markers, path=None):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        # A cold Tor can burst consensus downloads while a local DNS probe is
        # running. Size this socket's queue, not a system-wide kernel setting;
        # dropped frames still invalidate the entire observation below.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024**2)
        self.receive_buffer = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.sock.bind((interface, 0))
        self.sock.settimeout(0.05)
        self.mac, self.target, self.port, self.payload = mac, target, port, payload
        self.markers = markers
        self.path = path
        self.seen = set()
        self.matches = 0
        self.errors = []
        self.frames = []
        self.byte_count = 0
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.read, daemon=True)

    def read(self):
        while not self.done.is_set():
            try:
                frame = self.sock.recv(65535)
            except TimeoutError:
                continue
            except OSError as exc:
                self.errors.append(str(exc))
                return
            if len(frame) < 14:
                self.errors.append("Short Ethernet capture")
                continue
            if frame[6:12] != self.mac:
                continue
            self.byte_count += len(frame)
            if self.byte_count > 16 * 1024**2:
                self.errors.append("Capture exceeded the per-window memory budget")
                return
            self.frames.append((time.time_ns(), frame))
            if frame[12:14] == b"\x88\xb5":
                for marker in self.markers:
                    if frame[14:].startswith(marker):
                        self.seen.add(marker)
                continue
            try:
                value = udp_payload(frame)
                if value == (self.target, self.port, self.payload):
                    self.matches += 1
            except ValueError as exc:
                self.errors.append(str(exc))

    def __enter__(self):
        self.started_at = datetime.now(UTC).isoformat()
        self.started_ns = time.monotonic_ns()
        self.thread.start()
        return self

    def __exit__(self, *_):
        time.sleep(0.15)
        self.done.set()
        self.thread.join(timeout=2)
        try:
            _, self.drops = struct.unpack("II", self.sock.getsockopt(263, 6, 8))
        except OSError as exc:
            self.drops = None
            self.errors.append(f"Capture loss statistics unavailable: {exc}")
        self.sock.close()
        self.finished_at = datetime.now(UTC).isoformat()
        self.finished_ns = time.monotonic_ns()
        self.complete = not self.thread.is_alive() and not self.errors and self.drops == 0 and len(self.seen) == 2
        if self.path is not None:
            self.save(self.path)

    def save(self, path):
        with path.open("wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for stamp, frame in self.frames:
                stream.write(
                    struct.pack("<IIII", stamp // 10**9, (stamp % 10**9) // 1000, len(frame), len(frame)) + frame
                )


def cases():
    for family, host in ((4, HOST4), (6, HOST6)):
        for mode in ("drop", "servfail", "notimp", "refused", "answer"):
            yield f"dns_{mode}_ipv{family}", family, host, 53, mode
        yield f"udp_ipv{family}", family, host, 19302, "drop"


def payload_for(run_id, phase, name, port):
    token = f"{run_id}-{phase}-{name}".encode()
    if port != 53:
        return token
    # Valid TXT question, unique name/transaction and exact-byte matching.
    label = token[:63]
    return (
        secrets.token_bytes(2)
        + b"\x01\x00\x00\x01"
        + bytes(6)
        + bytes([len(label)])
        + label
        + b"\x04test\x00\x00\x10\x00\x01"
    )


@contextlib.contextmanager
def receiver(family, host, port, mode):
    sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.05)
    received = []
    done = threading.Event()

    def run():
        while not done.is_set():
            try:
                data, peer = sock.recvfrom(4096)
            except TimeoutError:
                continue
            received.append(data)
            if mode != "drop":
                rcode = {"servfail": 2, "notimp": 4, "refused": 5, "answer": 0}[mode]
                if mode == "answer":
                    header = data[:2] + b"\x81\x80\x00\x01\x00\x01" + bytes(4)
                    answer = header + data[12:] + b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x02\x01x"
                else:
                    answer = data[:2] + bytes([0x81, 0x80 | rcode]) + data[4:]
                sock.sendto(answer, peer)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield received
    finally:
        done.set()
        thread.join(timeout=2)
        sock.close()


def beacon(cid, marker):
    execute(
        cid,
        f"""import socket
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
s.bind(('eth0',0))
mac=bytes.fromhex(open('/sys/class/net/eth0/address').read().strip().replace(':',''))
s.send(bytes.fromhex('ffffffffffff')+mac+bytes.fromhex('88b5')+{marker!r})
s.close()
""",
    )


def measure(cid, metadata, phase, work):
    results = {}
    for name, family, host, port, mode in cases():
        payload = payload_for(metadata["run_id"], phase, name, port)
        markers = [secrets.token_bytes(24), secrets.token_bytes(24)]
        with receiver(family, host, port, mode) as received:
            with Capture(
                metadata["interface"],
                bytes.fromhex(metadata["mac"]),
                host,
                port,
                payload,
                markers,
                path=work / f"{phase}-{name}.pcap",
            ) as capture:
                beacon(cid, markers[0])
                output = execute(
                    cid,
                    f"""import socket,json,errno,os
assert os.geteuid()=={PROBE_UID}
status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert int(status['CapEff'].strip(),16)==0, 'Probe has effective capabilities'
s=socket.socket({socket.AF_INET if family == 4 else socket.AF_INET6},socket.SOCK_DGRAM)
s.settimeout(0.35)
sent=False
try:
 s.sendto({payload!r},({host!r},{port})); sent=True
 data,peer=s.recvfrom(4096)
 result={{'outcome':'answered','detail':data.hex()}}
except OSError as exc:
 result={{'outcome':'blocked' if exc.errno in (errno.EACCES,errno.EPERM) else 'unreachable','detail':repr(exc)}}
finally: s.close()
result['attempted']=sent or result['outcome']=='blocked'
print(json.dumps(result))
""",
                    user=f"{PROBE_UID}:{PROBE_UID}",
                )
                probe = json.loads(output)
                beacon(cid, markers[1])
        results[name] = {
            **probe,
            "escaped": max(capture.matches, received.count(payload)),
            "capture_complete": capture.complete,
            "drops": capture.drops,
            "receive_buffer": capture.receive_buffer,
            "capture_errors": capture.errors,
            "target": f"{host}:{port}",
            "payload": payload.hex(),
            "capture_started_at": capture.started_at,
            "capture_finished_at": capture.finished_at,
            "capture_started_monotonic_ns": capture.started_ns,
            "capture_finished_monotonic_ns": capture.finished_ns,
        }
        (work / f"{phase}-partial.json").write_text(json.dumps(results, indent=2))
        if not capture.complete:
            raise RuntimeError(f"Incomplete observation: {name}: {results[name]}")
        if phase != "protected" and (results[name]["escaped"] == 0 or not probe["attempted"]):
            raise RuntimeError(f"Positive control failed: {name}: {results[name]}")
        if phase != "protected" and mode != "drop" and probe["outcome"] != "answered":
            raise RuntimeError(f"Controlled DNS error/answer did not reach the sender: {name}: {probe}")
    return results


def configure(cid):
    peer = int(command("docker", "exec", cid, "cat", "/sys/class/net/eth0/iflink"))
    interface = next(p.name for p in Path("/sys/class/net").iterdir() if int((p / "ifindex").read_text()) == peer)
    bridge = (Path("/sys/class/net") / interface / "master").resolve().name
    mac = command("docker", "exec", cid, "cat", "/sys/class/net/eth0/address").replace(":", "")
    for device in (bridge,):
        command("sysctl", "-w", f"net.ipv6.conf.{device}.disable_ipv6=0")
    command("ip", "addr", "replace", f"{HOST4}/24", "dev", bridge)
    command("ip", "-6", "addr", "replace", f"{HOST6}/64", "dev", bridge, "nodad")
    command("docker", "exec", cid, "sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")
    command("docker", "exec", cid, "ip", "addr", "replace", f"{CLIENT4}/24", "dev", "eth0")
    command("docker", "exec", cid, "ip", "-6", "addr", "replace", f"{CLIENT6}/64", "dev", "eth0", "nodad")
    bridge_mac = (Path("/sys/class/net") / bridge / "address").read_text().strip()
    for family, address in (("-4", HOST4), ("-6", HOST6)):
        command(
            "docker",
            "exec",
            cid,
            "ip",
            family,
            "neigh",
            "replace",
            address,
            "lladdr",
            bridge_mac,
            "nud",
            "permanent",
            "dev",
            "eth0",
        )
    return {"run_id": secrets.token_hex(8), "interface": interface, "mac": mac}


def session(cid):
    value = json.loads(
        execute(cid, "import json; from ttp import state; print(json.dumps(state.read_lock(strict=True)))")
    )
    if (
        not value
        or not isinstance(value.get("session_id"), str)
        or not value["session_id"]
        or value.get("phase") != "running"
        or type(value.get("tor_uid")) is not int
        or value.get("tor_uid") == PROBE_UID
        or value.get("bypass_users")
        or value.get("bypass_groups")
        or value.get("external_daemon")
    ):
        raise RuntimeError("Unsupported or absent protected session")
    return value["session_id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("before", "protected", "after"))
    parser.add_argument("cid")
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    if os.environ.get("TTP_DISPOSABLE_VM") != "1":
        raise RuntimeError("This fixture requires an explicitly disposable integration VM")
    work = args.work
    if args.phase == "before":
        work.mkdir(mode=0o700)
        metadata = configure(args.cid)
        (work / "metadata.json").write_text(json.dumps(metadata))
    else:
        metadata = json.loads((work / "metadata.json").read_text())
    if args.phase == "protected":
        identity = session(args.cid)
    results = measure(args.cid, metadata, args.phase, work)
    if args.phase == "protected":
        if session(args.cid) != identity:
            raise RuntimeError("Session changed while observing traffic")
        metadata["session_id"] = identity
    (work / f"{args.phase}.json").write_text(json.dumps(results, indent=2))
    (work / "metadata.json").write_text(json.dumps(metadata))
    if args.phase == "after":
        before = json.loads((work / "before.json").read_text())
        protected = json.loads((work / "protected.json").read_text())
        observations = {}
        for name, data in protected.items():
            evidence = BoundaryEvidence(
                data["escaped"],
                before[name]["escaped"],
                results[name]["escaped"],
                data["capture_complete"],
                data["attempted"],
            )
            observations[name] = asdict(
                Observation(
                    name,
                    data["target"],
                    Outcome(data["outcome"]),
                    True,
                    data["detail"],
                    observed_at=data["capture_finished_at"],
                    boundary=evidence,
                )
            )
        report = {
            "schema": SCHEMA_VERSION,
            "run_id": metadata["run_id"],
            "complete": True,
            "session_id": metadata["session_id"],
            "observations": observations,
        }
        (work / "report.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
