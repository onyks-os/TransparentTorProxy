# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Guest stimulus and phase beacons for externally observed chaos trials.

Socket results are diagnostics. Only the controller's independent capture may
decide whether packets crossed the boundary. Run inside a disposable VM only.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import pwd
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

DESTINATIONS = {4: "198.51.100.7", 6: "2001:db8:5444::7"}
MARKER_PREFIX = b"TTP-CHAOS-PHASE:"
INTERVAL = 0.1


def control_paths(interface: str) -> dict | None:
    """Read calibration readiness; never change routes, addresses or policy."""
    paths = {}
    for family, destination in DESTINATIONS.items():
        result = subprocess.run(
            ["ip", "-j", f"-{family}", "route", "get", destination],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        route = json.loads(result.stdout)[0]
        source = route.get("prefsrc")
        if route.get("dev") != interface or not source:
            return None
        address = ipaddress.ip_address(source)
        if address.is_link_local or address.is_unspecified or address.is_multicast:
            return None
        if family == 6:
            addresses = subprocess.run(
                ["ip", "-j", "-6", "addr", "show", "dev", interface],
                capture_output=True,
                text=True,
                check=True,
            )
            configured = [
                a for device in json.loads(addresses.stdout) for a in device["addr_info"] if a.get("local") == source
            ]
            if not configured or any(a.get("tentative") or a.get("dadfailed") for a in configured):
                return None
        paths[str(family)] = route
    return paths


def wait_control_paths(interface: str, timeout: float = 20) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        paths = control_paths(interface)
        if paths is not None:
            return paths
        if time.monotonic() >= deadline:
            raise RuntimeError("Unprotected calibration paths did not become ready")
        time.sleep(0.25)


def solicit_control_router(interface: str, mac: bytes) -> None:
    """Refresh native router discovery only after intentional unprotected stop."""
    if len(mac) != 6:
        raise ValueError("Invalid fixture MAC")
    index = socket.if_nametoindex(interface)
    # RFC 4861 router solicitation plus source link-layer address option.
    # Linux computes the ICMPv6 checksum for this raw ICMPv6 socket.
    request = struct.pack("!BBHI", 133, 0, 0, 0) + b"\x01\x01" + mac
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.sendto(request, ("ff02::2", 0, 0, index))


def probe(run_id: str) -> None:
    """Sample DNS, arbitrary UDP and TCP in both families without capabilities."""
    assert os.geteuid() != 0, "The stimulus must be an ordinary identity"
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    assert int(status["CapEff"].strip(), 16) == 0, "The stimulus has effective capabilities"
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())

    def emit(data):
        print(json.dumps(data), flush=True)

    emit(
        {
            "kind": "ready",
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "cap_eff": 0,
            "run_id": run_id,
            "interval": INTERVAL,
        }
    )
    sequence = 0
    while not done.is_set():
        started = time.monotonic()
        for family, destination in DESTINATIONS.items():
            for protocol, port in (("dns", 53), ("udp", 19302), ("tcp", 80)):
                token = f"{run_id}-{family}-{protocol}-{sequence}".encode()
                # Valid, unique TXT question. No response is needed to measure
                # egress, including when Tor refuses the unsupported qtype.
                payload = token
                if protocol == "dns":
                    payload = secrets.token_bytes(2) + b"\x01\x00\x00\x01" + bytes(6)
                    payload += bytes([len(token)]) + token + b"\x04test\x00\x00\x10\x00\x01"
                entry = {
                    "kind": "attempt",
                    "run_id": run_id,
                    "sequence": sequence,
                    "family": family,
                    "protocol": protocol,
                    "destination": destination,
                    "port": port,
                    "monotonic_ns": time.monotonic_ns(),
                    "payload": payload.hex(),
                }
                with socket.socket(
                    socket.AF_INET if family == 4 else socket.AF_INET6,
                    socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM,
                ) as sock:
                    sock.setblocking(False)
                    try:
                        if protocol == "tcp":
                            entry["errno"] = sock.connect_ex((destination, port))
                        else:
                            # Outbound clients: let connect select the concrete
                            # local address/port, without a wildcard bind.
                            sock.connect((destination, port))
                            sock.send(payload)
                            entry["errno"] = 0
                    except OSError as exc:
                        entry["errno"] = exc.errno
                    entry["source_port"] = sock.getsockname()[1]
                    entry["source_address"] = sock.getsockname()[0]
                    entry["finished_ns"] = time.monotonic_ns()
                emit(entry)
        sequence += 1
        done.wait(max(0, INTERVAL - (time.monotonic() - started)))
    emit({"kind": "finished", "run_id": run_id, "sequences": sequence})


class Recorder:
    """Own a continuously running ordinary process and root-only phase beacons."""

    def __init__(self, directory: Path, interface: str, user: str):
        directory.mkdir(mode=0o700)
        self.directory = directory
        self.run_id = secrets.token_hex(8)
        self.interface = interface
        self.mac = bytes.fromhex(Path(f"/sys/class/net/{interface}/address").read_text().strip().replace(":", ""))
        identity = pwd.getpwnam(user)
        self.log = (directory / "stimulus.jsonl").open("w")
        self.events = (directory / "events.jsonl").open("w")
        # The checked-out tree may be root-readable only. Pass this trusted
        # fixture through an inherited descriptor instead of making the tree
        # readable to the ordinary actor or requiring it to open a root path.
        with Path(__file__).open("rb") as source:
            self.process = subprocess.Popen(
                [sys.executable, "-", "probe", self.run_id],
                user=identity.pw_uid,
                group=identity.pw_gid,
                extra_groups=[],
                stdin=source,
                stdout=self.log,
                stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + 5
        try:
            while True:
                lines = (directory / "stimulus.jsonl").read_text().splitlines()
                if lines and json.loads(lines[0]).get("kind") == "ready":
                    break
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Continuous chaos stimulus did not become ready")
                time.sleep(0.05)
            self.marker("capture-open", mac=self.mac.hex())
        except BaseException:
            with contextlib.suppress(RuntimeError):
                self.stop()
            raise

    def marker(self, kind: str, **fields):
        if self.process.poll() is not None:
            raise RuntimeError("Continuous chaos stimulus exited unexpectedly")
        data = {"kind": kind, "run_id": self.run_id, "monotonic_ns": time.monotonic_ns(), **fields}
        payload = MARKER_PREFIX + json.dumps(data, sort_keys=True).encode()
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
            sock.bind((self.interface, 0))
            sock.send(bytes.fromhex("ffffffffffff") + self.mac + b"\x88\xb5" + payload)
        self.events.write(json.dumps(data) + "\n")
        self.events.flush()

    def control(self, name: str, *, after_stop: bool = False):
        # Link flap can leave SLAAC/DAD pending after intentional stop. Wait
        # only before the unprotected calibration; never pause fault sampling
        # or manufacture a route to turn a missing family into a clean result.
        self.marker("control-settle", name=name)
        if after_stop:
            # Discovery attempts during a protected link flap can have been
            # rejected. Ask the VM's actual router again after explicit release;
            # do not install a route/address or alter protected fault sampling.
            solicit_control_router(self.interface, self.mac)
            self.marker("control-router-solicitation", name=name)
        paths = wait_control_paths(self.interface)
        self.marker("control-start", name=name, paths=paths)
        time.sleep(1)
        self.marker("control-end", name=name)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.events.close()
        if self.process.returncode != 0:
            raise RuntimeError("Continuous chaos stimulus did not finish cleanly")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "probe":
        probe(sys.argv[2])
    else:
        raise SystemExit("Use scripts/vm/lifecycle/chaos.sh")
