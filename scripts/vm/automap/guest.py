# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""E01: real onion automapping, only inside an explicitly disposable VM.

Root owns the fixture and non-IP phase markers; every probe runs as nobody
without supplementary groups or effective capabilities. Controls deliberately
remove enforcement, and are never labelled protected intervals.
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from stem.control import Controller

PROBE = r"""
import json, os, socket, sys
mode, address, token, budget = sys.argv[1:]
caps = int(next(line.split()[1] for line in open('/proc/self/status') if line.startswith('CapEff:')), 16)
if os.geteuid() != 65534 or os.getegid() != 65534 or os.getgroups() or caps:
    raise RuntimeError('Probe identity is not ordinary')
family = socket.AF_INET6 if ':' in address else socket.AF_INET
result = dict(mode=mode, address=address, uid=os.geteuid(), gid=os.getegid(), cap_eff=caps, groups=[], attempted=False)
with socket.socket(family, socket.SOCK_DGRAM if mode == 'udp' else socket.SOCK_STREAM) as sock:
    sock.settimeout(float(budget))
    try:
        result['attempted'] = True
        sock.connect((address, 19302 if mode == 'udp' else 80))
        if mode == 'udp':
            sock.send(token.encode())
        else:
            sock.sendall(b'GET / HTTP/1.0\r\nHost: e01\r\n\r\n')
            answer = b''
            while chunk := sock.recv(4096):
                answer += chunk
                if len(answer) > 16384:
                    raise RuntimeError('Oversized fixture response')
            result['nonce_ok'] = answer.startswith(b'HTTP/1.0 200 ') and answer.endswith(token.split(':')[1].encode())
    except OSError as exc:
        result.update(errno=exc.errno, error=str(exc))
    finally:
        result['source_port'] = sock.getsockname()[1]
print(json.dumps(result))
"""


def resolve_mapping(name: str, qtype: int) -> str:
    """Read Tor's single A/AAAA automap answer, rejecting incomplete responses."""
    ident = os.urandom(2)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
    query = ident + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect(("127.0.0.1", 9054))
        sock.send(query)
        data = sock.recv(4096)
    if len(data) < 12:
        raise ValueError("Truncated DNS header")
    _, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12 + len(question)
    if (
        data[:2] != ident
        or flags & 0x820F != 0x8000
        or questions != 1
        or answers != 1
        or data[12:offset] != question
        or data[offset : offset + 2] != b"\xc0\x0c"
        or len(data) < offset + 12
    ):
        raise ValueError("Invalid or unsupported Tor DNS answer")
    typ, klass, _, size = struct.unpack("!HHIH", data[offset + 2 : offset + 12])
    if typ != qtype or klass != 1 or size != (4 if qtype == 1 else 16) or len(data) < offset + 12 + size:
        raise ValueError("Invalid automap address")
    return str(ipaddress.ip_address(data[offset + 12 : offset + 12 + size]))


class Experiment:
    def __init__(self):
        self.run = uuid.uuid4().hex
        self.iface = json.loads(subprocess.check_output(["ip", "-j", "route", "get", "198.51.100.7"]))[0]["dev"]
        self.mac = bytes.fromhex(Path(f"/sys/class/net/{self.iface}/address").read_text().strip().replace(":", ""))

    def emit(self, kind, **fields):
        print(json.dumps(dict(kind=kind, run=self.run, **fields)), flush=True)

    def marker(self, tag):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
            sock.bind((self.iface, 0))
            sock.send(b"\xff" * 6 + self.mac + b"\x88\xb5" + f"E01:{self.run}:{tag}".encode())
        self.emit("marker", tag=tag)

    def command(self, argv, *, input=None):
        result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=420)
        self.emit("command", argv=argv, rc=result.returncode, output=result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"Command failed: {argv!r}")
        return result.stdout

    def probe(self, address, mode, phase, profile, repeat):
        family = ipaddress.ip_address(address).version
        tag = f"{profile}-{phase}-v{family}-{mode}-{repeat}"
        token = f"E01:{self.run}:{tag}"
        self.marker(tag + "-before")
        result = subprocess.run(
            [sys.executable, "-c", PROBE, mode, address, token, "45" if phase == "protected" else "2"],
            user=65534,
            group=65534,
            extra_groups=[],
            capture_output=True,
            text=True,
            timeout=50,
        )
        if result.returncode:
            raise RuntimeError(f"Probe failed: {result.stderr}")
        self.emit(
            "probe",
            tag=tag,
            profile=profile,
            phase=phase,
            repeat=repeat,
            family=family,
            token=token,
            **json.loads(result.stdout),
        )
        self.marker(tag + "-after")

    def load(self, rules):
        self.command(["nft", "-f", "-"], input="delete table inet ttp\n" + rules)

    def profile(self, profile):
        argv = ["ttp", "start", "--no-watchdog", "--bootstrap-timeout", "300"]
        if profile == "strict":
            argv.append("--no-lan-bypass")
        self.command(argv)
        with Controller.from_socket_file("/run/tor/ttp/control.sock") as controller:
            controller.authenticate()
            onion = (
                controller.create_ephemeral_hidden_service(
                    {80: "127.0.0.1:18080"},
                    key_type="NEW",
                    key_content="ED25519-V3",
                    discard_key=True,
                    await_publication=True,
                    timeout=180,
                ).service_id
                + ".onion"
            )
            addresses = []
            for qtype in (1, 28):
                address = resolve_mapping(onion, qtype)
                reused = resolve_mapping(onion, qtype)
                if address != reused:
                    raise RuntimeError("Automap did not reuse its mapping")
                addresses.append(address)
                self.emit("mapping", profile=profile, onion=onion, qtype=qtype, address=address, reused=reused)
            rules = self.command(["nft", "list", "table", "inet", "ttp"])
            for phase in ("control-pre", "protected", "mutant", "control-post"):
                if phase == "mutant" and profile != "lan":
                    continue
                if phase.startswith("control"):
                    self.command(["nft", "delete", "table", "inet", "ttp"])
                elif phase == "mutant":
                    mutant = "\n".join(line for line in rules.splitlines() if 'comment "ttp automap ' not in line)
                    if mutant == rules.rstrip("\n"):
                        raise RuntimeError("Targeted automap mutation removed no rules")
                    self.load(mutant)
                for repeat in range(2 if phase == "protected" else 1):
                    for address in addresses:
                        for mode in ("tcp", "udp"):
                            self.probe(address, mode, phase, profile, repeat)
                if phase.startswith("control"):
                    self.command(["nft", "-f", "-"], input=rules)
                elif phase == "mutant":
                    self.load(rules)
        self.command(["ttp", "stop"])


def main():
    if os.environ.get("TTP_DISPOSABLE_VM") != "1" or os.geteuid() != 0:
        raise RuntimeError("Run only as root inside an explicitly disposable VM")
    experiment = Experiment()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = experiment.run.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        experiment.emit(
            "ready",
            profiles=["strict", "lan"],
            source=subprocess.check_output(["sha256sum", __file__], text=True).split()[0],
        )
        try:
            for profile in ("strict", "lan"):
                experiment.profile(profile)
        finally:
            try:
                experiment.command(["ttp", "stop", "--restore-only"])
            finally:
                server.shutdown()
                worker.join(timeout=5)
        experiment.marker("finished")
        experiment.emit("finished")


if __name__ == "__main__":
    main()
