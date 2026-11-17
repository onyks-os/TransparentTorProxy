# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Redirected TCP sockets must not outlive the rules that redirected them.

An orphaned socket of a connection TTP redirected to Tor's TransPort keeps
retransmitting after `ttp stop`. Without the redirect and filter rules its
next segment leaves the physical interface towards the original destination
(observed with an external capture in the VPN VM qualification).
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ttp.firewall import redirected

DST_NAT = 1 << 5


def attr(kind: int, payload: bytes, *, nested: bool = False) -> bytes:
    header = struct.pack("=HH", 4 + len(payload), kind | (0x8000 if nested else 0))
    return header + payload + bytes(-len(payload) % 4)


def flow_tuple(src: str, dst: str, sport: int, dport: int, proto: int = 6) -> bytes:
    family = socket.AF_INET6 if ":" in src else socket.AF_INET
    kinds = (3, 4) if family == socket.AF_INET6 else (1, 2)
    ip = attr(kinds[0], socket.inet_pton(family, src)) + attr(kinds[1], socket.inet_pton(family, dst))
    ports = attr(1, bytes([proto])) + attr(2, struct.pack("!H", sport)) + attr(3, struct.pack("!H", dport))
    return attr(1, ip, nested=True) + attr(2, ports, nested=True)


def conntrack(orig: bytes, reply: bytes, status: int, family: int = socket.AF_INET) -> bytes:
    body = struct.pack("=BBH", family, 0, 0)
    body += attr(1, orig, nested=True) + attr(2, reply, nested=True) + attr(3, struct.pack("!I", status))
    return struct.pack("=IHHII", 16 + len(body), 0x0100, 2, 1, 0) + body


def done() -> bytes:
    return struct.pack("=IHHII", 20, 3, 2, 1, 0) + struct.pack("=i", 0)


REDIRECTED_V4 = conntrack(
    flow_tuple("172.31.250.20", "198.51.100.7", 51028, 8000),
    flow_tuple("127.0.0.1", "172.31.250.20", 9041, 51028),
    DST_NAT | 0b1110,
)
REDIRECTED_V6 = conntrack(
    flow_tuple("fd31:250::20", "2001:db8:100::7", 54490, 8000),
    flow_tuple("::1", "fd31:250::20", 9041, 54490),
    DST_NAT | 0b1110,
    socket.AF_INET6,
)


def test_only_tcp_redirected_to_the_local_transport_port_is_selected():
    unrelated = [
        # DNS redirected to the DNSPort is UDP: nothing retransmits it.
        conntrack(
            flow_tuple("172.31.250.20", "1.1.1.1", 40000, 53, 17),
            flow_tuple("127.0.0.1", "172.31.250.20", 9054, 40000, 17),
            DST_NAT,
        ),
        # An inbound SSH session was never redirected.
        conntrack(
            flow_tuple("192.168.1.5", "192.168.1.9", 50000, 22),
            flow_tuple("192.168.1.9", "192.168.1.5", 22, 50000),
            0b1110,
        ),
        # Another tool's DNAT to a different local port.
        conntrack(
            flow_tuple("172.31.250.20", "203.0.113.1", 40001, 80),
            flow_tuple("127.0.0.1", "172.31.250.20", 9050, 40001),
            DST_NAT,
        ),
        # DNAT to a remote host is not TTP's redirect.
        conntrack(
            flow_tuple("172.31.250.20", "203.0.113.1", 40002, 80),
            flow_tuple("10.0.0.9", "172.31.250.20", 9041, 40002),
            DST_NAT,
        ),
        # A direct local client of the TransPort was not translated.
        conntrack(
            flow_tuple("127.0.0.1", "127.0.0.1", 40003, 9041),
            flow_tuple("127.0.0.1", "127.0.0.1", 9041, 40003),
            0b1110,
        ),
    ]
    data = REDIRECTED_V4 + b"".join(unrelated) + REDIRECTED_V6 + done()
    # Both ends of each connection: the application's socket and Tor's accepted
    # TransPort socket. Tor's end, orphaned when Tor stops, keeps retransmitting
    # to the application; the host's RST answer then left with a stale NAT
    # destination (::1) once the rules were gone (VPN VM capture, IPv6).
    assert redirected.flows_from_dump(redirected.parse_messages(data), {9041}) == [
        redirected.Flow(socket.AF_INET, "172.31.250.20", 51028, "198.51.100.7", 8000),
        redirected.Flow(socket.AF_INET, "127.0.0.1", 9041, "172.31.250.20", 51028),
        redirected.Flow(socket.AF_INET6, "fd31:250::20", 54490, "2001:db8:100::7", 8000),
        redirected.Flow(socket.AF_INET6, "::1", 9041, "fd31:250::20", 54490),
    ]


def test_a_dump_error_is_not_an_empty_table():
    error = struct.pack("=IHHII", 36, 2, 0, 1, 0) + struct.pack("=i", -1) + bytes(16)
    with pytest.raises(OSError):
        redirected.flows_from_dump(redirected.parse_messages(REDIRECTED_V4 + error), {9041})


@pytest.mark.parametrize("cut", [1, 7, 19, 21])  # 20 removes exactly the DONE message
def test_a_truncated_dump_is_refused(cut):
    with pytest.raises(ValueError):
        redirected.parse_messages((REDIRECTED_V4 + done())[:-cut])


def test_a_dump_without_its_end_marker_is_refused():
    with pytest.raises(ValueError):
        redirected.flows_from_dump(redirected.parse_messages(REDIRECTED_V4), {9041})


def test_socket_identity_request_matches_the_kernel_layout():
    request = redirected.socket_request(redirected.Flow(socket.AF_INET6, "fd31:250::20", 54490, "::1", 9041))
    assert len(request) == 56  # struct inet_diag_req_v2
    family, protocol = struct.unpack_from("=BB", request)
    sport, dport = struct.unpack_from("!HH", request, 8)
    assert (family, protocol, sport, dport) == (socket.AF_INET6, socket.IPPROTO_TCP, 54490, 9041)
    assert request[12:28] == socket.inet_pton(socket.AF_INET6, "fd31:250::20")
    assert request[-8:] == b"\xff" * 8  # INET_DIAG_NOCOOKIE
    v4 = redirected.socket_request(redirected.Flow(socket.AF_INET, "10.0.0.2", 1, "10.0.0.3", 2))
    assert v4[12:28] == socket.inet_aton("10.0.0.2") + bytes(12)


class Kernel:
    """Fake netlink side: sockets disappear when destroyed or when they time out."""

    def __init__(self, flows, *, destroy_error=None, survives=(), dies_after=None):
        self.flows = list(flows)
        self.alive = set(flows)
        self.destroy_error = destroy_error
        self.survives = set(survives)
        self.dies_after = dies_after
        self.destroyed = []
        self.now = 0.0

    def dump(self, ports):
        assert ports == {9041}
        return list(self.flows)

    def destroy(self, flow):
        self.destroyed.append(flow)
        if self.destroy_error:
            raise self.destroy_error
        if flow not in self.survives:
            self.alive.discard(flow)

    def exists(self, flow):
        if self.dies_after is not None and self.now >= self.dies_after:
            self.alive.clear()
        return flow in self.alive

    def sleep(self, seconds):
        self.now += seconds

    def install(self, monkeypatch):
        monkeypatch.setattr(redirected, "_dump_flows", self.dump)
        monkeypatch.setattr(redirected, "_destroy", self.destroy)
        monkeypatch.setattr(redirected, "_exists", self.exists)
        monkeypatch.setattr(redirected.time, "sleep", self.sleep)
        monkeypatch.setattr(redirected.time, "monotonic", lambda: self.now)


A = redirected.Flow(socket.AF_INET, "172.31.250.20", 51028, "198.51.100.7", 8000)
B = redirected.Flow(socket.AF_INET6, "fd31:250::20", 54490, "2001:db8:100::7", 8000)


pytestmark = pytest.mark.real_redirected_sockets


def test_every_redirected_socket_is_destroyed_and_verified_gone(monkeypatch):
    kernel = Kernel([A, B])
    kernel.install(monkeypatch)
    assert redirected.close_redirected_sockets(9041) == 2
    assert kernel.destroyed == [A, B] and not kernel.alive


def test_nothing_to_close_is_a_clean_success(monkeypatch):
    Kernel([]).install(monkeypatch)
    assert redirected.close_redirected_sockets(9041) == 0


def test_without_sock_destroy_a_bounded_wait_lets_orphans_expire(monkeypatch):
    import errno

    kernel = Kernel([A], destroy_error=OSError(errno.EOPNOTSUPP, "unsupported"), dies_after=4.0)
    kernel.install(monkeypatch)
    assert redirected.close_redirected_sockets(9041) == 1
    assert 4.0 <= kernel.now < redirected.WAIT_SECONDS


@pytest.mark.parametrize(
    "kernel",
    [
        Kernel([A, B], survives=[B]),
        Kernel([A], destroy_error=OSError(95, "unsupported")),
    ],
    ids=["survivor", "unsupported"],
)
def test_a_socket_that_remains_retains_protection(monkeypatch, kernel):
    kernel.install(monkeypatch)
    with pytest.raises(redirected.RedirectedSocketsRemain, match="1 redirected TCP connection"):
        redirected.close_redirected_sockets(9041)
    assert kernel.now >= redirected.WAIT_SECONDS


@pytest.mark.parametrize("failure", [OSError(1, "not permitted"), ValueError("bad dump")])
def test_unreadable_connection_tracking_retains_protection(monkeypatch, failure):
    def broken(ports):
        raise failure

    monkeypatch.setattr(redirected, "_dump_flows", broken)
    with pytest.raises(redirected.RedirectedSocketsRemain, match="cannot be enumerated"):
        redirected.close_redirected_sockets(9041)


def _user_namespaces_work() -> bool:
    if shutil.which("unshare") is None or shutil.which("nft") is None:
        return False
    probe = subprocess.run(
        ["unshare", "-rn", "nft", "list", "tables"], capture_output=True, text=True, timeout=10, check=False
    )
    return probe.returncode == 0


ORPHAN = textwrap.dedent(
    """
    import socket, subprocess, sys, time
    from ttp.firewall import redirected

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "198.51.100.7/32", "dev", "lo"], check=True)
    subprocess.run(["ip", "-6", "addr", "add", "2001:db8:100::7/128", "dev", "lo", "nodad"], check=True)
    subprocess.run(["nft", "-f", "-"], check=True, text=True, input='''
    table inet t {
      chain out { type nat hook output priority -100;
        ip daddr 198.51.100.7 tcp dport 8000 redirect to :9041
        ip6 daddr 2001:db8:100::7 tcp dport 8000 redirect to :9041
      }
    }''')
    tor = []
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        listener = socket.socket(family)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        listener.bind((host, 9041))
        listener.listen()
        tor.append(listener)
    ports = []
    for family, target in ((socket.AF_INET, "198.51.100.7"), (socket.AF_INET6, "2001:db8:100::7")):
        client = socket.socket(family)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        client.connect((target, 8000))
        client.setblocking(False)
        try:
            while True:
                client.send(b"x" * 65536)
        except BlockingIOError:
            pass
        ports.append(client.getsockname()[1])
        client.close()  # unread data and a zero window: an orphan in FIN-WAIT-1
    # Tor's accepted ends stay open and unread; both ends must be destroyed.
    accepted = [listener.accept()[0] for listener in tor]
    time.sleep(0.5)

    def orphans():
        out = subprocess.run(["ss", "-Htan"], capture_output=True, text=True, check=True).stdout
        return [
            line for line in out.splitlines()
            if not line.startswith("LISTEN")
            and any(column.endswith(f":{port}") for column in line.split()[3:5] for port in ports)
        ]

    before = orphans()
    print("before", before)
    assert sum(line.startswith("FIN-WAIT-1") for line in before) == 2, before
    assert sum(line.startswith("ESTAB") for line in before) == 2, before
    closed = redirected.close_redirected_sockets(9041)
    print("closed", closed, "remaining", orphans())
    assert closed == 4 and orphans() == []
    """
)


@pytest.mark.skipif(not _user_namespaces_work(), reason="needs unprivileged user+network namespaces with nftables")
def test_real_kernel_orphans_are_destroyed_while_redirected():
    """Against the running kernel, in a throwaway user and network namespace."""
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["unshare", "-rn", sys.executable, "-c", ORPHAN],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "PYTHONPATH": str(root)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "closed 4 remaining []" in result.stdout


class FakeNetlink:
    """Records the request and replays kernel replies in fixed-size reads."""

    def __init__(self, *reads: bytes):
        self.reads = list(reads)
        self.sent = b""
        self.opened = None

    def __call__(self, family, kind, protocol):
        self.opened = (family, kind, protocol)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def bind(self, address):
        assert address == (0, 0)

    def send(self, data):
        self.sent = data

    def recv(self, size):
        return self.reads.pop(0)


def ack(code: int, kind: int = 2) -> bytes:
    return struct.pack("=IHHII", 36, kind, 0, 1, 0) + struct.pack("=i", code) + bytes(16)


def diag(state: int) -> bytes:
    body = bytes([socket.AF_INET, state]) + bytes(70)
    return struct.pack("=IHHII", 16 + len(body), 20, 0, 1, 0) + body


def test_conntrack_dump_request_and_multi_read_reply(monkeypatch):
    # Real dumps arrive over several reads; each read holds whole messages.
    fake = FakeNetlink(REDIRECTED_V4, REDIRECTED_V6 + done())
    monkeypatch.setattr(redirected.socket, "socket", fake)
    assert redirected._dump_flows({9041})[::2] == [A, B]
    assert fake.opened == (socket.AF_NETLINK, socket.SOCK_RAW, redirected.NETLINK_NETFILTER)
    length, kind, flags = struct.unpack_from("=IHH", fake.sent)
    assert (length, kind, flags) == (20, 0x0101, 0x301)


@pytest.mark.parametrize(("code", "raises"), [(0, None), (-2, None), (-95, OSError), (-1, OSError)])
def test_destroy_accepts_success_or_already_gone(monkeypatch, code, raises):
    fake = FakeNetlink(ack(code))
    monkeypatch.setattr(redirected.socket, "socket", fake)
    if raises:
        with pytest.raises(raises):
            redirected._destroy(A)
    else:
        redirected._destroy(A)
    assert fake.opened[2] == redirected.NETLINK_SOCK_DIAG
    assert struct.unpack_from("=HH", fake.sent, 4) == (redirected.SOCK_DESTROY, 0x5)
    assert fake.sent[16:] == redirected.socket_request(A)


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (diag(4), True),  # FIN-WAIT-1 still retransmits
        (diag(1), True),  # ESTABLISHED
        (diag(redirected.TCP_TIME_WAIT), False),
        (ack(-2), False),  # ENOENT: gone
    ],
)
def test_exists_reports_only_live_sockets(monkeypatch, reply, expected):
    monkeypatch.setattr(redirected.socket, "socket", FakeNetlink(reply))
    assert redirected._exists(B) is expected


@pytest.mark.parametrize("reply", [ack(0), ack(-1)])
def test_an_ambiguous_lookup_is_never_absence(monkeypatch, reply):
    monkeypatch.setattr(redirected.socket, "socket", FakeNetlink(reply))
    with pytest.raises(OSError):
        redirected._exists(B)


def test_a_verification_failure_retains_protection(monkeypatch):
    kernel = Kernel([A])
    kernel.install(monkeypatch)

    def unreadable(flow):
        raise OSError(1, "not permitted")

    monkeypatch.setattr(redirected, "_exists", unreadable)
    with pytest.raises(redirected.RedirectedSocketsRemain, match="cannot be verified closed"):
        redirected.close_redirected_sockets(9041)


def test_an_acknowledgement_inside_a_dump_is_not_an_error():
    messages = redirected.parse_messages(ack(0) + REDIRECTED_V4 + done())
    assert redirected.flows_from_dump(messages, {9041})[0] == A


def test_a_truncated_attribute_is_refused():
    body = struct.pack("=BBH", socket.AF_INET, 0, 0) + struct.pack("=HH", 64, 1) + bytes(8)
    message = struct.pack("=IHHII", 16 + len(body), 0x0100, 2, 1, 0) + body
    with pytest.raises(ValueError, match="attribute"):
        redirected.flows_from_dump(redirected.parse_messages(message + done()), {9041})
