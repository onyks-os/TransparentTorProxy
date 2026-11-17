# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""The external observer must fail closed on missing or ambiguous evidence."""

import hashlib
import importlib.util
import json
import shutil
import socket
import struct
import subprocess
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "vpn_vm_qemu", Path(__file__).resolve().parents[1] / "scripts/vm/vpn/qemu.py"
)
assert _spec and _spec.loader
qemu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qemu)
CLIENT = bytes.fromhex("525400123402")
OTHER = bytes.fromhex("525400123401")
ENDPOINT6 = "fd31:250::1"


def packet(*, dst="172.31.250.1", port=51820, source=CLIENT, proto=17, fragment=0):
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        0,
        fragment,
        64,
        proto,
        0,
        socket.inet_aton("172.31.250.20"),
        socket.inet_aton(dst),
    )
    return OTHER + source + b"\x08\x00" + ip + struct.pack("!HHHH", 51820, port, 8, 0)


def capture(tmp_path, *frames):
    path = tmp_path / "external.pcap"
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 768, 1)
    for frame in frames:
        data += struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    path.write_bytes(data)
    return path


def inspect(path):
    return qemu.inspect_capture(path, client_mac=CLIENT, endpoint="172.31.250.1")


def test_exact_transport_and_peer_replies(tmp_path):
    result = inspect(capture(tmp_path, packet(), packet(source=OTHER, dst="172.31.250.20")))
    assert result == {"counts": {"outgoing": 1, "wireguard": 1}, "violations": {}}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dst": "198.51.100.7", "proto": 6, "port": 8000},  # reachable leak canary
        {"port": 53},  # clear DNS to the correct host still fails
        {"dst": "1.1.1.1"},  # the right port at the wrong endpoint still fails
        {"proto": 6},  # TCP at the right endpoint/port still fails
        {"fragment": 1},  # fragment cannot masquerade as a UDP header
    ],
)
def test_forbidden_packets_are_detected(tmp_path, kwargs):
    result = inspect(capture(tmp_path, packet(), packet(**kwargs)))
    assert result["violations"]


def test_unknown_ethernet_is_not_silently_skipped(tmp_path):
    result = inspect(capture(tmp_path, OTHER + CLIENT + b"\x81\x00" + bytes(40)))
    assert result["violations"]


def test_ipv6_payload_on_an_ipv4_endpoint_is_a_violation(tmp_path):
    result = inspect(capture(tmp_path, packet(), packet6(dst="fd31:250::1")))
    assert result["violations"] == {"fd31:250::1/proto17/port51820": 1}


def packet6(*, dst=ENDPOINT6, header=17, hops=64, payload=None, source=CLIENT, dport=51820, sport=51820):
    if payload is None:
        payload = struct.pack("!HHHH", sport, dport, 8, 0) if header in (6, 17) else b""
    ip = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        header,
        hops,
        socket.inet_pton(socket.AF_INET6, "fd31:250::20"),
        socket.inet_pton(socket.AF_INET6, dst),
    )
    return OTHER + source + b"\x86\xdd" + ip + payload


def inspect6(path):
    return qemu.inspect_capture(path, client_mac=CLIENT, endpoint=ENDPOINT6, dhcp_server="172.31.250.1")


def icmp6(kind):
    return bytes([kind, 0]) + bytes(22)


def test_ipv6_endpoint_and_guard_control_exceptions_are_accepted(tmp_path):
    frames = (
        packet6(),
        packet6(dst="ff02::2", header=58, hops=255, payload=icmp6(133)),
        packet6(dst="ff02::1:ff00:1", header=58, hops=255, payload=icmp6(135)),
        packet6(dst="fe80::1", header=58, hops=255, payload=icmp6(136)),
        packet6(dst="ff02::1:2", sport=546, dport=547),
        dhcp(),
    )
    result = inspect6(capture(tmp_path, *frames))
    assert result["violations"] == {}
    assert result["counts"] == {
        "outgoing": 6,
        "wireguard": 1,
        "ndp": 3,
        "dhcpv6": 1,
        "dhcp": 1,
        "dhcp_renewals_acknowledged": 0,
    }


@pytest.mark.parametrize(
    ("kwargs", "key"),
    [
        ({"dst": "2001:db8:100::7", "header": 6, "dport": 8000}, "2001:db8:100::7/proto6/port8000"),
        ({"dport": 53}, "fd31:250::1/proto17/port53"),
        ({"dst": "fd31:250::2"}, "fd31:250::2/proto17/port51820"),
        ({"header": 6}, "fd31:250::1/proto6/port51820"),
        # A fragment header cannot masquerade as the WireGuard UDP header.
        ({"header": 44, "payload": bytes([17, 0, 0, 1]) + bytes(12)}, "fd31:250::1/proto44"),
        # MLD reports use hop-by-hop options and are outside the guard.
        ({"dst": "ff02::16", "header": 0, "payload": bytes(8)}, "ff02::16/proto0"),
        # Neighbor discovery is accepted only with hop limit 255, never echo.
        ({"dst": "fe80::1", "header": 58, "hops": 64, "payload": icmp6(135)}, "fe80::1/proto58/type135"),
        ({"dst": "fe80::1", "header": 58, "hops": 255, "payload": icmp6(128)}, "fe80::1/proto58/type128"),
        ({"dst": "ff02::1:2", "sport": 547, "dport": 546}, "ff02::1:2/proto17/port546"),
    ],
)
def test_forbidden_ipv6_packets_are_detected(tmp_path, kwargs, key):
    result = inspect6(capture(tmp_path, packet6(), packet6(**kwargs)))
    assert result["violations"] == {key: 1}


def test_ipv4_wireguard_to_the_old_endpoint_fails_an_ipv6_underlay(tmp_path):
    result = inspect6(capture(tmp_path, packet6(), packet()))
    assert result["violations"] == {"172.31.250.1/proto17/port51820": 1}


@pytest.mark.parametrize(
    "frame",
    [
        OTHER + CLIENT + b"\x86\xdd" + bytes(40),  # version 0
        OTHER + CLIENT + b"\x86\xdd" + bytes([0x60]) + bytes(20),  # truncated header
        packet6(payload=b"\x00\x01"),  # truncated UDP header
        packet6(header=58, payload=b""),  # missing ICMPv6 type
    ],
)
def test_malformed_ipv6_is_inconclusive(tmp_path, frame):
    with pytest.raises(ValueError):
        inspect6(capture(tmp_path, packet6(), frame))


def dhcp6(kind, xid=b"\x00\x00\x2a", *, reply=False):
    message = bytes([kind]) + xid + bytes(8)
    udp = struct.pack("!HHHH", *((547, 546) if reply else (546, 547)), 8 + len(message), 0) + message
    destination = "fd31:250::20" if reply else "ff02::1:2"
    frame = packet6(dst=destination, payload=udp, source=OTHER if reply else CLIENT)
    return frame if not reply else CLIENT + frame[6:]


def test_dhcpv6_renewal_needs_a_matching_reply(tmp_path):
    result = inspect6(capture(tmp_path, dhcp6(5), dhcp6(7, reply=True)))
    assert result["counts"]["dhcpv6_renewals_acknowledged"] == 1
    assert not result["violations"]
    result = inspect6(capture(tmp_path, dhcp6(5), dhcp6(7, b"\x00\x00\x2b", reply=True)))
    assert result["counts"]["dhcpv6_renewals_acknowledged"] == 0
    # A Rebind (sent when the server's unicast Renew went unanswered) counts.
    result = inspect6(capture(tmp_path, dhcp6(6), dhcp6(7, reply=True)))
    assert result["counts"]["dhcpv6_renewals_acknowledged"] == 1
    # A Solicit/Request is the initial lease, not a renewal of a bound one.
    result = inspect6(capture(tmp_path, dhcp6(1), dhcp6(7, reply=True)))
    assert "dhcpv6_renewals_acknowledged" not in result["counts"]


@pytest.mark.parametrize("content", [b"", b"invalid", b"\xd4\xc3\xb2\xa1" + bytes(20)])
def test_missing_or_unsupported_capture_is_inconclusive(tmp_path, content):
    path = tmp_path / "broken.pcap"
    path.write_bytes(content)
    with pytest.raises(ValueError):
        inspect(path)


def test_empty_and_reply_only_capture_cannot_pass(tmp_path):
    for frames in ((), (packet(source=OTHER),)):
        with pytest.raises(ValueError, match="inconclusive"):
            inspect(capture(tmp_path, *frames))


@pytest.mark.parametrize("remove", [1, 20, 50])
def test_truncation_is_not_a_clean_capture(tmp_path, remove):
    path = capture(tmp_path, packet())
    path.write_bytes(path.read_bytes()[:-remove])
    with pytest.raises(ValueError):
        inspect(path)


def dhcp(*, reply=False, xid=42, bound=True):
    bootp = bytearray(240)
    bootp[0:3] = bytes([2 if reply else 1, 1, 6])
    bootp[4:8] = struct.pack("!I", xid)
    bootp[12:16] = socket.inet_aton("172.31.250.20") if bound else bytes(4)
    bootp[28:34] = CLIENT
    bootp[236:240] = bytes.fromhex("63825363")
    bootp += bytes([53, 1, 5 if reply else 3, 255])
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28 + len(bootp),
        0,
        0,
        64,
        17,
        0,
        socket.inet_aton("172.31.250.1" if reply else "172.31.250.20"),
        socket.inet_aton("172.31.250.20" if reply else "172.31.250.1"),
    )
    ports = (67, 68) if reply else (68, 67)
    return (
        OTHER
        + (OTHER if reply else CLIENT)
        + b"\x08\x00"
        + ip
        + struct.pack("!HHHH", *ports, len(bootp) + 8, 0)
        + bootp
    )


def test_dhcp_renewal_needs_a_matching_ack(tmp_path):
    result = inspect(capture(tmp_path, dhcp(), dhcp(reply=True)))
    assert result["counts"]["dhcp_renewals_acknowledged"] == 1
    assert not result["violations"]
    result = inspect(capture(tmp_path, dhcp(), dhcp(reply=True, xid=43)))
    assert result["counts"]["dhcp_renewals_acknowledged"] == 0


def test_initial_address_request_does_not_qualify_as_renewal(tmp_path):
    result = inspect(capture(tmp_path, dhcp(bound=False), dhcp(reply=True)))
    assert not result["counts"].get("dhcp_renewals_acknowledged")


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img is required for real disk checks")
@pytest.mark.parametrize("size", [3 * 1024**3, 64 * 1024**3])
def test_disposable_overlay_preserves_large_base_and_original_bytes(tmp_path, size):
    base, overlay = tmp_path / "original.qcow2", tmp_path / "disposable.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(base), str(size)], check=True)
    original_digest = hashlib.sha256(base.read_bytes()).digest()
    qemu.create_overlay(base, overlay)
    response = subprocess.run(
        ["qemu-img", "info", "--output=json", str(overlay)], check=True, capture_output=True, text=True
    )
    info = json.loads(response.stdout)
    assert info["virtual-size"] >= size
    assert Path(info["backing-filename"]) == base
    assert hashlib.sha256(base.read_bytes()).digest() == original_digest
