# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""The external observer must fail closed on missing or ambiguous evidence."""

import importlib.util
import socket
import struct
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


def test_ipv6_and_unknown_ethernet_are_not_silently_skipped(tmp_path):
    for kind in (b"\x86\xdd", b"\x81\x00"):
        result = inspect(capture(tmp_path, OTHER + CLIENT + kind + bytes(40)))
        assert result["violations"]


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
