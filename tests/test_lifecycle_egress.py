# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""O02 for the lifecycle VM's capture reader: no damaged capture reads as clean.

``scripts/vm/lifecycle/run.sh`` passes a contained scenario when
``egress.py --hits`` prints 0. Every case below is a capture that would once
have printed 0 -- or a wrong port -- without having seen what the verdict is
about, and must now be inconclusive or parsed correctly instead.

The pcaps are built here byte by byte: the reader uses only the standard
library, and so does its test.
"""

from __future__ import annotations

import ipaddress
import struct

import pytest

from scripts.vm.lifecycle import egress

PROBE = "198.51.100.7"
GUEST, GATEWAY = "10.0.2.15", "10.0.2.2"
GUEST_V6 = "fec0::5054:ff:fe12:3456"


@pytest.fixture(autouse=True)
def _default_subnet():
    egress.use_subnet("10.0.2.0/24")


def ether(ethertype: int, payload: bytes) -> bytes:
    return b"\x52\x55\x0a\x00\x02\x02" + b"\x52\x54\x00\x12\x34\x56" + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, l4: bytes, *, fragment_offset: int = 0) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(l4),
        1,
        fragment_offset,
        64,
        proto,
        0,
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    return ether(0x0800, header + l4)


def ipv6(src: str, dst: str, next_header: int, rest: bytes) -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(rest), next_header, 64)
    return ether(0x86DD, header + ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + rest)


def ports(sport: int, dport: int) -> bytes:
    return struct.pack("!HH", sport, dport) + bytes(16)


def probe_udp() -> bytes:
    return ipv4(GUEST, PROBE, 17, ports(40000, 53))


def ssh_control() -> bytes:
    return ipv4(GUEST, GATEWAY, 6, ports(22, 50000))


def pcap(frames, *, snaplen: int = 65535, linktype: int = 1, cut: int = 0, orig_extra: int = 0) -> bytes:
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)
    for frame in frames:
        incl = frame[:snaplen]
        data += struct.pack("<IIII", 1, 0, len(incl), len(frame) + orig_extra) + incl
    return data[: len(data) - cut] if cut else data


def write(tmp_path, data: bytes) -> str:
    path = tmp_path / "phase.pcap"
    path.write_bytes(data)
    return str(path)


def run(monkeypatch, capsys, path: str, *args: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.argv", ["egress.py", path, *args])
    code = egress.main()
    out, err = capsys.readouterr()
    return code, out.strip(), err.strip()


# ---------------------------------------------------------------------------
# Healthy captures still give a verdict
# ---------------------------------------------------------------------------


def test_a_contained_window_with_control_traffic_reports_zero(tmp_path, monkeypatch, capsys) -> None:
    path = write(tmp_path, pcap([ssh_control(), ipv4(GUEST, "93.184.216.34", 6, ports(41000, 443))]))
    assert run(monkeypatch, capsys, path, "--hits", PROBE, "--require-control") == (0, "0", "")


def test_a_leaking_window_counts_the_probe(tmp_path, monkeypatch, capsys) -> None:
    path = write(tmp_path, pcap([ssh_control(), probe_udp(), probe_udp()]))
    assert run(monkeypatch, capsys, path, "--hits", PROBE, "--require-control") == (0, "2", "")


def test_an_intentional_snap_length_keeps_the_verdict(tmp_path, monkeypatch, capsys) -> None:
    """vm_capture_start keeps 128 bytes: shorter than the frame, longer than its addresses."""
    big = ipv4(GUEST, PROBE, 17, ports(40000, 53) + bytes(1400))
    path = write(tmp_path, pcap([ssh_control(), big], snaplen=128))
    assert run(monkeypatch, capsys, path, "--hits", PROBE, "--require-control") == (0, "1", "")


def test_arp_is_not_a_reason_to_doubt_the_capture(tmp_path, monkeypatch, capsys) -> None:
    path = write(tmp_path, pcap([ether(0x0806, bytes(28)), ssh_control()]))
    assert run(monkeypatch, capsys, path, "--hits", PROBE, "--require-control") == (0, "0", "")


# ---------------------------------------------------------------------------
# Damaged files are inconclusive, never zero
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        pytest.param(b"", "empty file header", id="empty-file"),
        pytest.param(pcap([])[:10], "truncated file header", id="short-header"),
        pytest.param(b"\x00" * 24, "not a pcap file", id="bad-magic"),
        pytest.param(pcap([ssh_control()], linktype=113), "not Ethernet", id="linux-cooked"),
        pytest.param(pcap([ssh_control(), probe_udp()], cut=30), "frame cut short", id="truncated-frame"),
        pytest.param(pcap([ssh_control()]) + b"\x01\x00\x00", "record 2 header cut short", id="truncated-record"),
        pytest.param(pcap([ssh_control()], orig_extra=-10), "claims", id="incl-above-orig"),
    ],
)
def test_a_damaged_capture_is_inconclusive(tmp_path, monkeypatch, capsys, data: bytes, reason: str) -> None:
    code, out, err = run(monkeypatch, capsys, write(tmp_path, data), "--hits", PROBE)
    assert code == 2
    assert out == "", "an inconclusive capture must not print a count run.sh could read"
    assert err.startswith("INCONCLUSIVE:") and reason in err


def test_a_missing_capture_is_inconclusive(tmp_path, monkeypatch, capsys) -> None:
    code, out, err = run(monkeypatch, capsys, str(tmp_path / "absent.pcap"), "--hits", PROBE)
    assert (code, out) == (2, "") and "cannot be read" in err


# ---------------------------------------------------------------------------
# Blind windows: a valid file that does not show the guest's egress
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "frames",
    [
        pytest.param([], id="header-only"),
        pytest.param([ipv4("93.184.216.34", GUEST, 6, ports(443, 41000))], id="replies-only"),
        pytest.param([ipv4("10.0.3.15", PROBE, 17, ports(40000, 53))], id="another-guest-or-wrong-nic"),
    ],
)
def test_a_window_without_guest_control_traffic_is_inconclusive(tmp_path, monkeypatch, capsys, frames) -> None:
    code, out, err = run(monkeypatch, capsys, write(tmp_path, pcap(frames)), "--hits", PROBE, "--require-control")
    assert (code, out) == (2, "")
    assert "no guest-originated SSH control packet" in err


def test_the_control_requirement_is_opt_in(tmp_path, monkeypatch, capsys) -> None:
    """Without --require-control the old summary still works for manual inspection."""
    assert run(monkeypatch, capsys, write(tmp_path, pcap([])), "--hits", PROBE) == (0, "0", "")


# ---------------------------------------------------------------------------
# Layouts the reader cannot see into are inconclusive
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("frame", "reason"),
    [
        pytest.param(ether(0x8100, b"\x00\x01\x08\x00" + probe_udp()[14:]), "VLAN-tagged", id="vlan"),
        pytest.param(ether(0x88B5, bytes(40)), "EtherType 0x88b5", id="unknown-ethertype"),
        pytest.param(probe_udp()[: 14 + 12], "IPv4 frame was captured with 12", id="snapped-below-destination"),
        pytest.param(ether(0x0800, b"\x65" + bytes(19)), "malformed IPv4", id="ipv6-in-ipv4-ethertype"),
        pytest.param(ether(0x86DD, bytes(30)), "IPv6 frame was captured with 30", id="short-ipv6"),
        pytest.param(b"\x00" * 10, "no complete Ethernet header", id="runt"),
    ],
)
def test_an_unreadable_frame_makes_the_capture_inconclusive(tmp_path, monkeypatch, capsys, frame, reason) -> None:
    data = pcap([ssh_control(), frame, ssh_control()])
    code, out, err = run(monkeypatch, capsys, write(tmp_path, data), "--hits", PROBE, "--require-control")
    assert (code, out) == (2, "")
    assert "record 2" in err and reason in err


# ---------------------------------------------------------------------------
# Hidden families and transport layouts are parsed, not misread
# ---------------------------------------------------------------------------


def test_a_non_first_ipv4_fragment_has_no_port() -> None:
    """Its first bytes are payload; reading them as ports invents a destination port."""
    frame = ipv4(GUEST, PROBE, 17, struct.pack("!HH", 1234, 53) + bytes(16), fragment_offset=185)
    packet = egress.parse(frame)
    assert packet is not None and (packet.dst, packet.dport) == (PROBE, None)


def test_ipv6_extension_headers_are_walked_to_the_ports() -> None:
    hop_by_hop = bytes([17, 0]) + bytes(6)  # next header UDP, 8 bytes
    destination_options = bytes([0, 0]) + bytes(6)  # next header hop-by-hop
    frame = ipv6(GUEST_V6, "2001:db8::7", 60, destination_options + hop_by_hop + ports(40000, 443))
    packet = egress.parse(frame)
    assert packet is not None and (packet.proto, packet.dport) == ("udp", 443)


def test_an_ipv6_non_first_fragment_has_no_port() -> None:
    fragment = bytes([17, 0]) + struct.pack("!H", 185 << 3) + bytes(4)
    packet = egress.parse(ipv6(GUEST_V6, "2001:db8::7", 44, fragment + ports(1234, 53)))
    assert packet is not None and (packet.proto, packet.dport) == ("udp", None)


def test_an_extension_chain_cut_by_the_snap_keeps_the_destination() -> None:
    hop_by_hop = bytes([60, 0]) + bytes(6)
    packet = egress.parse(ipv6(GUEST_V6, "2001:db8::7", 0, hop_by_hop))
    assert packet is not None and packet.dst == "2001:db8::7" and packet.dport is None


def test_guest_ipv6_egress_is_summarised(tmp_path, monkeypatch, capsys) -> None:
    frames = [ssh_control(), ipv6(GUEST_V6, "2001:db8::7", 17, ports(40000, 53))]
    code, out, _ = run(monkeypatch, capsys, write(tmp_path, pcap(frames)), "--require-control")
    assert code == 0
    assert "udp     2001:db8::7:53" in out
    assert out.endswith("total 1 guest-originated packet(s), 1 SSH control packet(s)")
