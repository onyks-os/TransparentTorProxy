# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Continuous fault evidence must retain initial leaks and reject blind runs."""

import json
import socket
import struct

import pytest

from scripts.vm.lifecycle.chaos_capture import evaluate, main, records
from tests import chaos_observation
from tests.chaos_observation import DESTINATIONS, MARKER_PREFIX

MAC = bytes.fromhex("525400123456")
RUN = "0123456789abcdef"


def wire(family, protocol, sequence):
    port = {"dns": 53, "udp": 19302, "tcp": 80}[protocol]
    source = 10000 + family * 1000 + sequence
    payload = f"{RUN}-{family}-{protocol}-{sequence}".encode()
    if protocol == "tcp":
        transport = struct.pack("!HHIIBBHHH", source, port, 1, 0, 0x50, 2, 1000, 0, 0)
    else:
        transport = struct.pack("!HHHH", source, port, 8 + len(payload), 0) + payload
    if family == 4:
        header = bytearray(20)
        header[0], header[9] = 0x45, 6 if protocol == "tcp" else 17
        header[2:4] = (20 + len(transport)).to_bytes(2, "big")
        header[16:20] = socket.inet_aton(DESTINATIONS[family])
        ethertype = b"\x08\x00"
    else:
        header = bytearray(40)
        header[0], header[6] = 0x60, 6 if protocol == "tcp" else 17
        header[4:6] = len(transport).to_bytes(2, "big")
        header[24:40] = socket.inet_pton(socket.AF_INET6, DESTINATIONS[family])
        ethertype = b"\x86\xdd"
    return bytes(6) + MAC + ethertype + header + transport, source, payload


def fixture(tmp_path, *, fault="kill_tor", leak=False, hold_leak=False, defect=None):
    def event(kind, seconds, **fields):
        # Guest monotonic time deliberately bears no relation to PCAP time.
        return {"kind": kind, "run_id": RUN, "monotonic_ns": int((seconds + 100) * 1e9), **fields}

    events = [
        event("capture-open", 0, mac=MAC.hex()),
        event("plan", 0.01, faults=[fault]),
        event("control-start", 0.1, name="pre"),
        event("control-end", 1.1, name="pre"),
        event("fault-before", 2, fault=fault),
        event("fault-after", 2.01, fault=fault),
        event("fault-hold", 20, fault=fault),
        event("fault-end", 23, fault=fault),
        event("control-start", 25, name="post"),
        event("control-end", 26, name="post"),
        event("capture-close", 27),
    ]
    if defect == "missing_close":
        events.pop()
    stimulus = [{"kind": "ready", "run_id": RUN, "uid": 65534, "gid": 65534, "cap_eff": 0}]
    packets = []
    for seq in range(270):
        for family in (4, 6):
            for protocol in ("dns", "udp", "tcp"):
                frame, source, payload = wire(family, protocol, seq)
                stamp = int((100 + seq / 10) * 1e9)
                if defect == "sample_gap" and seq >= 40:
                    stamp += 1_000_000_000
                stimulus.append(
                    {
                        "kind": "attempt",
                        "run_id": RUN,
                        "sequence": seq,
                        "family": family,
                        "protocol": protocol,
                        "destination": DESTINATIONS[family],
                        "source_port": source,
                        "port": {"dns": 53, "udp": 19302, "tcp": 80}[protocol],
                        "payload": payload.hex(),
                        "errno": 0,
                        "monotonic_ns": stamp,
                        "finished_ns": stamp + 1000,
                    }
                )
                if seq in (5, 255) and not (defect == "hidden_ipv6" and family == 6):
                    packets.append((seq / 10 + 0.01, frame))
                if leak and seq == 20 and family == 4 and protocol == "udp":
                    packets.append((2.05, frame))
                if hold_leak and seq == 210 and family == 6 and protocol == "dns":
                    packets.append((21.05, frame))
    stimulus.append({"kind": "finished", "run_id": RUN, "sequences": 270})
    if defect == "root":
        stimulus[0]["uid"] = 0
    if defect == "capabilities":
        stimulus[0]["cap_eff"] = 8192
    if defect == "missing_stimulus":
        del stimulus[10]
    if defect == "unfinished":
        stimulus.pop()
    if defect == "wrong_run":
        stimulus[10]["run_id"] = "other"
    for item in events:
        if defect == "missing_beacon" and item["kind"] == "fault-after":
            continue
        frame = bytes(6) + MAC + b"\x88\xb5" + MARKER_PREFIX + json.dumps(item).encode()
        packets.append((item["monotonic_ns"] / 1e9 - 100, frame))
    capture = tmp_path / "capture.pcap"
    with capture.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for seconds, frame in sorted(packets, key=lambda item: item[0]):
            stamp = int((seconds + 10_000) * 1e6)
            stream.write(struct.pack("<IIII", stamp // 10**6, stamp % 10**6, len(frame), len(frame)))
            stream.write(frame)
    paths = [tmp_path / name for name in ("stimulus.jsonl", "events.jsonl")]
    for path, data in zip(paths, (stimulus, events), strict=True):
        path.write_text("".join(json.dumps(item) + "\n" for item in data))
    return capture, *paths


def test_complete_continuous_observation_can_measure_non_firewall_fault(tmp_path):
    result = evaluate(*fixture(tmp_path))
    assert result["accepted"]
    assert result["faults"][0]["containment"] == "contained"
    assert len(result["controls"]) == 2


@pytest.mark.parametrize("fault", ["kill_tor", "unmount_dns", "link_flap"])
def test_initial_leak_cannot_be_erased_by_later_recovery(tmp_path, fault):
    result = evaluate(*fixture(tmp_path, fault=fault, leak=True))
    assert not result["accepted"]
    window = result["faults"][0]
    assert window["containment"] == "leak" and window["escaped_packets"] == 1
    assert window["first_egress_after_before_beacon_s"] == pytest.approx(0.05)
    assert window["hold_escaped_packets"] == 0


def test_privileged_removal_reports_exposure_separately_from_recovery(tmp_path):
    result = evaluate(*fixture(tmp_path, fault="flush_firewall", leak=True))
    window = result["faults"][0]
    assert result["accepted"] and window["privileged_enforcement_mutation"]
    assert window["containment"] == "leak"  # Never renamed contained after repair.
    assert window["escaped_packets"] == 1 and window["hold_escaped_packets"] == 0


def test_persistent_exposure_fails_even_after_privileged_removal(tmp_path):
    result = evaluate(*fixture(tmp_path, fault="flush_firewall", leak=True, hold_leak=True))
    assert not result["accepted"]
    assert result["faults"][0]["hold_escaped_packets"] == 1


@pytest.mark.parametrize("leak", [False, True])
@pytest.mark.parametrize("damage", ["truncated", "missing_close"])
def test_later_capture_loss_cannot_erase_a_confirmed_fault_leak(tmp_path, monkeypatch, leak, damage):
    capture, _, _ = fixture(tmp_path, leak=leak, defect=damage)
    if damage == "truncated":
        capture.write_bytes(capture.read_bytes()[:-1])
    report = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", ["chaos_capture.py", str(capture), str(tmp_path), str(report)])
    assert main() == 1
    result = json.loads(report.read_text())
    assert result["containment"] == ("leak" if leak else "inconclusive")
    assert result["confirmed_fault_escaped_packets"] == int(leak)
    assert not result["observation_complete"] and not result["accepted"]


@pytest.mark.parametrize(
    "defect",
    [
        "hidden_ipv6",
        "root",
        "capabilities",
        "missing_stimulus",
        "unfinished",
        "wrong_run",
        "missing_beacon",
        "sample_gap",
    ],
)
def test_blind_or_incomplete_fault_observation_is_never_green(tmp_path, defect):
    with pytest.raises(ValueError):
        evaluate(*fixture(tmp_path, defect=defect))


@pytest.mark.parametrize(
    "damage", ["empty", "short_header", "short_record", "short_frame", "snaplen", "wrong_link", "truncated_original"]
)
def test_capture_corruption_is_not_absence_of_egress(tmp_path, damage):
    capture, _, _ = fixture(tmp_path)
    data = bytearray(capture.read_bytes())
    if damage == "empty":
        data = bytearray()
    elif damage == "short_header":
        data = data[:20]
    elif damage == "short_record":
        data = data[:30]
    elif damage == "short_frame":
        data = data[:-1]
    elif damage == "snaplen":
        data[16:20] = struct.pack("<I", 128)
    elif damage == "wrong_link":
        data[20:24] = struct.pack("<I", 113)
    else:
        data[36:40] = struct.pack("<I", 65535)
    capture.write_bytes(data)
    with pytest.raises(ValueError):
        list(records(capture))


@pytest.mark.parametrize("state", ["ready", "tentative", "dadfailed", "linklocal", "unreachable"])
def test_calibration_waits_for_usable_ipv6_without_mutating_the_network(monkeypatch, state):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if "route" in args:
            family = 4 if "-4" in args else 6
            if family == 6 and state == "unreachable":
                return chaos_observation.subprocess.CompletedProcess(args, 2, "", "unreachable")
            source = "10.0.2.15" if family == 4 else "fec0::15"
            if family == 6 and state == "linklocal":
                source = "fe80::15"
            data = [{"dev": "ens3", "prefsrc": source}]
        else:
            address = {"local": "fec0::15"}
            if state in ("tentative", "dadfailed"):
                address[state] = True
            data = [{"addr_info": [address]}]
        return chaos_observation.subprocess.CompletedProcess(args, 0, json.dumps(data), "")

    monkeypatch.setattr(chaos_observation.subprocess, "run", run)
    assert (chaos_observation.control_paths("ens3") is not None) is (state == "ready")
    assert all("-j" in args and not {"add", "replace", "del", "set"}.intersection(args) for args in calls)


def test_missing_calibration_path_times_out_instead_of_skipping_a_family(monkeypatch):
    monkeypatch.setattr(chaos_observation, "control_paths", lambda interface: None)
    ticks = iter([0, 21])
    monkeypatch.setattr(chaos_observation.time, "monotonic", lambda: next(ticks))
    with pytest.raises(RuntimeError, match="did not become ready"):
        chaos_observation.wait_control_paths("ens3", timeout=20)


def test_outbound_probe_records_the_ephemeral_port_assigned_by_connect(monkeypatch, capsys):
    class Done:
        stopped = False

        def is_set(self):
            return self.stopped

        def wait(self, timeout):
            self.stopped = True

    class Client:
        connected = False

        def __init__(self, family, kind):
            self.source = "10.0.2.15" if family == socket.AF_INET else "fec0::15"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def setblocking(self, value):
            pass

        def connect_ex(self, target):
            self.connected = True
            return 115

        def connect(self, target):
            self.connected = True

        def send(self, payload):
            assert self.connected
            return len(payload)

        def getsockname(self):
            return (self.source, 23456 if self.connected else 0)

    monkeypatch.setattr(chaos_observation.os, "geteuid", lambda: 65534)
    monkeypatch.setattr(chaos_observation.os, "getegid", lambda: 65534)
    real_read = chaos_observation.Path.read_text
    monkeypatch.setattr(
        chaos_observation.Path, "read_text", lambda p: "CapEff: 0\n" if str(p) == "/proc/self/status" else real_read(p)
    )
    monkeypatch.setattr(chaos_observation.signal, "signal", lambda *args: None)
    monkeypatch.setattr(chaos_observation.threading, "Event", Done)
    monkeypatch.setattr(chaos_observation.socket, "socket", Client)
    chaos_observation.probe(RUN)
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    attempts = [row for row in rows if row["kind"] == "attempt"]
    assert {(row["family"], row["protocol"]) for row in attempts} == {
        (f, p) for f in (4, 6) for p in ("dns", "udp", "tcp")
    }
    assert all(row["source_port"] == 23456 for row in attempts)
    assert rows[-1]["kind"] == "finished" and rows[-1]["sequences"] == 1
