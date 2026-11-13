# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Regressions: silence and DNS errors can coexist with real packet delivery."""

import importlib.util
import json
import socket
import struct
import threading
import time
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.leak import oracle
from tests.leak.test_dns_leak import _QUERY, _probe

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("boundary_fixture", ROOT / "scripts/vm/leak_boundary.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


@pytest.mark.parametrize("rcode", [None, 2, 4, 5])
def test_actual_receiver_can_receive_dns_even_when_socket_is_silent_or_errors(monkeypatch, rcode):
    """A real local UDP exchange reproduces the old oracle's false positive.

    This is a regression of the inference, not a claim about a TTP session:
    actual protected-netns containment is qualified by the external VM fixture.
    """
    monkeypatch.setattr("tests.leak.test_dns_leak.session_is_active", lambda: True)
    counter = Mock(return_value={"dns_redirected": 999})
    monkeypatch.setattr("ttp.firewall.read_counters", counter)
    received = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as responder:
        responder.bind(("127.0.0.1", 0))
        responder.settimeout(2)

        def respond():
            data, peer = responder.recvfrom(4096)
            received.append(data)
            if rcode is not None:
                responder.sendto(data[:2] + bytes([0x81, 0x80 | rcode]) + data[4:], peer)

        thread = threading.Thread(target=respond)
        thread.start()
        observation = _probe(
            socket.AF_INET, "127.0.0.1", "controlled_dns", port=responder.getsockname()[1], timeout=0.15
        )
        thread.join(timeout=3)
    assert not thread.is_alive() and received == [_QUERY]
    assert oracle.verdict_for(observation)[0] is oracle.Verdict.INCONCLUSIVE
    counter.assert_not_called()
    observed_egress = replace(observation, boundary=oracle.BoundaryEvidence(1, 0, 0, False, True))
    assert oracle.verdict_for(observed_egress)[0] is oracle.Verdict.LEAK


@pytest.mark.parametrize(
    "evidence",
    [
        (0, 0, 1, True, True),
        (0, 1, 0, True, True),
        (0, 1, 1, False, True),
        (0, 1, 1, True, False),
    ],
)
def test_missing_control_capture_or_stimulus_cannot_prove_containment(evidence):
    observation = oracle.Observation(
        "dns", "target", oracle.Outcome.BLOCKED, True, boundary=oracle.BoundaryEvidence(*evidence)
    )
    assert oracle.verdict_for(observation)[0] is oracle.Verdict.INCONCLUSIVE


def test_complete_calibrated_capture_can_prove_the_bounded_observation():
    observation = oracle.Observation(
        "dns", "target", oracle.Outcome.ANSWERED, True, boundary=oracle.BoundaryEvidence(0, 2, 3, True, True)
    )
    assert oracle.verdict_for(observation)[0] is oracle.Verdict.CONTAINED


@pytest.mark.parametrize(
    "counts", [(True, 1, 1, True, True), (-1, 1, 1, True, True), (0, 1.5, 1, True, True), (0, 1, 1, 1, True)]
)
def test_invalid_capture_counts_and_flags_are_rejected(counts):
    with pytest.raises(ValueError):
        oracle.BoundaryEvidence(*counts)


def test_reader_rederives_verdict_instead_of_trusting_saved_green(tmp_path, monkeypatch):
    monkeypatch.setattr(oracle, "ARTIFACT_DIR", tmp_path)
    observation = oracle.Observation("dns", "target", oracle.Outcome.BLOCKED, True)
    path = oracle.record(observation)
    data = json.loads(path.read_text())
    data["verdict"] = "contained"
    path.write_text(json.dumps(data))
    assert oracle.read_verdict(path)[0] is oracle.Verdict.INCONCLUSIVE


@pytest.mark.parametrize("defect", [None, "unfinished", "wrong_run", "wrong_probe", "invalid_evidence"])
def test_measurement_identity_and_finalization_are_required(tmp_path, monkeypatch, defect):
    path = tmp_path / "report.json"
    monkeypatch.setenv("TTP_BOUNDARY_REPORT", str(path))
    monkeypatch.setenv("TTP_BOUNDARY_RUN", "this-run")
    observation = oracle.Observation(
        "dns", "target", oracle.Outcome.BLOCKED, True, boundary=oracle.BoundaryEvidence(0, 1, 1, True, True)
    )
    data = {
        "schema": oracle.SCHEMA_VERSION,
        "complete": True,
        "run_id": "this-run",
        "observations": {"dns": asdict(observation)},
    }
    if defect == "unfinished":
        data["complete"] = False
    if defect == "wrong_run":
        data["run_id"] = "other-run"
    if defect == "wrong_probe":
        data["observations"]["dns"]["probe"] = "other"
    if defect == "invalid_evidence":
        data["observations"]["dns"]["boundary"]["escaped"] = -1
    path.write_text(json.dumps(data))
    measured = oracle.measured_observation("dns")
    assert (oracle.verdict_for(measured)[0] is oracle.Verdict.CONTAINED) is (defect is None)


def udp_frame(family, payload=b"unique-probe"):
    udp = struct.pack("!HHHH", 30000, 53, 8 + len(payload), 0) + payload
    if family == 4:
        header = bytearray(20)
        header[0], header[9] = 0x45, 17
        header[2:4] = (20 + len(udp)).to_bytes(2, "big")
        header[16:20] = socket.inet_aton(fixture.HOST4)
        ethertype = b"\x08\x00"
    else:
        header = bytearray(40)
        header[0], header[6] = 0x60, 17
        header[4:6] = len(udp).to_bytes(2, "big")
        header[24:40] = socket.inet_pton(socket.AF_INET6, fixture.HOST6)
        ethertype = b"\x86\xdd"
    return bytes(12) + ethertype + header + udp


@pytest.mark.parametrize("family", [4, 6])
def test_classifier_identifies_exact_destination_port_and_payload(family):
    frame = udp_frame(family)
    assert fixture.udp_payload(frame) == (fixture.HOST4 if family == 4 else fixture.HOST6, 53, b"unique-probe")
    assert fixture.udp_payload(udp_frame(family, b"unrelated DNS"))[2] != b"unique-probe"
    for cut in (0, 12, 17, len(frame) - 1):
        with pytest.raises(ValueError):
            fixture.udp_payload(frame[:cut])


@pytest.mark.parametrize("family", [4, 6])
def test_fragmented_or_extension_layout_is_not_a_clean_capture(family):
    frame = bytearray(udp_frame(family))
    if family == 4:
        frame[20] = 0x20
    else:
        frame[20] = 44
    with pytest.raises(ValueError):
        fixture.udp_payload(bytes(frame))


@pytest.mark.parametrize("final_protocol", [58, 17])
def test_ipv6_hop_by_hop_control_is_distinct_from_unsupported_udp(final_protocol):
    frame = bytearray(udp_frame(6))
    payload = bytes([final_protocol, 0]) + bytes(6) + frame[54:]
    frame[20] = 0
    frame[18:20] = len(payload).to_bytes(2, "big")
    frame = bytes(frame[:54]) + payload
    if final_protocol == 58:
        assert fixture.udp_payload(frame) is None
    else:
        with pytest.raises(ValueError, match="UDP/IPv6 extension"):
            fixture.udp_payload(frame)


@pytest.mark.parametrize("defect", [None, "drops", "missing_marker", "truncated", "budget"])
def test_capture_health_brackets_and_loss_are_required(tmp_path, monkeypatch, defect):
    markers = [b"before-unique-marker", b"after-unique-marker"]

    def beacon(marker):
        return bytes(12) + b"\x88\xb5" + marker

    frames = [beacon(markers[0]), udp_frame(4, b"unrelated DNS")]
    if defect != "missing_marker":
        frames.append(beacon(markers[1]))
    if defect == "truncated":
        frames.insert(1, bytes(12))

    class Wire:
        def setsockopt(self, *args):
            pass

        def bind(self, address):
            pass

        def settimeout(self, timeout):
            pass

        def recv(self, size):
            if frames:
                return frames.pop(0)
            time.sleep(0.001)
            raise TimeoutError

        def getsockopt(self, *args):
            if args == (socket.SOL_SOCKET, socket.SO_RCVBUF):
                return 16 * 1024**2
            return struct.pack("II", 10, int(defect == "drops"))

        def close(self):
            pass

    monkeypatch.setattr(fixture.socket, "socket", lambda *args: Wire())
    capture = fixture.Capture("fixture", bytes(6), fixture.HOST4, 53, b"unique-probe", markers)
    if defect == "budget":
        capture.byte_count = 16 * 1024**2 + 1
    with capture:
        time.sleep(0.01)
    assert capture.matches == 0  # Concurrent unrelated DNS cannot become our evidence.
    assert capture.complete is (defect is None)
    path = tmp_path / "capture.pcap"
    capture.save(path)
    assert path.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"
    assert capture.finished_ns >= capture.started_ns
