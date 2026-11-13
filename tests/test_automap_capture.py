# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""An empty, blind or unavailable onion experiment must never be green."""

import ipaddress
import json
import socket
import struct

import pytest

from scripts.vm.automap.capture import analyse
from scripts.vm.automap.guest import resolve_mapping

RUN = "0123456789abcdef"


def fixture(tmp_path, *, defect=None, leak=False):
    events = [dict(kind="ready", run=RUN)]
    frames = []

    def marker(tag):
        events.append(dict(kind="marker", run=RUN, tag=tag))
        frames.append(bytes(12) + b"\x88\xb5" + f"E01:{RUN}:{tag}".encode())

    for profile in ("strict", "lan"):
        for _family, address in ((4, "10.192.0.7"), (6, "fc00::7")):
            events.append(dict(kind="mapping", run=RUN, profile=profile, address=address, reused=address))
        for phase in ("control-pre", "protected", "mutant", "control-post"):
            if phase == "mutant" and profile == "strict":
                continue
            for repeat in range(2 if phase == "protected" else 1):
                for family, address in ((4, "10.192.0.7"), (6, "fc00::7")):
                    for mode in ("tcp", "udp"):
                        tag = f"{profile}-{phase}-v{family}-{mode}-{repeat}"
                        token = f"E01:{RUN}:{tag}"
                        source = 40000 + len(events)
                        probe = dict(
                            kind="probe",
                            run=RUN,
                            tag=tag,
                            token=token,
                            address=address,
                            profile=profile,
                            phase=phase,
                            family=family,
                            mode=mode,
                            repeat=repeat,
                            uid=65534,
                            gid=65534,
                            groups=[],
                            cap_eff=0,
                            attempted=True,
                            source_port=source,
                            nonce_ok=defect != "unavailable",
                        )
                        if defect == "root":
                            probe["uid"] = 0
                        marker(tag + "-before")
                        events.append(probe)
                        if phase != "protected" or leak:
                            transport = (
                                struct.pack("!HHIIBBHHH", source, 80, 1, 0, 0x50, 2, 1000, 0, 0)
                                if mode == "tcp"
                                else struct.pack("!HHHH", source, 19302, 8 + len(token), 0) + token.encode()
                            )
                            if family == 4:
                                header = bytearray(20)
                                header[0], header[9] = 0x45, 6 if mode == "tcp" else 17
                                header[2:4] = (20 + len(transport)).to_bytes(2, "big")
                                header[16:20] = socket.inet_aton(address)
                                ethertype = b"\x08\x00"
                            else:
                                header = bytearray(40)
                                header[0], header[6] = 0x60, 6 if mode == "tcp" else 17
                                header[4:6] = len(transport).to_bytes(2, "big")
                                header[24:40] = ipaddress.ip_address(address).packed
                                ethertype = b"\x86\xdd"
                            if defect != "missing_control" or phase == "protected":
                                frames.append(bytes(12) + ethertype + header + transport)
                        marker(tag + "-after")
    marker("finished")
    events.append(dict(kind="finished", run=RUN))
    if defect == "unfinished":
        events.pop()
    capture = tmp_path / "capture.pcap"
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for number, frame in enumerate(frames):
        data += struct.pack("<IIII", 10, number, len(frame), len(frame)) + frame
    if defect == "truncated":
        data = data[:-1]
    capture.write_bytes(data)
    log = tmp_path / "events.jsonl"
    log.write_text("".join(json.dumps(event) + "\n" for event in events))
    return capture, log


def test_complete_controls_and_real_onion_answers_are_required(tmp_path):
    report = analyse(*fixture(tmp_path))
    assert report["accepted"] and report["containment"] == "contained"
    assert len(report["probes"]) == 36


@pytest.mark.parametrize("defect", ["missing_control", "unavailable", "truncated"])
def test_no_false_green_from_failed_observation_or_unavailable_onion(tmp_path, defect):
    report = analyse(*fixture(tmp_path, defect=defect))
    assert not report["accepted"]
    if defect != "unavailable":
        assert report["containment"] == "inconclusive"


@pytest.mark.parametrize("defect", [None, "truncated"])
def test_positive_egress_survives_later_capture_loss(tmp_path, defect):
    report = analyse(*fixture(tmp_path, defect=defect, leak=True))
    assert report["containment"] == "leak" and not report["accepted"]


@pytest.mark.parametrize("defect", ["root", "unfinished"])
def test_untrustworthy_stimulus_or_completion_is_rejected(tmp_path, defect):
    with pytest.raises(ValueError):
        analyse(*fixture(tmp_path, defect=defect))


def test_truncated_dns_mapping_is_not_an_address(monkeypatch):
    from unittest.mock import MagicMock

    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.recv.return_value = b"short"
    monkeypatch.setattr(socket, "socket", lambda *_: sock)
    with pytest.raises(ValueError, match="Truncated DNS"):
        resolve_mapping("fixture.onion", 1)
