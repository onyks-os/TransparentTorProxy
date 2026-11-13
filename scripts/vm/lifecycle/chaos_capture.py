# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Evaluate continuous fault observations outside the chaos VM.

Use capture-order phase beacons, never subtraction of guest and QEMU clocks.
Privileged removal of enforcement is reported as exposure even after recovery.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import struct
import sys
from itertools import pairwise
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts.vm.leak_boundary import udp_payload
from tests.chaos_observation import DESTINATIONS, INTERVAL, MARKER_PREFIX

ENFORCEMENT_FAULTS = {"insert_accept", "delete_last_filter_rule", "flush_firewall", "destroy_firewall"}
CHANNELS = {(family, protocol) for family in DESTINATIONS for protocol in ("dns", "udp", "tcp")}
MAX_SAMPLE_GAP = 0.5


def records(path):
    """Stream full Ethernet PCAP records; a short/corrupt file is never clean."""
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("Missing or unsupported capture header")
        _, major, minor, _, _, snaplen, link = struct.unpack("<IHHIIII", header)
        if (major, minor, link) != (2, 4, 1) or snaplen < 65535:
            raise ValueError("Full Ethernet capture is required")
        previous = None
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("Truncated capture record")
            seconds, micros, size, original = struct.unpack("<IIII", record)
            if size != original or not 14 <= size <= snaplen or size > 65535 or micros >= 10**6:
                raise ValueError("Truncated or invalid captured frame")
            frame = stream.read(size)
            if len(frame) != size:
                raise ValueError("Truncated frame bytes")
            stamp = seconds + micros / 10**6
            if previous is not None and stamp < previous:
                raise ValueError("Capture clock moved backwards")
            previous = stamp
            yield stamp, frame


def flow(frame):
    """Strict fixture UDP/TCP tuple; unrelated traffic is not a containment claim."""
    udp = udp_payload(frame)  # Also validates the Ethernet and IP envelope.
    if udp is not None:
        destination, port, payload = udp
        return (6 if ":" in destination else 4), destination, "dns" if port == 53 else "udp", port, payload
    ip = frame[14:]
    if frame[12:14] == b"\x08\x00":
        if ip[9] != 6:
            return None
        offset, size, family = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big"), 4
        destination = str(ipaddress.ip_address(ip[16:20]))
    elif frame[12:14] == b"\x86\xdd":
        if ip[6] != 6:
            if ip[6] in (0, 43, 60) and str(ipaddress.ip_address(ip[24:40])) in DESTINATIONS.values():
                raise ValueError("Unsupported probe TCP/IPv6 extension layout")
            return None
        offset, size, family = 40, 40 + int.from_bytes(ip[4:6], "big"), 6
        destination = str(ipaddress.ip_address(ip[24:40]))
    else:
        return None
    tcp = ip[offset:size]
    if len(tcp) < 20 or not 20 <= (tcp[12] >> 4) * 4 <= len(tcp):
        raise ValueError("Invalid TCP header")
    source_port, port = struct.unpack("!HH", tcp[:4])
    return family, destination, "tcp", port, source_port


def read_stimulus(path):
    lines = [json.loads(line) for line in Path(path).read_text().splitlines()]
    if not lines or lines[0].get("kind") != "ready" or lines[-1].get("kind") != "finished":
        raise ValueError("Missing stimulus readiness/completion")
    ready = lines[0]
    if (
        type(ready.get("uid")) is not int
        or ready["uid"] <= 0
        or type(ready.get("gid")) is not int
        or ready["gid"] <= 0
        or ready.get("cap_eff") != 0
    ):
        raise ValueError("Stimulus was not an ordinary identity")
    run_id = ready["run_id"]
    if any(line.get("run_id") != run_id for line in lines):
        raise ValueError("Stimulus run mismatch")
    attempts = lines[1:-1]
    sequences = collections.defaultdict(set)
    previous = -1
    for attempt in attempts:
        channel = attempt["family"], attempt["protocol"]
        if attempt["kind"] != "attempt" or channel not in CHANNELS:
            raise ValueError("Unknown stimulus channel")
        if attempt["destination"] != DESTINATIONS[attempt["family"]]:
            raise ValueError("Wrong stimulus destination")
        if (
            type(attempt["monotonic_ns"]) is not int
            or attempt["monotonic_ns"] < previous
            or type(attempt["finished_ns"]) is not int
            or attempt["finished_ns"] < attempt["monotonic_ns"]
            or type(attempt["errno"]) is not int
        ):
            raise ValueError("Invalid stimulus timing/result")
        previous = attempt["monotonic_ns"]
        if channel in sequences[attempt["sequence"]]:
            raise ValueError("Duplicate stimulus sequence")
        sequences[attempt["sequence"]].add(channel)
    count = lines[-1]["sequences"]
    if (
        not sequences
        or set(sequences) != set(range(count))
        or any(channels != CHANNELS for channels in sequences.values())
    ):
        raise ValueError("Missing stimulus sequence/channel")
    return run_id, attempts


def evaluate(capture, stimulus, expected_events, *, observed_evidence=None):
    run_id, attempts = read_stimulus(stimulus)
    events = [json.loads(line) for line in Path(expected_events).read_text().splitlines()]
    if not events or events[0].get("kind") != "capture-open" or events[-1].get("kind") != "capture-close":
        raise ValueError("Missing capture phase boundaries")
    if any(event.get("run_id") != run_id for event in events):
        raise ValueError("Phase run mismatch")
    mac = bytes.fromhex(events[0]["mac"])
    observed, escaped = [], []
    evidence = observed_evidence if observed_evidence is not None else {}
    evidence.update(confirmed_fault_escaped_packets=0, confirmed_fault_escaped_bytes=0)
    previous_phase = None
    fault_phases = {"fault-before": 0, "fault-after": 1, "fault-hold": 2, "fault-end": 3}
    udp_stimuli = {bytes.fromhex(a["payload"]) for a in attempts if a["protocol"] != "tcp"}
    tcp_stimuli = {(a["family"], a["source_port"]) for a in attempts if a["protocol"] == "tcp"}
    for index, (stamp, frame) in enumerate(records(capture)):
        if frame[6:12] != mac:
            continue
        if frame[12:14] == b"\x88\xb5":
            if not frame[14:].startswith(MARKER_PREFIX):
                raise ValueError("Unknown phase beacon")
            event = json.loads(frame[14 + len(MARKER_PREFIX) :])
            if event.get("run_id") != run_id:
                raise ValueError("Unrelated capture run")
            # Retain positively measured egress even if later capture bytes or
            # liveness evidence are lost. Only count packets bracketed by known,
            # ordered fault beacons, never unprotected calibration traffic.
            if event in events and event["kind"] in fault_phases:
                if (
                    previous_phase is not None
                    and previous_phase[0]["fault"] == event["fault"]
                    and fault_phases[previous_phase[0]["kind"]] < fault_phases[event["kind"]]
                ):
                    hits = [hit for hit in escaped if previous_phase[1] < hit[0] < index]
                    evidence["confirmed_fault_escaped_packets"] += len(hits)
                    evidence["confirmed_fault_escaped_bytes"] += sum(hit[3] for hit in hits)
                previous_phase = (event, index)
            else:
                previous_phase = None
            observed.append((event, index, stamp))
            continue
        value = flow(frame)
        if value is None or value[1] not in DESTINATIONS.values():
            continue
        family, destination, protocol, port, identity = value
        if destination != DESTINATIONS[family] or port != {"dns": 53, "udp": 19302, "tcp": 80}[protocol]:
            raise ValueError("Unexpected traffic to the fixture destination")
        if (protocol == "tcp" and (family, identity) not in tcp_stimuli) or (
            protocol != "tcp" and identity not in udp_stimuli
        ):
            raise ValueError("Captured probe has no matching stimulus")
        escaped.append((index, stamp, (family, protocol), len(frame)))
    if [event for event, _, _ in observed] != events:
        raise ValueError("Missing, reordered or duplicated phase beacons")
    if not escaped:
        raise ValueError("No positive control was captured")
    controls, windows = [], []
    pending_control, pending_fault = None, None
    for event, index, stamp in observed:
        kind = event["kind"]
        if kind == "control-start":
            if pending_control is not None:
                raise ValueError("Overlapping controls")
            pending_control = (event, index, stamp)
        elif kind == "control-end":
            if pending_control is None or pending_control[0]["name"] != event["name"]:
                raise ValueError("Unmatched control boundary")
            before, start, _ = pending_control
            channels = {channel for i, _, channel, _ in escaped if start < i < index}
            if channels != CHANNELS:
                raise ValueError(f"Positive control missed a family/protocol: {event['name']}: {channels}")
            controls.append({"name": before["name"], "channels": len(channels), "index": start})
            pending_control = None
        elif kind == "fault-before":
            if pending_fault is not None:
                raise ValueError("Overlapping faults")
            pending_fault = {
                "fault": event["fault"],
                "start": index,
                "start_stamp": stamp,
                "start_ns": event["monotonic_ns"],
            }
        elif kind in ("fault-after", "fault-hold", "fault-end"):
            if pending_fault is None or pending_fault["fault"] != event["fault"]:
                raise ValueError("Unmatched fault boundary")
            pending_fault[kind] = (index, stamp, event["monotonic_ns"])
            if kind == "fault-end":
                if "fault-after" not in pending_fault or "fault-hold" not in pending_fault:
                    raise ValueError("Missing injection or final hold boundary")
                window = pending_fault
                hits = [(i, ts, ch, size) for i, ts, ch, size in escaped if window["start"] < i < index]
                hold_index, _, hold_ns = window["fault-hold"]
                if event["monotonic_ns"] - hold_ns < 2.5e9:
                    raise ValueError("Final hold interval is too short")
                # Cadence/completion are checked using the guest's own clock;
                # captured egress uses only QEMU's clock relative to beacons.
                gaps = []
                for channel in CHANNELS:
                    samples = [
                        a["monotonic_ns"]
                        for a in attempts
                        if (a["family"], a["protocol"]) == channel
                        and window["start_ns"] <= a["monotonic_ns"] <= event["monotonic_ns"]
                    ]
                    points = [window["start_ns"], *samples, event["monotonic_ns"]]
                    if not samples:
                        raise ValueError("Fault interval has no attempted stimulus")
                    gaps.append(max(b - a for a, b in pairwise(points)) / 1e9)
                if max(gaps) > MAX_SAMPLE_GAP:
                    raise ValueError(f"Stimulus gap exceeded {MAX_SAMPLE_GAP}s: {max(gaps)}")
                hold_hits = [hit for hit in hits if hit[0] > hold_index]
                expected_exposure = window["fault"] in ENFORCEMENT_FAULTS
                errors = collections.Counter(
                    str(a["errno"])
                    for a in attempts
                    if window["start_ns"] <= a["monotonic_ns"] <= event["monotonic_ns"]
                )
                windows.append(
                    {
                        "fault": window["fault"],
                        "containment": "leak" if hits else "contained",
                        "privileged_enforcement_mutation": expected_exposure,
                        "escaped_packets": len(hits),
                        "escaped_bytes": sum(h[3] for h in hits),
                        "first_egress_after_before_beacon_s": hits[0][1] - window["start_stamp"] if hits else None,
                        "last_egress_after_before_beacon_s": hits[-1][1] - window["start_stamp"] if hits else None,
                        "hold_escaped_packets": len(hold_hits),
                        "injection_bracket_s": [0, window["fault-after"][1] - window["start_stamp"]],
                        "observed_interval_s": stamp - window["start_stamp"],
                        "hold_duration_s": (event["monotonic_ns"] - hold_ns) / 1e9,
                        "socket_errno_counts": dict(errors),
                        "max_sample_gap_s": max(gaps),
                        "accepted": not hold_hits and (not hits or expected_exposure),
                        "start_index": window["start"],
                        "end_index": index,
                    }
                )
                pending_fault = None
    plans = [event["faults"] for event in events if event["kind"] == "plan"]
    if pending_control or pending_fault or len(plans) != 1 or [w["fault"] for w in windows] != plans[0]:
        raise ValueError("Incomplete planned fault sweep")
    if (
        not windows
        or len(controls) < 2
        or controls[0]["index"] >= windows[0]["start_index"]
        or controls[-1]["index"] <= windows[-1]["end_index"]
    ):
        raise ValueError("Missing pre/post positive controls")
    return {
        "schema": 1,
        "run_id": run_id,
        "nominal_interval_s": INTERVAL,
        "capture": "QEMU full Ethernet filter-dump; no host packet-socket queue",
        "controls": controls,
        "faults": windows,
        "accepted": all(w["accepted"] for w in windows),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("directory", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    evidence = {}
    try:
        result = evaluate(
            args.capture, args.directory / "stimulus.jsonl", args.directory / "events.jsonl", observed_evidence=evidence
        )
    except (OSError, ValueError, KeyError, TypeError, struct.error) as exc:
        result = {
            "schema": 1,
            "accepted": False,
            "containment": "leak" if evidence.get("confirmed_fault_escaped_packets", 0) else "inconclusive",
            "observation_complete": False,
            **evidence,
            "error": str(exc),
        }
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
