# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Correlate E01 ordinary probes with full, externally captured Ethernet frames."""

from __future__ import annotations

import collections
import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts.vm.lifecycle.chaos_capture import flow, records
from ttp.virtual_addresses import VIRTUAL_IPV4, VIRTUAL_IPV6


def analyse(capture, log):
    events = [json.loads(line) for line in Path(log).read_text().splitlines()]
    if not events or events[0]["kind"] != "ready" or events[-1]["kind"] != "finished":
        raise ValueError("Missing experiment readiness/completion")
    run = events[0]["run"]
    if any(event["run"] != run for event in events):
        raise ValueError("Mixed experiment identities")
    if any(event["kind"] == "command" and event["rc"] != 0 for event in events):
        raise ValueError("Fixture command failed")
    probes = {event["tag"]: event for event in events if event["kind"] == "probe"}
    expected = {
        f"{profile}-{phase}-v{family}-{mode}-{repeat}"
        for profile in ("strict", "lan")
        for phase in ("control-pre", "protected", "mutant", "control-post")
        if phase != "mutant" or profile == "lan"
        for family in (4, 6)
        for mode in ("tcp", "udp")
        for repeat in range(2 if phase == "protected" else 1)
    }
    if set(probes) != expected or len(probes) != sum(e["kind"] == "probe" for e in events):
        raise ValueError("Missing, duplicate or unexpected probe")
    mappings = {(e["profile"], ipaddress.ip_address(e["address"]).version): e for e in events if e["kind"] == "mapping"}
    if set(mappings) != {(profile, family) for profile in ("strict", "lan") for family in (4, 6)}:
        raise ValueError("Missing automap family/profile")
    for (_, family), mapping in mappings.items():
        if mapping["address"] != mapping["reused"] or ipaddress.ip_address(
            mapping["address"]
        ) not in ipaddress.ip_network(VIRTUAL_IPV4 if family == 4 else VIRTUAL_IPV6):
            raise ValueError("Mapping was not reused or disagrees with the managed range")
    markers = [e["tag"] for e in events if e["kind"] == "marker"]
    planned = [tag + suffix for tag in probes for suffix in ("-before", "-after")] + ["finished"]
    if markers != planned:
        raise ValueError("Missing or reordered guest phases")
    for tag, probe in probes.items():
        if (
            probe["uid"] != 65534
            or probe["gid"] != 65534
            or probe["groups"]
            or probe["cap_eff"] != 0
            or probe["attempted"] is not True
            or not 0 < probe["source_port"] <= 65535
            or probe["address"] != mappings[probe["profile"], probe["family"]]["address"]
            or probe["token"] != f"E01:{run}:{tag}"
            or tag != f"{probe['profile']}-{probe['phase']}-v{probe['family']}-{probe['mode']}-{probe['repeat']}"
        ):
            raise ValueError("Invalid probe identity, source or correlation")
    seen_markers = []
    active = None
    counts = collections.Counter()
    byte_counts = collections.Counter()
    # Retain positive observations even if a later record or marker is lost.
    errors = []
    try:
        for _, frame in records(capture):
            if frame[12:14] == b"\x88\xb5" and frame[14:].startswith(f"E01:{run}:".encode()):
                tag = frame[14:].decode().split(":", 2)[2]
                seen_markers.append(tag)
                if seen_markers != markers[: len(seen_markers)]:
                    raise ValueError("Unexpected capture phase")
                active = tag[:-7] if tag.endswith("-before") else None
                continue
            if active is None:
                continue
            probe = probes[active]
            if (
                frame[12:14] == b"\x86\xdd"
                and len(frame) >= 54
                and str(ipaddress.ip_address(frame[38:54])) == probe["address"]
                and frame[20] not in (6, 17)
            ):
                raise ValueError("Unsupported required IPv6 layout")
            packet = flow(frame)
            if (
                packet is None
                or packet[0] != probe["family"]
                or packet[1] != probe["address"]
                or packet[2] != probe["mode"]
            ):
                continue
            if packet[3] != (80 if probe["mode"] == "tcp" else 19302):
                continue
            if packet[4] != (probe["source_port"] if probe["mode"] == "tcp" else probe["token"].encode()):
                continue
            counts[active] += 1
            byte_counts[active] += len(frame)
    except (ValueError, OSError) as exc:
        errors.append(str(exc))
    if seen_markers != markers:
        errors.append("Missing external phase markers")
    results = []
    for tag, probe in probes.items():
        protected = probe["phase"] == "protected"
        packets = counts[tag]
        available = probe.get("nonce_ok") is True if probe["mode"] == "tcp" else None
        accepted = packets == 0 and (available if probe["mode"] == "tcp" else True) if protected else packets > 0
        results.append(
            dict(
                tag=tag,
                phase=probe["phase"],
                packets=packets,
                bytes=byte_counts[tag],
                onion_available=available,
                accepted=bool(accepted),
            )
        )
    leak = any(row["phase"] == "protected" and row["packets"] for row in results)
    controls_complete = all(row["packets"] > 0 for row in results if row["phase"] != "protected")
    if not controls_complete:
        errors.append("Missing positive control or targeted mutation evidence")
    return dict(
        schema=1,
        run=run,
        accepted=not errors and all(row["accepted"] for row in results),
        containment="leak" if leak else "inconclusive" if errors else "contained",
        errors=errors,
        probes=results,
    )


def main():
    try:
        report = analyse(sys.argv[1], sys.argv[2])
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        report = dict(schema=1, accepted=False, containment="inconclusive", errors=[str(exc)])
    Path(sys.argv[3]).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
