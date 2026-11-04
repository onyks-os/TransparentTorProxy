#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Audit every pinned version, including variants inactive on this interpreter."""

import subprocess
import sys
import tempfile
from pathlib import Path

from packaging.requirements import Requirement


def batches(paths):
    versions = {}
    for path in paths:
        for line in path.read_text().splitlines():
            line = line.strip().removesuffix("\\").strip()
            if not line or line.startswith(("#", "--")):
                continue
            requirement = Requirement(line)
            name = requirement.name.lower().replace("_", "-")
            pin = str(requirement.specifier)
            versions.setdefault(name, set()).add(f"{name}{pin}")
    # A batch cannot require two versions of the same package. Markers are
    # intentionally discarded: this is an advisory query, not an installation.
    ordered = {name: sorted(pins) for name, pins in versions.items()}
    return [
        [pins[index] for _, pins in sorted(ordered.items()) if index < len(pins)]
        for index in range(max(map(len, ordered.values()), default=0))
    ]


def main():
    root = Path(__file__).resolve().parents[1]
    groups = batches((root / "requirements").glob("*.txt"))
    if not groups:
        raise SystemExit("No lock entries found")
    failed = False
    with tempfile.TemporaryDirectory() as directory:
        for index, pins in enumerate(groups):
            path = Path(directory) / f"audit-{index}.txt"
            path.write_text("\n".join(pins) + "\n")
            print(f"Auditing lock batch {index + 1}/{len(groups)} ({len(pins)} versions)", flush=True)
            result = subprocess.run([sys.executable, "-m", "pip_audit", "--disable-pip", "--no-deps", "-r", str(path)])
            failed |= result.returncode != 0
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
