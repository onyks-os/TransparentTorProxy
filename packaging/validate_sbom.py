#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Fail unless every given SBOM is valid CycloneDX against the official schema.

    python3 packaging/validate_sbom.py packaging/*.cdx.json

Needs cyclonedx-python-lib[json-validation] (in the `dev` extra). Validates
against the specVersion each file declares, strictly: unknown fields fail.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    failed = 0
    for arg in argv:
        text = Path(arg).read_text(encoding="utf-8")
        declared = json.loads(text).get("specVersion", "")
        schema = SchemaVersion.from_version(declared)
        error = JsonStrictValidator(schema).validate_str(text)
        if error is None:
            print(f"valid CycloneDX {declared}: {arg}")
        else:
            print(f"INVALID CycloneDX {declared}: {arg}\n  {error}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
