# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Recognize completed provisioning carrying only benign hostname warnings."""

import json
import sys
from pathlib import Path


def hostname_warning_only(value):
    if not isinstance(value, dict) or value.get("status") != "done" or value.get("errors") != []:
        return False
    recoverable = value.get("recoverable_errors")
    if not isinstance(recoverable, dict) or set(recoverable) != {"WARNING"}:
        return False
    warnings = recoverable["WARNING"]
    return (
        isinstance(warnings, list)
        and bool(warnings)
        and all(isinstance(item, str) and item.startswith("Failed to set the hostname to ") for item in warnings)
    )


if __name__ == "__main__":
    try:
        accepted = hostname_warning_only(json.loads(Path(sys.argv[1]).read_text()))
    except (OSError, ValueError):
        accepted = False
    raise SystemExit(0 if accepted else 1)
