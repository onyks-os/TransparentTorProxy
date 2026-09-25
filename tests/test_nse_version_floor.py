# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The NSE version floor is stated twice, and the two statements must agree.

``pyproject.toml`` decides what pip installs; ``MIN_NSE_VERSION`` in
``tests/test_nse_rules.py`` decides what the zero-leak suite will run against.
Raising one without the other has already been half-done once (2.1.2): the
suite then either refuses an engine pip is allowed to install, or accepts one
the floor exists to exclude. Neither is visible in review, so it is checked here.

``test_nse_rules.py`` skips at module level without root, so it cannot be
imported by the ordinary run; the constant is read from its source instead.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_floor() -> tuple[int, ...]:
    text = (ROOT / "pyproject.toml").read_text()
    matches = re.findall(r'"network-sandbox-engine>=([0-9][0-9.]*)[,"]', text)
    assert len(matches) == 1, f"expected one network-sandbox-engine floor in pyproject.toml, found {matches}"
    return tuple(int(part) for part in matches[0].split("."))


def _min_nse_version() -> tuple[int, ...]:
    tree = ast.parse((ROOT / "tests" / "test_nse_rules.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "MIN_NSE_VERSION" for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, tuple), f"MIN_NSE_VERSION is not a tuple: {value!r}"
            return value
    raise AssertionError("MIN_NSE_VERSION is not assigned at module level in tests/test_nse_rules.py")


def test_the_suite_gate_and_the_install_floor_name_the_same_version() -> None:
    floor, gate = _pyproject_floor(), _min_nse_version()
    assert floor == gate, (
        f"pyproject.toml requires network-sandbox-engine>={'.'.join(map(str, floor))} but "
        f"MIN_NSE_VERSION is {'.'.join(map(str, gate))}. Raise both together."
    )
