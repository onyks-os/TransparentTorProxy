# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The suite's verdict must not depend on the terminal it runs in.

With FORCE_COLOR set, 11 CLI tests failed: Rich's consoles are built at import
and emitted ANSI escapes into the text the tests assert on. tests/conftest.py
now clears the variable before ttp is imported; this runs a CLI test in a child
pytest with it set, so the guard cannot silently stop working.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("variable", ["FORCE_COLOR", "TTY_COMPATIBLE"])
def test_cli_assertions_hold_with_colour_forced_by_the_environment(variable):
    env = {**os.environ, variable: "1"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_cli_misc.py::test_check_success"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-2000:]
