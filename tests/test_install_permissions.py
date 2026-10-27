# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Exercise the installer's permissions repair on real files, including a venv symlink."""

import os
import stat
import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[1] / "scripts/install-permissions.sh"


@pytest.mark.parametrize("mask", [0o027, 0o077])
def test_install_permissions_repair_restrictive_tree_without_touching_symlink_target(tmp_path, mask):
    install = tmp_path / "ttp"
    interpreter = tmp_path / "system-python"
    interpreter.write_text("system interpreter sentinel")
    interpreter.chmod(0o700)
    old_mask = os.umask(mask)
    try:
        binary = install / "venv/bin"
        package = install / "venv/lib/python/site-packages/ttp"
        binary.mkdir(parents=True)
        package.mkdir(parents=True)
        (binary / "python").symlink_to(interpreter)
        entry = binary / "ttp"
        entry.write_text("#!/bin/sh\nexit 0\n")
        entry.chmod(0o700)
        module = package / "netprobe.py"
        module.write_text("# public Python code\n")
        # An existing incorrectly writable file must not stay writable either.
        metadata = install / "venv/pyvenv.cfg"
        metadata.write_text("include-system-site-packages = false\n")
        metadata.chmod(0o666)
        subprocess.run(
            ["bash", "-c", 'source "$1"; ttp_install_permissions "$2"', "test", str(HELPER), str(install)],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        os.umask(old_mask)
    assert stat.S_IMODE(install.stat().st_mode) == 0o755
    for path in install.rglob("*"):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode & 0o044 == 0o044, path
        assert mode & 0o022 == 0, path
        if path.is_dir() or path == entry:
            assert mode & 0o111 == 0o111, path
    assert stat.S_IMODE(module.stat().st_mode) == 0o644
    assert stat.S_IMODE(interpreter.stat().st_mode) == 0o700
