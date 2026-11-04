# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Enforce complete reviewed pins and package compatibility, including markers."""

import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement

ROOT = Path(__file__).parents[1]


def entries(profile):
    content = (ROOT / "requirements" / f"{profile}.txt").read_text()
    return [line.strip() for line in content.splitlines() if line and not line.lstrip().startswith("#")]


@pytest.mark.parametrize("profile", ["tools", "runtime", "ci", "oldest", "docs"])
def test_every_download_has_an_exact_version_and_hash(profile):
    current = None
    hashed = False
    for line in entries(profile):
        line = line.removesuffix("\\").strip()
        if line.startswith("--hash="):
            assert re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", line)
            hashed = True
        else:
            if current is not None:
                assert hashed, f"{profile}: {current} has no reviewed artifact hash"
            current = Requirement(line)
            specs = list(current.specifier)
            assert len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version
            assert current.url is None
            hashed = False
    assert current is not None and hashed


def test_runtime_lock_does_not_raise_the_public_dependency_floor():
    import tomllib

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    locked = {
        r.name.lower(): r
        for line in entries("runtime")
        if not line.startswith("--hash=")
        for r in [Requirement(line.removesuffix("\\").strip())]
    }
    for raw in metadata["project"]["dependencies"]:
        requirement = Requirement(raw)
        version = next(iter(locked[requirement.name.lower()].specifier)).version
        assert version in requirement.specifier


def test_pip_refuses_artifact_with_unreviewed_bytes(tmp_path):
    """A positive control and a one-byte mutation exercise pip's actual hash gate."""
    import hashlib
    import subprocess
    import sys
    import zipfile

    wheel = tmp_path / "ttp_hash_canary-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ttp_hash_canary-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
        archive.writestr(
            "ttp_hash_canary-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: ttp-hash-canary\nVersion: 1.0\n"
        )
    expected = hashlib.sha256(wheel.read_bytes()).hexdigest()
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(f"ttp-hash-canary==1.0 --hash=sha256:{expected}\n")
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--no-deps",
        "--no-index",
        "--no-cache-dir",
        "--require-hashes",
        "--find-links",
        str(tmp_path),
        "-r",
        str(requirements),
    ]
    baseline = subprocess.run([*command, "-d", str(tmp_path / "good")], capture_output=True, text=True)
    assert baseline.returncode == 0, baseline.stderr
    with wheel.open("ab") as stream:
        stream.write(b"x")
    mutated = subprocess.run([*command, "-d", str(tmp_path / "bad")], capture_output=True, text=True)
    assert mutated.returncode != 0
    assert "HASHES" in mutated.stderr and expected in mutated.stderr


def test_audit_includes_inactive_marker_variants(tmp_path):
    import runpy

    batches = runpy.run_path(str(ROOT / "scripts/audit_dependency_locks.py"))["batches"]
    lock = tmp_path / "lock.txt"
    lock.write_text(
        'filelock==4.2.7 ; python_version < "3.13" \\\n --hash=sha256:abc\nfilelock==4.3.0 ; python_version >= "3.13"\n'
    )
    groups = batches([lock])
    assert {pin for group in groups for pin in group} == {"filelock==4.2.7", "filelock==4.3.0"}
    assert len(groups) == 2


def test_audit_tool_has_a_patched_filelock_on_supported_python():
    from packaging.markers import default_environment
    from packaging.version import Version

    pins = [Requirement(line.removesuffix("\\").strip()) for line in entries("ci") if not line.startswith("--hash=")]
    for minor in ("3.12", "3.13", "3.14", "3.15"):
        environment = {**default_environment(), "python_version": minor, "python_full_version": f"{minor}.99"}
        active = [pin for pin in pins if pin.marker is None or pin.marker.evaluate(environment)]
        assert any(pin.name.lower() == "pip-audit" for pin in active)
        for pin in active:
            if pin.name.lower() == "filelock":
                assert Version(next(iter(pin.specifier)).version) >= Version("4.2.1")


def test_python_minimum_excludes_older_interpreters():
    import tomllib

    from packaging.specifiers import SpecifierSet

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    supported = SpecifierSet(metadata["project"]["requires-python"])
    assert "3.10" not in supported
    assert "3.11" not in supported
    assert "3.12" in supported


def test_oldest_input_keeps_compatibility_pins_without_external_includes():
    source = (ROOT / "requirements/oldest.in").read_text()
    assert not any(line.startswith("-r") for line in source.splitlines())
    for line in (ROOT / "packaging/oldest-supported.pins").read_text().splitlines():
        if line and not line.startswith("#"):
            assert line in source.splitlines()
