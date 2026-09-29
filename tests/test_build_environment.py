# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Every artifact TTP releases is built in the same, hash-pinned environment.

pyproject.toml asks for `hatchling>=1.27`, so two builds of the same tag could
use different backends - and different backends produce different wheels. The
release builds through packaging/build_python.sh instead, which installs
packaging/build-requirements.txt with --require-hashes: one version and one set
of SHA-256 digests per package. These tests fail if a build call site stops
using it, or if the file stops pinning what it claims to.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONSTRAINTS = (REPO_ROOT / "packaging/build-requirements.txt").read_text(encoding="utf-8")
HELPER = (REPO_ROOT / "packaging/build_python.sh").read_text(encoding="utf-8")

#: Where TTP's released artifacts are built. The PKGBUILD is not here on purpose:
#: it builds with the distribution's hatchling, as a distribution package does.
BUILD_SITES = ("packaging/release.sh", "packaging/build_deb.sh", "packaging/ttp.spec")


def _requirements() -> dict[str, list[str]]:
    """name==version -> hashes, from the constraints file (continuation lines joined)."""
    body = "\n".join(line for line in CONSTRAINTS.splitlines() if not line.startswith("#"))
    body = body.replace("\\\n", " ")
    out: dict[str, list[str]] = {}
    for line in body.splitlines():
        if not line.strip():
            continue
        spec, *rest = line.split()
        out[spec] = re.findall(r"--hash=sha256:([0-9a-f]{64})", " ".join(rest))
    return out


@pytest.mark.parametrize("site", BUILD_SITES)
def test_every_release_build_goes_through_the_pinned_helper(site):
    text = (REPO_ROOT / site).read_text(encoding="utf-8")
    code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    assert not [line for line in code if re.search(r"python3? -m build\b", line)], (
        f"{site} calls `python -m build` directly, outside the pinned environment"
    )
    assert any("packaging/build_python.sh" in line for line in code), f"{site} does not build through the helper"


def test_the_helper_installs_the_pinned_environment_with_hashes_and_builds_inside_it():
    code = "\n".join(line for line in HELPER.splitlines() if not line.lstrip().startswith("#"))
    assert "--require-hashes" in code and "-r packaging/build-requirements.txt" in code
    assert "-m build --no-isolation" in code, "an isolated build would fetch its own, unpinned backend"


def test_every_requirement_is_an_exact_version_with_digests():
    requirements = _requirements()
    assert requirements
    for spec, hashes in requirements.items():
        assert re.fullmatch(r"[a-z0-9._-]+==[0-9][0-9a-z.]*", spec), f"not an exact pin: {spec}"
        assert hashes, f"{spec} has no --hash"


def test_the_pinned_backend_satisfies_the_floor_in_pyproject():
    floor = re.search(r'requires = \["hatchling>=([0-9.]+)"\]', (REPO_ROOT / "pyproject.toml").read_text())
    assert floor, "pyproject.toml no longer declares a hatchling floor"
    pinned = next(spec.split("==")[1] for spec in _requirements() if spec.startswith("hatchling=="))

    def as_tuple(version: str) -> tuple[int, ...]:
        return tuple(int(part) for part in version.split("."))

    assert as_tuple(pinned) >= as_tuple(floor.group(1))


def test_the_python_distributions_are_built_in_a_digest_pinned_image():
    """The same files compress to different bytes under a different zlib (Fedora
    ships zlib-ng), so only a pinned image makes the wheel and sdist rebuildable
    to the same bytes on someone else's machine."""
    image = re.search(r'PYTHON_BUILD_IMAGE="\$\{PYTHON_BUILD_IMAGE:-([^}]+)\}"', HELPER)
    assert image, "build_python.sh has no default build image"
    assert re.fullmatch(r"[\w./-]+@sha256:[0-9a-f]{64}", image.group(1)), f"not pinned by digest: {image.group(1)}"


def test_only_release_sh_writes_the_published_distributions():
    """release.sh publishes dist/*.whl. build_deb.sh used to build its own wheel
    into dist/ too, natively, and so replaced the one built in the pinned image
    under the same file name: the release shipped a host-dependent wheel."""
    deb = (REPO_ROOT / "packaging/build_deb.sh").read_text(encoding="utf-8")
    calls = [line for line in deb.splitlines() if "build_python.sh" in line and not line.lstrip().startswith("#")]
    assert calls, "build_deb.sh no longer builds its wheel through the helper"
    for call in calls:
        assert " dist" not in call, f"build_deb.sh builds into dist/: {call.strip()}"
