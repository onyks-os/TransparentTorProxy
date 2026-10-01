# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Every runtime dependency in pyproject.toml must reach every native package.

`transitions` was added to pyproject.toml for the watchdog and never to the
.deb, the .rpm or the PKGBUILD. The .deb installed and then could not build the
watchdog - nor run `ttp stop`, which imported it. The .rpm's generated
dependencies asked for a `transitions` (and a `rich`) that no Fedora release
provides, so it could not be installed at all. Both shipped from 0.4.7 on.

`packaging/smoke_test.sh` installs the built packages in CI; this is the
fast, static half: it reads the packaging files and fails as soon as a
dependency is added to one place and not the others.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ttp.watchdog.fsm import VENDOR_DIR

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
BUILD_DEB = (REPO_ROOT / "packaging/build_deb.sh").read_text(encoding="utf-8")
SPEC = (REPO_ROOT / "packaging/ttp.spec").read_text(encoding="utf-8")
PKGBUILD = (REPO_ROOT / "packaging/PKGBUILD").read_text(encoding="utf-8")
BUILD_RPM = (REPO_ROOT / "packaging/build_rpm.sh").read_text(encoding="utf-8")
OLDEST = dict(
    line.split("==", 1)
    for line in (REPO_ROOT / "packaging/oldest-supported.pins").read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
)
BUNDLE = dict(
    line.split("=", 1)
    for line in (REPO_ROOT / "packaging/bundled-transitions.env").read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
)

#: Python packages the native packages bundle rather than depend on, per format.
BUNDLED_IN = {"rpm": {"transitions"}, "arch": {"transitions"}, "deb": set()}


def _runtime_dependencies() -> dict[str, str]:
    """name -> floor, from [project] dependencies. tomllib is 3.11+; CI runs 3.10."""
    block = re.search(r"^dependencies = \[(.*?)^\]", PYPROJECT, re.MULTILINE | re.DOTALL)
    assert block, "no [project] dependencies list in pyproject.toml"
    deps = re.findall(r'^\s*"([A-Za-z0-9_.-]+)>=([0-9.]+)', block.group(1), re.MULTILINE)
    assert deps, "no dependencies parsed from pyproject.toml"
    return dict(deps)


def _deb_depends() -> dict[str, str | None]:
    line = re.search(r"^Depends: (.*)$", BUILD_DEB, re.MULTILINE)
    assert line, "no Depends: line in build_deb.sh"
    out: dict[str, str | None] = {}
    for item in line.group(1).split(","):
        m = re.fullmatch(r"\s*([a-z0-9.+-]+)(?:\s*\(>=\s*([0-9.]+)\))?\s*", item)
        assert m, f"unparseable Depends entry: {item!r}"
        out[m.group(1)] = m.group(2)
    return out


def _spec_requires() -> set[str]:
    return set(re.findall(r"^Requires:\s+(\S+)", SPEC, re.MULTILINE))


def _arch_depends() -> set[str]:
    m = re.search(r"^depends=\((.*?)\)", PKGBUILD, re.MULTILINE | re.DOTALL)
    assert m, "no depends=() in PKGBUILD"
    return set(re.findall(r"'([^']+)'", m.group(1)))


@pytest.mark.parametrize("name", sorted(_runtime_dependencies()))
def test_the_deb_depends_on_every_runtime_dependency(name):
    assert f"python3-{name}" in _deb_depends(), (
        f"pyproject.toml requires {name!r} but the .deb does not depend on python3-{name}"
    )


@pytest.mark.parametrize("name", sorted(_runtime_dependencies()))
def test_the_rpm_requires_or_bundles_every_runtime_dependency(name):
    if name in BUNDLED_IN["rpm"]:
        assert f"Provides:       bundled(python3dist({name}))" in SPEC
    else:
        assert f"python3-{name}" in _spec_requires(), f"the .rpm does not require python3-{name}"


@pytest.mark.parametrize("name", sorted(_runtime_dependencies()))
def test_the_pkgbuild_depends_on_or_bundles_every_runtime_dependency(name):
    if name in BUNDLED_IN["arch"]:
        assert f"_{name}_whl=" in PKGBUILD
    else:
        assert f"python-{name}" in _arch_depends(), f"the PKGBUILD does not depend on python-{name}"


def test_versioned_deb_floors_match_pyproject():
    """A floor stated in two places must be the same floor."""
    floors = _runtime_dependencies()
    for package, version in _deb_depends().items():
        if version is None or not package.startswith("python3-"):
            continue
        name = package.removeprefix("python3-")
        assert floors.get(name) == version, f"{package} (>= {version}) but pyproject says {name}>={floors.get(name)}"


def test_the_rpm_does_not_require_the_bundled_packages_it_cannot_resolve():
    """The generator derives python3dist(transitions) from ttp's metadata;
    no Fedora package provides it, so it must be excluded - the bundle covers it."""
    exclude = re.search(r"^%global __requires_exclude (.+)$", SPEC, re.MULTILINE)
    assert exclude, "no __requires_exclude in ttp.spec"
    pattern = exclude.group(1).replace("\\\\", "\\")
    for name in BUNDLED_IN["rpm"]:
        assert re.search(pattern, f"python3.14dist({name})"), exclude.group(1)
    assert not re.search(pattern, "python3.14dist(rich)"), "the exclusion must not hide real dependencies"


def test_the_bundle_goes_where_ttp_looks_for_it():
    assert f"{VENDOR_DIR}/" in SPEC
    assert str(VENDOR_DIR) in PKGBUILD


def test_the_pkgbuild_bundles_the_same_wheel_as_the_rpm():
    assert f"_transitions_whl={BUNDLE['TRANSITIONS_WHEEL']}" in PKGBUILD
    assert BUNDLE["TRANSITIONS_URL"].replace(BUNDLE["TRANSITIONS_WHEEL"], "${_transitions_whl}") in PKGBUILD
    assert f"sha256sums=('{BUNDLE['TRANSITIONS_SHA256']}')" in PKGBUILD
    assert BUNDLE["TRANSITIONS_WHEEL"] == f"transitions-{BUNDLE['TRANSITIONS_VERSION']}-py2.py3-none-any.whl"


def test_the_rpm_build_refuses_a_wheel_with_another_digest():
    assert "sha256sum -c" in BUILD_RPM and "TRANSITIONS_SHA256" in BUILD_RPM


def test_the_bundled_version_satisfies_the_floor():
    floor = tuple(int(p) for p in _runtime_dependencies()["transitions"].split("."))
    bundled = tuple(int(p) for p in BUNDLE["TRANSITIONS_VERSION"].split("."))
    assert bundled >= floor


@pytest.mark.parametrize("name", sorted(_runtime_dependencies()))
def test_every_floor_is_the_version_ci_tests_against(name):
    """A floor nobody has run the suite against is a guess."""
    assert OLDEST.get(name) == _runtime_dependencies()[name], (
        f"pyproject says {name}>={_runtime_dependencies()[name]}, "
        f"packaging/oldest-supported.pins pins {OLDEST.get(name)}"
    )


def test_the_pkgbuild_does_not_list_the_checkout_as_a_source():
    """makepkg rejects a directory source ("local-source was not found in the
    build directory"): the documented `makepkg -si` built nothing."""
    code = "\n".join(line for line in PKGBUILD.splitlines() if not line.lstrip().startswith("#"))
    assert "local-source" not in code
    assert 'cd "$startdir/.."' in PKGBUILD


def test_the_oldest_supported_pins_are_not_a_file_dependabot_updates():
    """Dependabot raises any pins it finds in a requirements-like .txt to the
    newest releases. Here that would silently turn the oldest-supported job into
    a newest-supported one."""
    assert not (REPO_ROOT / "packaging/oldest-supported.txt").exists()
    assert (REPO_ROOT / "packaging/oldest-supported.pins").exists()


def test_the_indirect_pins_are_ubuntu_24_04s_too():
    """six and click are not floors in pyproject.toml, so the floor test above
    does not see them; their pins must still be the oldest distribution's."""
    assert OLDEST["six"] == "1.16.0"
    assert OLDEST["click"] == "8.1.6"
