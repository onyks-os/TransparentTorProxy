# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Each release SBOM must describe its artifact, not the machine that built it.

0.4.9's single sbom.json came from cdxgen run on the checkout: it listed the CI
runner's rich 15.0.0 and typer 0.27.2, neither of which is in the .deb (it uses
the distribution's) and omitted the `transitions` the .rpm bundles. These tests
feed packaging/make_sbom.py artifacts - real archives for the wheel and sdist,
recorded `dpkg-deb`/`rpm` answers for the native packages - and check what it
declares, and that every result is valid CycloneDX.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("make_sbom", REPO_ROOT / "packaging/make_sbom.py")
assert _spec and _spec.loader
make_sbom = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_sbom)

METADATA = """\
Metadata-Version: 2.4
Name: transparent-tor-proxy
Version: 9.9.9
Requires-Dist: rich>=13.7.1
Requires-Dist: transitions>=0.9.0
Requires-Dist: pytest>=9.1.1; extra == 'dev'
"""


def _valid(bom: dict) -> None:
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert error is None, error


def _components(bom: dict) -> dict[str, dict]:
    return {c["name"]: c for c in bom["components"]}


def _props(component: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in component["properties"]}


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    path = tmp_path / "transparent_tor_proxy-9.9.9-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("transparent_tor_proxy-9.9.9.dist-info/METADATA", METADATA)
    return path


@pytest.fixture
def sdist(tmp_path: Path) -> Path:
    path = tmp_path / "transparent_tor_proxy-9.9.9.tar.gz"
    data = METADATA.encode()
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("transparent_tor_proxy-9.9.9/PKG-INFO")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return path


@pytest.mark.parametrize("fixture", ["wheel", "sdist"])
def test_a_python_distribution_declares_its_runtime_requirements_not_its_extras(fixture, request):
    bom = make_sbom.sbom_for(request.getfixturevalue(fixture))
    _valid(bom)
    components = _components(bom)
    assert set(components) == {"rich", "transitions"}, "an extra is not a runtime requirement"
    assert _props(components["rich"]) == {"ttp:provided-by": "pip", "ttp:version-constraint": ">=13.7.1"}
    assert bom["metadata"]["component"]["version"] == "9.9.9"


def test_the_described_artifact_is_identified_by_its_digest(wheel):
    bom = make_sbom.sbom_for(wheel)
    assert bom["metadata"]["component"]["hashes"] == [{"alg": "SHA-256", "content": make_sbom._sha256(wheel)}]


def test_the_same_artifact_gives_the_same_sbom(wheel, monkeypatch):
    """A release should be rebuildable to identical bytes, the SBOM included."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790000000")
    first = make_sbom.sbom_for(wheel)
    second = make_sbom.sbom_for(wheel)
    assert first == second
    assert first["metadata"]["timestamp"] == "2026-09-21T14:13:20Z"


def _fake(outputs: dict[tuple[str, ...], str]):
    def run(argv, **kwargs):
        # rpm -qp <args...> <path>  |  dpkg-deb -f <path> <field>
        key = tuple(argv[:-1]) if argv[0] == "rpm" else tuple(argv[3:])
        for prefix, out in outputs.items():
            if key[: len(prefix)] == prefix:
                return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
        raise AssertionError(f"unexpected call {argv}")

    return run


def _rpm_outputs(files: str) -> dict[tuple[str, ...], str]:
    bundle = make_sbom._bundle_env()
    return {
        ("rpm", "-qp", "--queryformat"): "9.9.9\n1.fc44\n",
        ("rpm", "-qp", "--requires"): "\n".join(
            [
                "/usr/bin/python3",
                "python(abi) = 3.14",
                "python3-rich",
                "python3.14dist(rich) >= 13.7.1",
                "tor",
                "rpmlib(CompressedFileNames) <= 3.0.4-1",
            ]
        ),
        ("rpm", "-qp", "--list"): files,
        ("rpm", "-qp", "--provides"): f"bundled(python3dist(transitions)) = {bundle['TRANSITIONS_VERSION']}\n",
    }


def test_the_rpm_declares_the_copy_of_transitions_it_carries(tmp_path, monkeypatch):
    rpm = tmp_path / "transparent-tor-proxy-9.9.9-1.fc44.noarch.rpm"
    rpm.write_bytes(b"not really an rpm")
    files = "/usr/lib/transparent-tor-proxy/vendor/transitions/core.py\n/usr/bin/ttp\n"
    monkeypatch.setattr(make_sbom.subprocess, "run", _fake(_rpm_outputs(files)))

    bom = make_sbom.sbom_for(rpm)
    _valid(bom)
    components = _components(bom)
    bundle = make_sbom._bundle_env()

    bundled = components["transitions"]
    assert bundled["version"] == bundle["TRANSITIONS_VERSION"]
    assert bundled["hashes"] == [{"alg": "SHA-256", "content": bundle["TRANSITIONS_SHA256"]}]
    assert _props(bundled)["ttp:provided-by"] == "bundled"

    # The interpreter and the rpm runtime are not components; the generated
    # python3.Xdist floor is folded onto the package that provides it.
    assert set(components) == {"transitions", "python3-rich", "tor"}
    assert _props(components["python3-rich"])["ttp:version-constraint"] == ">= 13.7.1"


def test_an_rpm_that_declares_a_bundle_it_does_not_contain_is_refused(tmp_path, monkeypatch):
    rpm = tmp_path / "transparent-tor-proxy-9.9.9-1.fc44.noarch.rpm"
    rpm.write_bytes(b"x")
    monkeypatch.setattr(make_sbom.subprocess, "run", _fake(_rpm_outputs("/usr/bin/ttp\n")))
    with pytest.raises(SystemExit, match="does not contain it"):
        make_sbom.sbom_for(rpm)


def test_the_deb_declares_what_it_depends_on_with_its_floors(tmp_path, monkeypatch):
    deb = tmp_path / "transparent-tor-proxy_9.9.9_all.deb"
    deb.write_bytes(b"x")
    monkeypatch.setattr(
        make_sbom.subprocess,
        "run",
        _fake(
            {
                ("Version",): "9.9.9\n",
                ("Depends",): "python3, python3-rich (>= 13.7.1), python3-transitions (>= 0.9.0), tor\n",
            }
        ),
    )
    bom = make_sbom.sbom_for(deb)
    _valid(bom)
    components = _components(bom)
    assert _props(components["python3-transitions"]) == {
        "ttp:provided-by": "distribution",
        "ttp:version-constraint": ">= 0.9.0",
    }
    assert "transitions" not in components, "the .deb bundles nothing"


def test_the_release_publishes_and_signs_the_per_artifact_sboms():
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "cdxgen" not in workflow
    assert workflow.count("packaging/*.cdx.json") >= 3  # validated, signed, published
