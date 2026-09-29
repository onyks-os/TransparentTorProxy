#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Write a CycloneDX SBOM next to each built artifact, from the artifact itself.

    python3 packaging/make_sbom.py packaging/*.whl packaging/*.tar.gz packaging/*.deb packaging/*.rpm

The release used to publish one sbom.json made by cdxgen from the checkout. It
described the CI runner's Python environment - rich 15.0.0, typer 0.27.2 - not
any artifact: the .deb uses the distribution's rich, and the .rpm carries a copy
of `transitions` that the file did not mention. This reads what each artifact
really is and declares:

- the artifact itself (name, version, SHA-256) as the described component;
- what it *contains* besides TTP: the copy of `transitions` bundled in the .rpm,
  by version and by the digest of the wheel it was unpacked from;
- what it *requires*, as the artifact declares it: Requires-Dist for the wheel
  and sdist, Depends for the .deb, Requires for the .rpm - with the version
  constraint and who is expected to provide it (pip, or the distribution).

Stdlib only, plus `dpkg-deb` for a .deb and `rpm` for an .rpm. Deterministic:
the serial number derives from the artifact's digest and the timestamp from
SOURCE_DATE_EPOCH when set, so the same artifact gives the same SBOM.
"""

from __future__ import annotations

import email.parser
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile
from pathlib import Path

PACKAGING = Path(__file__).resolve().parent
NAME = "transparent-tor-proxy"
SPEC_VERSION = "1.6"
#: uuid5 namespace for serial numbers: stable, so equal artifacts get equal SBOMs.
SERIAL_NAMESPACE = uuid.UUID("5b0c3d0e-6f8e-4b8a-9d0e-0d1c1f6d7a10")

#: Declared requirements that are not packages: the interpreter and the rpm runtime.
_NOT_A_COMPONENT = re.compile(r"^(rpmlib\(|/|python\(abi\)|python3$|python3\.\d+dist\()")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _bundle_env() -> dict[str, str]:
    text = (PACKAGING / "bundled-transitions.env").read_text(encoding="utf-8")
    return dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))


def _requirement(name: str, constraint: str | None, provided_by: str) -> dict:
    component: dict = {
        "type": "library",
        "bom-ref": f"requires:{provided_by}:{name}",
        "name": name,
        "scope": "required",
        "properties": [{"name": "ttp:provided-by", "value": provided_by}],
    }
    if constraint:
        component["properties"].append({"name": "ttp:version-constraint", "value": constraint})
    return component


def _python_requirements(metadata: str) -> list[dict]:
    message = email.parser.Parser().parsestr(metadata)
    out = []
    for requirement in message.get_all("Requires-Dist") or []:
        if "extra ==" in requirement:
            continue  # optional extras are not what the artifact requires
        m = re.match(r"\s*([A-Za-z0-9._-]+)\s*(.*)", requirement.split(";")[0])
        if m:
            out.append(_requirement(m.group(1).lower(), m.group(2).strip() or None, "pip"))
    return out


def _wheel(path: Path) -> tuple[str, str, list[dict], list[dict]]:
    with zipfile.ZipFile(path) as wheel:
        metadata = next(n for n in wheel.namelist() if n.endswith(".dist-info/METADATA"))
        text = wheel.read(metadata).decode("utf-8")
    version = email.parser.Parser().parsestr(text)["Version"]
    return version, f"pkg:pypi/{NAME}@{version}", [], _python_requirements(text)


def _sdist(path: Path) -> tuple[str, str, list[dict], list[dict]]:
    with tarfile.open(path) as sdist:
        member = next(m for m in sdist.getmembers() if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO"))
        handle = sdist.extractfile(member)
        assert handle is not None
        text = handle.read().decode("utf-8")
    version = email.parser.Parser().parsestr(text)["Version"]
    return version, f"pkg:pypi/{NAME}@{version}?type=sdist", [], _python_requirements(text)


def _deb(path: Path) -> tuple[str, str, list[dict], list[dict]]:
    def field(name: str) -> str:
        return subprocess.run(
            ["dpkg-deb", "-f", str(path), name], check=True, capture_output=True, text=True
        ).stdout.strip()

    version = field("Version")
    requires = []
    for item in field("Depends").split(","):
        m = re.fullmatch(r"\s*([a-z0-9.+-]+)\s*(?:\((.*)\))?\s*", item)
        if m:
            requires.append(_requirement(m.group(1), m.group(2), "distribution"))
    return version, f"pkg:deb/onyks-os/{NAME}@{version}?arch=all", [], requires


def _rpm(path: Path) -> tuple[str, str, list[dict], list[dict]]:
    def query(*args: str) -> list[str]:
        out = subprocess.run(["rpm", "-qp", *args, str(path)], check=True, capture_output=True, text=True).stdout
        return [line.strip() for line in out.splitlines() if line.strip()]

    version, release = query("--queryformat", "%{VERSION}\n%{RELEASE}\n")[:2]
    # The generator's python3.Xdist(name) >= v lines carry the version floors that
    # the plain python3-name Requires do not; fold them onto the named package.
    floors: dict[str, str] = {}
    requires = []
    lines = query("--requires")
    for line in lines:
        m = re.fullmatch(r"python3\.\d+dist\(([a-z0-9._-]+)\) (.+)", line)
        if m:
            floors[f"python3-{m.group(1)}"] = m.group(2)
    for line in lines:
        name, _, constraint = line.partition(" ")
        if not _NOT_A_COMPONENT.match(name):
            requires.append(_requirement(name, constraint or floors.get(name), "distribution"))

    files = query("--list")
    bundle = _bundle_env()
    included = []
    for line in query("--provides"):
        m = re.fullmatch(r"bundled\(python3dist\(([a-z0-9._-]+)\)\) = (\S+)", line)
        if not m:
            continue
        name, bundled_version = m.groups()
        if not any(f"/vendor/{name}/" in f or f.endswith(f"/vendor/{name}") for f in files):
            raise SystemExit(f"{path.name} declares bundled {name} but does not contain it")
        component: dict = {
            "type": "library",
            "bom-ref": f"bundled:{name}",
            "name": name,
            "version": bundled_version,
            "purl": f"pkg:pypi/{name}@{bundled_version}",
            "scope": "required",
            "properties": [
                {"name": "ttp:provided-by", "value": "bundled"},
                {"name": "ttp:location", "value": "/usr/lib/transparent-tor-proxy/vendor"},
            ],
        }
        if name == "transitions" and bundle.get("TRANSITIONS_VERSION") == bundled_version:
            component["hashes"] = [{"alg": "SHA-256", "content": bundle["TRANSITIONS_SHA256"]}]
            component["licenses"] = [{"license": {"id": "MIT"}}]
            component["properties"].append({"name": "ttp:unpacked-from", "value": bundle["TRANSITIONS_WHEEL"]})
        included.append(component)
    return f"{version}-{release}", f"pkg:rpm/onyks-os/{NAME}@{version}-{release}?arch=noarch", included, requires


READERS = {".whl": _wheel, ".tar.gz": _sdist, ".deb": _deb, ".rpm": _rpm}


def sbom_for(path: Path) -> dict:
    reader = next((r for suffix, r in READERS.items() if path.name.endswith(suffix)), None)
    if reader is None:
        raise SystemExit(f"do not know how to describe {path.name}")
    version, purl, included, requires = reader(path)
    digest = _sha256(path)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    subject = {
        "type": "application",
        "bom-ref": "artifact",
        "name": NAME,
        "version": version,
        "purl": purl,
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "licenses": [{"license": {"id": "MIT"}}],
        "properties": [{"name": "ttp:artifact", "value": path.name}],
    }
    components = included + requires
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(SERIAL_NAMESPACE, digest)}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
            "tools": {"components": [{"type": "application", "name": "packaging/make_sbom.py"}]},
            "component": subject,
        },
        "components": components,
        "dependencies": [
            {"ref": "artifact", "dependsOn": [c["bom-ref"] for c in components]},
            *({"ref": c["bom-ref"]} for c in components),
        ],
    }


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    for arg in argv:
        path = Path(arg)
        out = path.with_name(path.name + ".cdx.json")
        out.write_text(json.dumps(sbom_for(path), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
