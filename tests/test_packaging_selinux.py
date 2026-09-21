# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The packaged installers must agree with the runtime about the SELinux policy.

Issue #50: `scripts/install.sh` carried the same dead version gate as
`is_selinux_module_installed` did - `semodule -l | grep -qE
"ttp_tor_policy[[:space:]]+1\\.2"` - against output that modern policycoreutils
does not produce. Nothing here is executed by the test suite (these run as root,
on a real host, at install time), so the only automatable guard is on their
text. It is a weak test of a strong invariant: the shell and the Python must
not disagree about how the loaded policy is identified.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ttp.selinux import POLICY_VERSION_STAMP

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Every packaged script that touches the policy module.
PACKAGING_SCRIPTS = (
    "scripts/install.sh",
    "scripts/uninstall.sh",
    "packaging/ttp.spec",
)

#: `semodule -l` grepped for something that looks like a version number.
_VERSION_GATE = re.compile(r"semodule\s+-l.*ttp_tor_policy[^\n]*[0-9]+[.\\]+[0-9]")


def _code_lines(text: str) -> list[str]:
    """Drop comments: a gate quoted in a comment is documentation, not a gate.

    Both sh and rpm spec use `#`, so one rule covers every file here.
    """
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def _section(spec: str, name: str) -> str:
    """Return the body of an rpm spec section, e.g. `%post`.

    A section header is a bare `%name` on its own line. Anchoring on that
    distinguishes the `%post` *section* from `%postun`, from the prose in the
    file's header comment, and from the `%systemd_post ttp.service` macro
    inside the body - all three of which a `str.split("%post")` selects instead.
    """
    lines = spec.splitlines()
    header = f"%{name}"
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == header)
    except StopIteration:
        raise AssertionError(f"packaging/ttp.spec has no {header} section") from None
    body: list[str] = []
    for line in lines[start + 1 :]:
        if re.fullmatch(r"%[a-zA-Z_]+", line.strip()):
            break
        body.append(line)
    return "\n".join(body)


@pytest.mark.parametrize("script", PACKAGING_SCRIPTS)
def test_no_packaging_script_asks_semodule_for_a_version(script: str) -> None:
    """`semodule -l` prints no version column; matching one can only fail."""
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    offending = [line.strip() for line in _code_lines(text) if _VERSION_GATE.search(line)]
    assert not offending, f"{script} gates on a version `semodule -l` does not print: {offending}"


def test_the_installer_records_the_policy_version_the_runtime_reads() -> None:
    """A fresh install must not leave the runtime believing the policy is stale.

    `setup_selinux_if_needed` skips the recompile only when TTP's own stamp
    matches the shipped `.te`. An installer that loads the module without
    writing the stamp makes the first `ttp start` recompile it again.
    """
    text = (REPO_ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert str(POLICY_VERSION_STAMP) in text


def test_the_rpm_records_the_policy_version_on_install_and_clears_it_on_removal() -> None:
    spec = (REPO_ROOT / "packaging/ttp.spec").read_text(encoding="utf-8")
    assert str(POLICY_VERSION_STAMP) in _section(spec, "post"), "%post loads the module but records no version"
    assert str(POLICY_VERSION_STAMP) in _section(spec, "preun"), "%preun removes the module but leaves the stamp behind"
