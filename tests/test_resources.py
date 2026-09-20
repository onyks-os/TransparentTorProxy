# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for internal resource management.

These tests verify that embedded files (like SELinux policies) are
correctly accessible via importlib.resources.
"""

import importlib.resources
from pathlib import Path


def test_selinux_policy_resource_exists():
    """Verify that the SELinux policy .te file is accessible."""
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath("ttp_tor_policy.te")
    assert traversable.exists()
    assert traversable.is_file()

    # Verify we can read content
    content = traversable.read_text(encoding="utf-8")
    assert "module ttp_tor_policy" in content
    assert "require {" in content


def test_selinux_resource_as_file():
    """Verify that as_file context manager works (needed for subprocesses)."""
    traversable = importlib.resources.files("ttp.resources.selinux").joinpath("ttp_tor_policy.te")
    with importlib.resources.as_file(traversable) as te_path:
        assert isinstance(te_path, Path)
        assert te_path.exists()
        assert te_path.suffix == ".te"


def _sockets_the_labeller_relabels() -> set[tuple[str, str]]:
    """Return the ``(selinux_type, proto)`` pairs ``label_ports_selinux`` asks for.

    Derived from the labeller's own ``semanage`` invocations rather than
    hardcoded, so the policy assertion below tracks the labelling if it
    ever moves to a different type or protocol.
    """
    from unittest.mock import MagicMock, patch

    from ttp.tor_install import label_ports_selinux

    pairs: set[tuple[str, str]] = set()
    with (
        patch("ttp.selinux.resolve_optional", side_effect=lambda binary: f"/usr/sbin/{binary}"),
        patch("ttp.selinux.subprocess.run", return_value=MagicMock(returncode=0)) as run,
    ):
        label_ports_selinux(9041, 9054)
        for call in run.call_args_list:
            argv = call.args[0]
            pairs.add((argv[argv.index("-t") + 1], argv[argv.index("-p") + 1]))
    return pairs


def test_policy_grants_bind_on_the_type_the_ports_are_relabelled_to():
    """The module must cover ``tor_port_t``, not only ``unreserved_port_t``.

    ``label_ports_selinux`` moves TTP's TransPort and DNSPort to ``tor_port_t``,
    which takes them *out* of ``unreserved_port_t``. A grant written only for
    ``unreserved_port_t`` is therefore cancelled by the very relabelling meant
    to make the bind legal: Fedora's base policy lets ``tor_t`` bind a
    ``tor_port_t`` TCP socket but not a UDP one, so the DNSPort bind is denied,
    Tor exits while parsing its config, and the control socket it would have
    opened never appears - leaving ``ttp start`` waiting at 0% bootstrap.
    """
    content = (
        importlib.resources.files("ttp.resources.selinux").joinpath("ttp_tor_policy.te").read_text(encoding="utf-8")
    )
    rules = {" ".join(line.split()) for line in content.splitlines()}

    pairs = _sockets_the_labeller_relabels()
    assert pairs, "the labeller issued no semanage call to derive the invariant from"

    for selinux_type, proto in sorted(pairs):
        assert f"allow tor_t {selinux_type}:{proto}_socket name_bind;" in rules, (
            f"ports relabelled to {selinux_type} have no {proto}_socket name_bind grant"
        )
