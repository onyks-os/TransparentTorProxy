# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""`transitions` is the watchdog's dependency, not the rest of TTP's.

The native packages never declared it, and `ttp stop` imported the watchdog
package, which imported `transitions` at module level, outside any `try`. On a
host without it, `ttp stop` raised before tearing anything down. These tests pin
the three properties that make that impossible: the watchdog package imports
without `transitions`; teardown does not depend on the watchdog package importing
at all; and `start --watchdog` refuses before changing anything when the watchdog
could not run. They also cover the private directory the .rpm and the PKGBUILD
bundle `transitions` into, for distributions that do not ship it.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import ttp
from ttp.cli import app
from ttp.commands import lifecycle

runner = CliRunner()

# Runs in a fresh interpreter so that no module is already imported. The finder
# makes `transitions` importable only from the vendor directory, and only once
# that directory is on sys.path: exactly a host whose distribution has no
# `transitions` and whose package bundled one - or, with no vendor directory,
# a host that has neither.
_WITHOUT_SYSTEM_TRANSITIONS = textwrap.dedent(
    """
    import importlib.machinery
    import sys

    VENDOR = sys.argv[1]

    class OnlyTheVendoredCopy:
        def find_spec(self, name, path=None, target=None):
            if name != "transitions":
                return None
            spec = importlib.machinery.PathFinder.find_spec(name, [p for p in sys.path if p == VENDOR])
            if spec is None:
                raise ModuleNotFoundError("No module named 'transitions'", name=name)
            return spec

    sys.meta_path.insert(0, OnlyTheVendoredCopy())
    """
)


def _run_without_system_transitions(vendor: Path, body: str) -> subprocess.CompletedProcess[str]:
    code = _WITHOUT_SYSTEM_TRANSITIONS + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", code, str(vendor)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _fake_vendored_transitions(root: Path) -> Path:
    package = root / "transitions"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("class Machine:\n    pass\n", encoding="utf-8")
    return root


def test_the_watchdog_package_imports_without_transitions(tmp_path):
    """Everything `ttp stop` and `ttp watchdog stop|status` touch must import."""
    result = _run_without_system_transitions(
        tmp_path / "no-vendor-dir",
        """
        from ttp.watchdog import fsm
        fsm.VENDOR_DIR = __import__("pathlib").Path(sys.argv[1])

        import ttp.commands.lifecycle
        import ttp.commands.watchdog
        from ttp import watchdog

        assert not fsm.watchdog_dependency_available()
        try:
            fsm.WatchdogFSM()
        except fsm.WatchdogUnavailableError as e:
            print("REFUSED:", e)
        else:
            raise SystemExit("WatchdogFSM() constructed without transitions")
        """,
    )
    assert result.returncode == 0, result.stderr
    assert "REFUSED:" in result.stdout
    assert "transitions" in result.stdout


def test_a_bundled_copy_is_used_when_the_system_has_none(tmp_path):
    vendor = _fake_vendored_transitions(tmp_path / "vendor")
    result = _run_without_system_transitions(
        vendor,
        """
        from pathlib import Path
        from ttp.watchdog import fsm

        fsm.VENDOR_DIR = Path(sys.argv[1])
        assert fsm.watchdog_dependency_available()
        machine = fsm.load_machine()
        print("FROM:", sys.modules[machine.__module__].__file__)
        """,
    )
    assert result.returncode == 0, result.stderr
    assert f"FROM: {vendor}" in result.stdout


def test_the_system_copy_wins_over_a_bundled_one(tmp_path, monkeypatch):
    """The bundle is a fallback. A distribution's own `transitions` is preferred."""
    import transitions

    from ttp.watchdog import fsm

    monkeypatch.setattr(fsm, "VENDOR_DIR", _fake_vendored_transitions(tmp_path / "vendor"))
    assert fsm.load_machine() is transitions.Machine
    assert str(tmp_path) not in sys.path


def _without_the_watchdog_package(monkeypatch):
    """Make `from ttp import watchdog` raise, as a missing dependency would."""
    monkeypatch.delattr(ttp, "watchdog", raising=False)
    monkeypatch.setitem(sys.modules, "ttp.watchdog", None)


def test_do_stop_tears_down_when_the_watchdog_cannot_be_imported(monkeypatch):
    _without_the_watchdog_package(monkeypatch)
    with (
        patch("ttp.state.read_lock", return_value={"pid": 1, "tor_uid": 107}),
        patch("ttp.commands.lifecycle.firewall") as firewall,
        patch("ttp.commands.lifecycle.tor_install"),
        patch("ttp.commands.lifecycle.dns") as dns,
        patch("ttp.commands.lifecycle.resolve_optional", return_value=None),
        patch("ttp.state.delete_lock") as delete_lock,
    ):
        lifecycle.do_stop()

    firewall.destroy_rules.assert_called_once()
    dns.restore_dns.assert_called_once()
    delete_lock.assert_called_once()


def test_restore_only_tears_down_when_the_watchdog_cannot_be_imported(monkeypatch):
    _without_the_watchdog_package(monkeypatch)
    with (
        patch("os.geteuid", return_value=0),
        patch("ttp.cli._setup_logging"),
        patch("ttp.state.read_lock", return_value=None),
        patch("ttp.tor_install.stop_tor_service"),
        patch("ttp.firewall.destroy_rules") as destroy_rules,
        patch("ttp.dns.restore_dns"),
        patch("ttp.state.delete_lock") as delete_lock,
    ):
        result = runner.invoke(app, ["stop", "--restore-only"])

    assert result.exit_code == 0, result.output
    destroy_rules.assert_called_once()
    delete_lock.assert_called_once()


def test_start_with_watchdog_refuses_before_changing_anything_when_it_cannot_run():
    """Found missing after the rules are loaded, the watchdog would be a warning
    printed over a session the user asked to have watched. Refuse first."""
    with (
        patch("os.geteuid", return_value=0),
        patch("ttp.cli._setup_logging"),
        patch("ttp.commands.start.require_systemd"),
        patch("ttp.watchdog.fsm.watchdog_dependency_available", return_value=False),
        patch("ttp.commands.start.preflight_checks") as preflight,
        patch("ttp.firewall.apply_rules") as apply_rules,
    ):
        result = runner.invoke(app, ["start", "--watchdog"])

    assert result.exit_code == 1
    assert "transitions" in result.output
    preflight.assert_not_called()
    apply_rules.assert_not_called()


def test_watchdog_start_refuses_when_it_cannot_run():
    with (
        patch("os.geteuid", return_value=0),
        patch("ttp.cli._setup_logging"),
        patch("ttp.state.read_lock", return_value={"pid": 1}),
        patch("ttp.watchdog.fsm.watchdog_dependency_available", return_value=False),
        patch("ttp.watchdog.start_watchdog") as start_watchdog,
    ):
        result = runner.invoke(app, ["watchdog", "start"])

    assert result.exit_code == 1
    assert "transitions" in result.output
    start_watchdog.assert_not_called()


@pytest.mark.parametrize("command", [["start", "--watchdog"], ["watchdog", "start"]])
def test_the_refusal_names_what_to_install(command):
    with (
        patch("os.geteuid", return_value=0),
        patch("ttp.cli._setup_logging"),
        patch("ttp.commands.start.require_systemd"),
        patch("ttp.state.read_lock", return_value={"pid": 1}),
        patch("ttp.watchdog.fsm.watchdog_dependency_available", return_value=False),
    ):
        result = runner.invoke(app, command)

    assert "python3-transitions" in result.output
