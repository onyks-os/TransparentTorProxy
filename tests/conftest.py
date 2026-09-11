# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Shared fixtures.

The one thing here worth reading is :func:`deterministic_binary_lookup`.

Why a unit test must never ask the host where a binary lives
------------------------------------------------------------

TTP resolves every binary it executes against a fixed list of trusted
directories (see :mod:`ttp.paths`). Tests then need to assert that production
passed the resolved absolute path rather than a bare name.

The obvious way to write that assertion is the wrong one::

    assert argv[0] == resolve("semodule")     # DON'T

That asks the machine running the tests what the answer should be. On a Fedora
workstation with the SELinux tools installed it passes; on a CI runner without
them ``resolve()`` raises ``BinaryNotFoundError`` *from inside the assertion*,
and the test fails for a reason that has nothing to do with the code under
test. Six tests failed exactly this way, and they failed only in CI - the worst
possible place to discover it.

The deeper problem is that such a test is not checking anything. Production
calls ``resolve("semodule")`` and the assertion calls ``resolve("semodule")``;
they agree by construction, on any host, whatever the function returns. It
would keep passing if ``resolve()`` started returning bare names again - the
exact regression the module exists to prevent.

So this fixture removes the host from the picture entirely. Every binding of
``resolve``/``resolve_optional``, in production *and* in the test modules, is
replaced with a fake that maps any name to a throwaway directory, creating an
inert ``exit 0`` shim there on first use.

A shim rather than a bare made-up path, for a reason worth recording. The first
version of this fixture returned ``/nonexistent/trusted/bin/<name>``, and seven
tests that had always passed started failing with ``FileNotFoundError``. They
were not broken by the change: they were unit tests that had been shelling out
to the real machine all along - ``ip route show default`` from the watchdog
loop, ``nft`` from the teardown lockdown, and ``wall``, which broadcasts to
every logged-in terminal, on the emergency path. They passed because a
developer workstation happens to have those binaries. Pointing them at an inert
shim keeps them honest *and* stops ``make test`` from touching the host.

Each binary still gets its own distinct path, so an assertion can tell ``nft``
from ``ip``, and the directory is nowhere near ``$PATH`` or a trusted dir, so
production only ever finds it by genuinely routing the lookup through
:mod:`ttp.paths`.

Tests that need the real resolver - :mod:`tests.test_paths`, which is its unit
test, and the integration suites, which execute actual binaries - opt out with
``@pytest.mark.real_binary_lookup``.
"""

from __future__ import annotations

import shutil
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import ttp.paths

#: Where the inert shims live. Created once per test session.
_shim_dir: Path | None = None


def _shim_root() -> Path:
    global _shim_dir
    if _shim_dir is None:
        _shim_dir = Path(tempfile.mkdtemp(prefix="ttp-test-bin-"))
    return _shim_dir


def stub_path(binary: str) -> str:
    """
    The path the fake resolver returns for *binary*, creating the shim.

    The shim succeeds and prints nothing. A test that cares what the command
    outputs must mock :mod:`subprocess` itself - which it should be doing
    anyway, since this is a unit test.
    """
    shim = _shim_root() / binary
    if not shim.exists():
        shim.write_text("#!/bin/sh\nexit 0\n")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(shim)


def _fake_resolve(binary: str) -> str:
    if not binary or "/" in binary:
        raise ValueError(f"resolve() takes a bare binary name, not {binary!r}")
    return stub_path(binary)


def _fake_resolve_optional(binary: str) -> str | None:
    return _fake_resolve(binary)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "real_binary_lookup: use the real ttp.paths resolver instead of the deterministic stub",
    )


@pytest.fixture(autouse=True)
def deterministic_binary_lookup(request: pytest.FixtureRequest):
    """
    Make binary resolution independent of the machine running the tests.

    Modules bind the resolver at import time (``from ttp.paths import
    resolve``), so patching :mod:`ttp.paths` alone would leave every one of
    those bindings pointing at the real function. Instead this walks every
    loaded module and replaces the attributes that *are* the real resolver -
    an identity check, so an unrelated ``resolve`` (``Path.resolve``, say) is
    never touched. Test modules are rebound too, which is what lets an
    assertion spell the expectation as ``resolve("nft")`` and still not
    consult the host.

    A test that stubs the lookup itself still wins: its ``patch`` is entered
    after this fixture.
    """
    if request.node.get_closest_marker("real_binary_lookup"):
        yield
        return

    real = {
        "resolve": ttp.paths.resolve,
        "resolve_optional": ttp.paths.resolve_optional,
    }
    fake = {
        "resolve": _fake_resolve,
        "resolve_optional": _fake_resolve_optional,
    }

    patches = [
        patch.object(module, attr, fake[attr])
        for module in list(sys.modules.values())
        if module is not None
        for attr in real
        if getattr(module, attr, None) is real[attr]
    ]

    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in patches:
            p.stop()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Remove the shim directory. Leaving one per run behind would fill /tmp."""
    global _shim_dir
    if _shim_dir is not None:
        shutil.rmtree(_shim_dir, ignore_errors=True)
        _shim_dir = None
