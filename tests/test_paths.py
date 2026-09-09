# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ``ttp.paths`` - trusted resolution of the binaries TTP runs as root.

The headline test is :func:`test_a_hostile_nft_on_path_is_not_executed`. Without
it, replacing bare names with ``resolve()`` is a refactor; with it, the property
that matters is asserted: **an attacker who controls $PATH cannot choose which
program TTP executes with full privileges.**

That is not a theoretical concern. TTP is invoked through ``sudo``, and while
``sudo`` normally sanitises PATH via ``secure_path``, that is a distribution
default an administrator can switch off - not a security guarantee TTP is
entitled to assume.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp.paths import (
    TRUSTED_DIRS,
    BinaryNotFoundError,
    UnsafeBinaryError,
    clear_cache,
    resolve,
    resolve_optional,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_cache()
    yield
    clear_cache()


def _plant(directory: Path, name: str, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    """Write an executable script - a stand-in for an attacker's binary."""
    path = directory / name
    path.write_text(body)
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------------------
# The attack this module exists to prevent
# ---------------------------------------------------------------------------


def test_a_hostile_nft_on_path_is_not_executed(tmp_path: Path, monkeypatch) -> None:
    """
    An attacker who prepends their own `nft` to $PATH must not get it run as root.

    This is the whole point of the module. Before it, every one of TTP's 47
    subprocess call sites passed a bare name, and the kernel resolved it through
    $PATH.
    """
    evil = _plant(tmp_path, "nft", "#!/bin/sh\necho OWNED\n")
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")

    resolved = resolve("nft")

    assert resolved != str(evil)
    assert resolved.startswith(TRUSTED_DIRS)


def test_the_firewall_really_invokes_the_trusted_binary(tmp_path: Path, monkeypatch) -> None:
    """
    End to end: with a hostile nft first on $PATH, the argv TTP hands to
    subprocess still names the trusted absolute path.

    Asserting on `resolve()` alone would not catch a call site that was missed
    during the migration; this asserts on what is actually executed.
    """
    _plant(tmp_path, "nft", "#!/bin/sh\necho OWNED\n")
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")

    from ttp.firewall import runner

    with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="")) as run:
        runner._run_nft(["list", "ruleset"])

    argv = run.call_args[0][0]
    assert argv[0] == resolve("nft")
    assert argv[0].startswith("/")
    assert str(tmp_path) not in argv[0]


def test_an_empty_path_changes_nothing(monkeypatch) -> None:
    """Resolution must not depend on $PATH at all, not even for the happy case."""
    monkeypatch.setenv("PATH", "")
    assert resolve("nft").startswith(TRUSTED_DIRS)


# ---------------------------------------------------------------------------
# Refusing what it cannot vouch for
# ---------------------------------------------------------------------------


def test_a_missing_binary_raises_and_says_where_it_looked() -> None:
    with pytest.raises(BinaryNotFoundError) as exc:
        resolve("definitely-not-a-real-binary")
    message = str(exc.value)
    assert "/usr/sbin/definitely-not-a-real-binary" in message
    # The message has to explain *why* it did not fall back to PATH, or the next
    # maintainer will "fix" it by adding one.
    assert "$PATH" in message


def test_a_path_argument_is_rejected() -> None:
    """A caller passing a path has made a mistake; accepting it reopens the hole."""
    for bad in ("/usr/sbin/nft", "./nft", "../nft", ""):
        with pytest.raises(ValueError):
            resolve(bad)


def test_a_world_writable_binary_is_refused(tmp_path: Path) -> None:
    """
    Present but replaceable is a finding, not a success. Resolving from a fixed
    directory is pointless if anyone can rewrite what is in it.
    """
    _plant(tmp_path, "nft").chmod(0o777)
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(tmp_path),)),
        pytest.raises(UnsafeBinaryError, match="not owned exclusively by root"),
    ):
        resolve("nft")


def test_a_group_writable_binary_is_refused(tmp_path: Path) -> None:
    _plant(tmp_path, "nft").chmod(0o775)
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(tmp_path),)),
        pytest.raises(UnsafeBinaryError),
    ):
        resolve("nft")


def test_a_binary_in_a_writable_directory_is_refused(tmp_path: Path) -> None:
    """Write access to the directory is enough to replace the file by rename."""
    directory = tmp_path / "bin"
    directory.mkdir(mode=0o777)
    _plant(directory, "nft").chmod(0o755)
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(directory),)),
        pytest.raises(UnsafeBinaryError),
    ):
        resolve("nft")


def test_a_non_executable_file_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "nft").write_text("not a program")
    (tmp_path / "nft").chmod(0o644)
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(tmp_path),)),
        pytest.raises(BinaryNotFoundError),
    ):
        resolve("nft")


def test_a_directory_named_like_the_binary_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "nft").mkdir(mode=0o755)
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(tmp_path),)),
        pytest.raises(BinaryNotFoundError),
    ):
        resolve("nft")


# ---------------------------------------------------------------------------
# resolve_optional
# ---------------------------------------------------------------------------


def test_optional_returns_none_when_absent() -> None:
    assert resolve_optional("definitely-not-a-real-binary") is None


def test_optional_still_refuses_an_unsafe_binary(tmp_path: Path) -> None:
    """
    Absence is tolerable; a replaceable binary is not. Swallowing this would let
    the killswitch's notification path run an attacker's program.
    """
    _plant(tmp_path, "notify-send").chmod(0o777)
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(tmp_path),)),
        pytest.raises(UnsafeBinaryError),
    ):
        resolve_optional("notify-send")


def test_optional_returns_the_path_when_present() -> None:
    assert resolve_optional("nft") == resolve("nft")


# ---------------------------------------------------------------------------
# Search order and caching
# ---------------------------------------------------------------------------


def test_search_order_prefers_the_earlier_trusted_directory(tmp_path: Path) -> None:
    """sbin before bin: on a split-/usr system they are different files."""
    first, second = tmp_path / "a", tmp_path / "b"
    for d in (first, second):
        d.mkdir(mode=0o755)
        _plant(d, "nft")
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(first), str(second))),
        patch("ttp.paths._is_safely_owned", return_value=True),
    ):
        assert resolve("nft") == str(first / "nft")


def test_falls_through_to_the_next_directory_when_absent(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    for d in (first, second):
        d.mkdir(mode=0o755)
    _plant(second, "nft")
    with (
        patch("ttp.paths.TRUSTED_DIRS", (str(first), str(second))),
        patch("ttp.paths._is_safely_owned", return_value=True),
    ):
        assert resolve("nft") == str(second / "nft")


def test_the_result_is_cached() -> None:
    """One stat per binary per process; the hot paths call this in a loop."""
    first = resolve("nft")
    with patch("ttp.paths._is_safely_owned", side_effect=AssertionError("re-checked")):
        assert resolve("nft") == first


def test_clear_cache_forces_a_re_check() -> None:
    resolve("nft")
    clear_cache()
    with (
        patch("ttp.paths.TRUSTED_DIRS", ()),
        pytest.raises(BinaryNotFoundError),
    ):
        resolve("nft")


# ---------------------------------------------------------------------------
# The trusted list itself
# ---------------------------------------------------------------------------


def test_every_trusted_directory_is_absolute() -> None:
    """A relative entry would be resolved against the caller's cwd."""
    for directory in TRUSTED_DIRS:
        assert directory.startswith("/"), directory


def test_no_trusted_directory_is_writable_by_others() -> None:
    """
    A sanity check on the host as much as on the list: if /usr/bin is group
    writable here, every other assumption in this module is void.
    """
    for directory in TRUSTED_DIRS:
        path = Path(directory)
        if not path.exists():
            continue
        mode = path.stat().st_mode
        assert not mode & (stat.S_IWGRP | stat.S_IWOTH), directory


def test_the_binaries_ttp_actually_needs_are_resolvable() -> None:
    """
    The required set. A distribution that puts one of these somewhere else would
    make TTP fail at runtime, and this is where that is discovered.
    """
    for binary in ("nft", "ip", "systemctl", "mount", "umount"):
        assert resolve(binary).startswith("/")


def test_no_source_file_still_invokes_a_bare_binary() -> None:
    """
    The migration guard. `ruff --select S607` is the real check and it runs in
    `make lint`; this asserts it stays selected, because a rule silently dropped
    from the config is how 47 call sites came back.
    """
    result = subprocess.run(
        ["ruff", "check", "--select", "S607", "ttp/", "--output-format", "concise"],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 127:  # pragma: no cover - ruff not installed
        pytest.skip("ruff is not available")
    assert result.returncode == 0, result.stdout
