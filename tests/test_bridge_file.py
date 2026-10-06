# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""--bridge-file must not let `sudo ttp` read files its caller cannot.

`ttp start` runs as root, and it opened --bridge-file as root. Two ways out:
a rejected line was printed verbatim in the error, and a line whose first token
merely contained ':' was *accepted* - every line of /etc/shadow does - and
written into the torrc as a Bridge. Where sudo is granted for `ttp` alone, that
read root-only files. The file is now read with the invoking user's
privileges, a bridge address must be an IP and a port, and errors name the line
number, never its content.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from ttp.commands import _tor_setup
from ttp.commands._validation import validate_bridge_line

SHADOW_LIKE = [
    "root:$y$j9T$Kx0abcdefghijklmn$0123456789abcdefghijklmnopqrstuvwxyzABCDEF:19700:0:99999:7:::",
    "daemon:*:19700:0:99999:7:::",
    "admin:$6$salt$hash:19700::::::",
]


@pytest.mark.parametrize("line", SHADOW_LIKE)
def test_a_shadow_line_is_not_a_bridge(line):
    with pytest.raises(ValueError):
        validate_bridge_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "localhost:9001",  # Tor takes an address, not a hostname, in a Bridge line
        "bridge.example:443",
        "192.0.2.10:0",
        "192.0.2.10:65536",
        "192.0.2.10:port",
        "999.0.2.10:9001",
        "obfs4 root:x:0:0 cert=a",
        "[2001:db8::1]",
        "[192.0.2.10]:9001",  # brackets are for IPv6 only
    ],
)
def test_a_bridge_address_must_be_an_ip_and_a_port(line):
    with pytest.raises(ValueError):
        validate_bridge_line(line)


def _as_root_via_sudo(monkeypatch, uid: int = 1000, gid: int = 1000) -> None:
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setenv("SUDO_GID", str(gid))
    monkeypatch.delenv("PKEXEC_UID", raising=False)


def test_under_sudo_the_file_is_read_with_the_callers_privileges(monkeypatch, tmp_path):
    _as_root_via_sudo(monkeypatch)
    bridges = tmp_path / "bridges.txt"
    ok = subprocess.CompletedProcess([], 0, stdout=b"obfs4 192.0.2.10:9001 cert=a iat-mode=0\n", stderr=b"")
    with (
        patch.object(_tor_setup.os, "geteuid", return_value=0),
        patch.object(_tor_setup.pwd, "getpwuid", return_value=MagicMock(pw_name="alice")),
        patch.object(_tor_setup.os, "getgrouplist", return_value=[1000, 27]),
        patch.object(_tor_setup, "resolve", side_effect=lambda b: f"/usr/bin/{b}"),
        patch.object(_tor_setup.subprocess, "run", return_value=ok) as run,
    ):
        lines, use_bridges = _tor_setup._parse_bridges(bridges, None, False)

    assert lines == ["obfs4 192.0.2.10:9001 cert=a iat-mode=0"] and use_bridges is True
    kwargs = run.call_args.kwargs
    assert (kwargs["user"], kwargs["group"], kwargs["extra_groups"]) == (1000, 1000, [1000, 27])
    assert run.call_args.args[0][-1] == str(bridges)


def test_a_file_the_caller_cannot_read_is_refused_without_its_content(monkeypatch, tmp_path, capsys):
    _as_root_via_sudo(monkeypatch)
    denied = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"cat: /etc/shadow: Permission denied\n")
    with (
        patch.object(_tor_setup.os, "geteuid", return_value=0),
        patch.object(_tor_setup.pwd, "getpwuid", return_value=MagicMock(pw_name="alice")),
        patch.object(_tor_setup.os, "getgrouplist", return_value=[1000]),
        patch.object(_tor_setup, "resolve", side_effect=lambda b: f"/usr/bin/{b}"),
        patch.object(_tor_setup.subprocess, "run", return_value=denied),
        pytest.raises(typer.Exit),
    ):
        _tor_setup._parse_bridges(Path("/etc/shadow"), None, False)
    captured = capsys.readouterr()
    shown = " ".join((captured.out + captured.err).split())
    assert "cannot be read as alice" in shown and "Permission denied" in shown


def test_a_rejected_line_is_reported_by_number_not_by_content(tmp_path, capsys):
    secret = "not-a-bridge-SECRET-VALUE"
    bridges = tmp_path / "bridges.txt"
    bridges.write_text(f"# comment\nobfs4 192.0.2.10:9001 cert=a iat-mode=0\n{secret}\n")
    with pytest.raises(typer.Exit):
        _tor_setup._parse_bridges(bridges, None, False)
    out = capsys.readouterr()
    shown = out.out + out.err
    assert "SECRET" not in shown
    assert "line 3" in shown.lower()


def test_run_as_root_directly_the_file_is_read_as_root(monkeypatch, tmp_path):
    """No sudo or pkexec caller: there is no less-privileged identity to use."""
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    bridges = tmp_path / "bridges.txt"
    bridges.write_text("192.0.2.10:9001\n")
    with (
        patch.object(_tor_setup.os, "geteuid", return_value=0),
        patch.object(_tor_setup.subprocess, "run") as run,
    ):
        lines, _ = _tor_setup._parse_bridges(bridges, None, False)
    assert lines == ["192.0.2.10:9001"]
    run.assert_not_called()


def test_pkexec_callers_are_honoured_too(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setenv("PKEXEC_UID", "1001")
    ok = subprocess.CompletedProcess([], 0, stdout=b"192.0.2.10:9001\n", stderr=b"")
    with (
        patch.object(_tor_setup.os, "geteuid", return_value=0),
        patch.object(_tor_setup.pwd, "getpwuid", return_value=MagicMock(pw_name="bob", pw_gid=1001)),
        patch.object(_tor_setup.os, "getgrouplist", return_value=[1001]),
        patch.object(_tor_setup, "resolve", side_effect=lambda b: f"/usr/bin/{b}"),
        patch.object(_tor_setup.subprocess, "run", return_value=ok) as run,
    ):
        _tor_setup._parse_bridges(tmp_path / "b.txt", None, False)
    assert (run.call_args.kwargs["user"], run.call_args.kwargs["group"]) == (1001, 1001)


def test_a_non_numeric_caller_id_is_refused_rather_than_read_as_root(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "alice")
    with patch.object(_tor_setup.os, "geteuid", return_value=0), pytest.raises(OSError, match="not a number"):
        _tor_setup._invoking_identity()


def test_sudo_from_root_needs_no_privilege_drop(monkeypatch):
    _as_root_via_sudo(monkeypatch, uid=0, gid=0)
    with patch.object(_tor_setup.os, "geteuid", return_value=0):
        assert _tor_setup._invoking_identity() is None


def test_a_caller_without_a_passwd_entry_is_read_as_its_bare_ids(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setenv("PKEXEC_UID", "4242")
    ok = subprocess.CompletedProcess([], 0, stdout=b"192.0.2.10:9001\n", stderr=b"")
    with (
        patch.object(_tor_setup.os, "geteuid", return_value=0),
        patch.object(_tor_setup.pwd, "getpwuid", side_effect=KeyError(4242)),
        patch.object(_tor_setup.os, "getgrouplist", side_effect=KeyError("4242")),
        patch.object(_tor_setup, "resolve", side_effect=lambda b: f"/usr/bin/{b}"),
        patch.object(_tor_setup.subprocess, "run", return_value=ok) as run,
    ):
        _tor_setup._parse_bridges(tmp_path / "b.txt", None, False)
    kwargs = run.call_args.kwargs
    assert (kwargs["user"], kwargs["group"], kwargs["extra_groups"]) == (4242, 4242, [4242])


def test_an_oversized_file_is_not_a_bridge_file(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    big = tmp_path / "big"
    big.write_bytes(b"#" * (_tor_setup._MAX_BRIDGE_FILE_BYTES + 1))
    with pytest.raises(OSError, match="larger than"):
        _tor_setup._read_as_invoking_user(big)


def test_a_binary_file_is_not_a_bridge_file(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(OSError, match="not UTF-8"):
        _tor_setup._read_as_invoking_user(binary)
