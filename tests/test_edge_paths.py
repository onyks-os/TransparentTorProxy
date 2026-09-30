# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Small branches the coverage report showed were never run.

Less consequential than tests/test_failure_paths.py, but each is behaviour an
operator can hit: a missing helper binary, an unreadable file, an unusual
argument. They are here so that the coverage ratchet measures the code, not
the parts of it that happened to be convenient to test.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from ttp import system_info, tor_detect
from ttp.cli import app
from ttp.commands import _logging, _tor_setup, _validation

runner = CliRunner()


# CLI and commands ------------------------------------------------------------


def test_quiet_silences_the_console():
    from ttp.commands._common import console

    with patch("ttp.cli._setup_logging"), patch("ttp.commands.session.state.read_lock", return_value=None):
        try:
            runner.invoke(app, ["--quiet", "logs"])
            assert console.quiet is True
        finally:
            console.quiet = False


def test_bypass_refuses_to_run_without_setpriv(monkeypatch):
    """Without setpriv the command would keep root's supplementary groups."""
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    with (
        patch("os.geteuid", return_value=0),
        patch("ttp.cli._setup_logging"),
        patch("ttp.commands.admin.state.read_lock", return_value={"pid": 1}),
        patch("ttp.commands.admin.resolve_optional", side_effect=lambda b: None if b == "setpriv" else f"/usr/bin/{b}"),
    ):
        result = runner.invoke(app, ["bypass", "true"])
    assert result.exit_code == 1
    assert "setpriv" in result.output


def test_only_root_passes_when_the_watchdog_account_does_not_exist():
    with (
        patch("os.geteuid", return_value=1234),
        patch("pwd.getpwnam", side_effect=KeyError("ttp-watchdog")),
        pytest.raises(typer.Exit),
    ):
        _validation.require_root_or_watchdog_user()


def test_blank_lines_in_dig_output_are_skipped():
    assert _validation.parse_txt_dig_ipv4('"not an address"\n\n"203.0.113.7"') == "203.0.113.7"


def test_a_numeric_bypass_group_is_accepted_by_gid():
    with patch("grp.getgrgid") as getgrgid:
        _users, groups, _uids, gids = _tor_setup._parse_bypass_users_groups(None, ["27"])
    getgrgid.assert_called_once_with(27)
    assert groups == ["27"] and gids == [27]


def test_an_unreadable_bridge_file_stops_start(tmp_path):
    bridges = tmp_path / "bridges.txt"
    bridges.write_text("obfs4 192.0.2.1:443 AAAA cert=x iat-mode=0\n")
    with patch.object(Path, "read_text", side_effect=PermissionError("denied")), pytest.raises(typer.Exit):
        _tor_setup._parse_bridges(bridges, None, False)


# Logging ---------------------------------------------------------------------


def test_a_log_file_that_cannot_be_chmodded_is_not_used(tmp_path, monkeypatch):
    monkeypatch.setattr(_logging, "_LOG_PATH", str(tmp_path / "ttp.log"))
    with patch.object(_logging.os, "fchmod", side_effect=OSError("EPERM")):
        assert _logging._open_log_file_safely() is False


def test_a_failed_close_of_the_log_descriptor_is_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(_logging, "_LOG_PATH", str(tmp_path / "ttp.log"))
    real_close = _logging.os.close

    def close(fd):
        real_close(fd)
        raise OSError("EBADF")

    with patch.object(_logging.os, "close", side_effect=close):
        assert _logging._open_log_file_safely() is True


def test_a_log_handler_that_cannot_open_leaves_logging_on_the_console(monkeypatch):
    monkeypatch.setattr(_logging, "_open_log_file_safely", lambda: True)
    with patch("logging.handlers.RotatingFileHandler", side_effect=OSError("ENOSPC")):
        _logging.setup_logging()  # must not raise


# Tor detection ---------------------------------------------------------------


def test_no_tor_binary_means_no_version():
    with patch.object(tor_detect, "resolve_optional", return_value=None):
        assert tor_detect._get_version() == ""


def test_a_tor_that_hangs_on_version_means_no_version():
    with (
        patch.object(tor_detect, "resolve_optional", return_value="/usr/bin/tor"),
        patch.object(tor_detect.subprocess, "run", side_effect=subprocess.TimeoutExpired("tor", 5)),
    ):
        assert tor_detect._get_version() == ""


def test_the_torrc_check_uses_the_session_ports_from_the_lock(tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text("TransPort 9141\nDNSPort 9154\nControlSocket /run/tor/ttp/control.sock\n")
    with (
        patch.object(tor_detect, "TTP_TORRC", torrc, create=True),
        patch("ttp.state.read_lock", return_value={"transport_port": 9141, "dns_port": 9154}),
    ):
        assert tor_detect._check_config(torrc_path=torrc) is True


# Diagnostics -----------------------------------------------------------------


def test_diagnostics_report_every_section_even_when_nothing_answers(monkeypatch):
    """`ttp diagnose` is run when things are broken; every probe failing must
    still produce a report, not a traceback."""
    empty = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    ctrl = MagicMock()
    ctrl.__enter__.return_value = ctrl
    ctrl.get_info.side_effect = RuntimeError("control socket closed")
    with (
        patch("builtins.open", side_effect=OSError("no os-release")),
        patch.object(system_info.subprocess, "run", return_value=empty),
        patch.object(system_info, "resolve", side_effect=lambda b: f"/usr/bin/{b}"),
        patch("ttp.tor_control.get_controller", return_value=ctrl),
        patch("ttp.state.read_lock", return_value={"pid": 1}),
    ):
        report = system_info.collect_diagnostics()

    assert "OS: Unknown" in report["os"]
    assert report["tor_service"] == "(ttp-tor service not found)"
    assert report["torrc"] == "(Empty or not readable)"
    assert report["nftables"] == "(Empty ruleset)"
    assert "Standard (No overlay detected)" in report["dns"]
    assert "error getting info" in report["control_interface"]
    assert "Lock contents" in report["ttp_state"]


# torrc ----------------------------------------------------------------------


def test_a_torrc_that_cannot_be_chmodded_is_not_written_and_its_fd_not_leaked(tmp_path):
    from ttp import tor_config

    closed = []
    real_close = tor_config.os.close
    with (
        patch.object(tor_config.os, "fchmod", side_effect=OSError("EPERM")),
        patch.object(tor_config.os, "close", side_effect=lambda fd: (closed.append(fd), real_close(fd))),
        pytest.raises(OSError, match="EPERM"),
    ):
        tor_config._write_private(tmp_path / "torrc", "SocksPort 0\n")
    assert len(closed) == 1


def test_a_missing_transport_binary_is_named_by_its_standard_path():
    """Preflight refuses bridges without their transport; if the torrc is built
    anyway, it names the standard path rather than anything from $PATH."""
    from ttp import tor_config

    with patch.object(tor_config, "resolve_optional", return_value=None):
        content = tor_config._build_torrc_content(
            tor_user="toranon",
            transport_port=9041,
            dns_port=9054,
            block_doh=False,
            use_bridges=True,
            bridges=["obfs4 192.0.2.1:443 AAAA cert=x iat-mode=0"],
            ipv6_avail=False,
        )
    assert "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" in content


def test_generate_torrc_survives_an_account_it_cannot_chown_to(tmp_path, monkeypatch):
    from ttp import tor_config

    runtime = tmp_path / "run" / "tor" / "ttp"
    cache = tmp_path / "lib" / "tor" / "ttp"
    cache.parent.mkdir(parents=True)
    monkeypatch.setattr(tor_config, "TOR_RUNTIME_DIR", runtime)
    monkeypatch.setattr(tor_config, "TOR_CACHE_DIR", cache)
    with (
        patch.object(tor_config.shutil, "chown", side_effect=KeyError("no such user")),
        patch("ttp.tor_detect.is_ipv6_supported", return_value=False),
    ):
        path = tor_config.generate_torrc("no-such-user")
    assert path.read_text().startswith("#") or "TransPort" in path.read_text()
    assert runtime.stat().st_mode & 0o777 == 0o700
    assert cache.stat().st_mode & 0o777 == 0o700
