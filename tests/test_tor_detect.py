# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.tor_detect - Tor detection module.

All tests use mocks to avoid hitting the real system.
Corresponds to TDD Section 8.1.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

from ttp.tor_detect import (
    detect_tor,
    _check_config,
    _detect_tor_user,
    is_firewalld_active,
)


# Helper: canonical subprocess side_effect


def _make_subprocess_side_effect(running: bool = True):
    """Return a side_effect function for mocked subprocess.run calls."""

    def side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd == ["pgrep", "-x", "tor"]:
            m.stdout = "1234\n" if running else ""
            m.returncode = 0 if running else 1
        elif cmd == ["tor", "--version"]:
            m.stdout = "Tor version 0.4.8.10.\n"
            m.returncode = 0
        else:
            m.stdout = ""
            m.returncode = 1
        return m

    return side_effect


# Correct torrc detection


def test_full_detection_all_true(tmp_path: Path):
    """torrc with TransPort and DNSPort -> dict with all True."""
    torrc = tmp_path / "torrc"
    torrc.write_text(
        "TransPort 9041\nDNSPort 9054\nControlSocket /run/tor/ttp/control.sock\n"
    )

    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/tor"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
        patch("ttp.tor_detect.TORRC_PATH", torrc),
        patch("ttp.tor_detect._detect_tor_user", return_value="debian-tor"),
    ):
        mock_run.side_effect = _make_subprocess_side_effect(running=True)
        result = detect_tor()

    assert result["is_installed"] is True
    assert result["is_running"] is True
    assert result["is_configured"] is True
    assert result["version"] == "0.4.8.10"
    assert result["tor_user"] == "debian-tor"


# Empty torrc detection


def test_empty_torrc_not_configured(tmp_path: Path):
    """Empty torrc -> is_configured = False."""
    torrc = tmp_path / "torrc"
    torrc.write_text("")

    assert _check_config(torrc) is False


def test_correct_torrc_is_configured(tmp_path: Path):
    """torrc with correct default ports -> is_configured = True."""
    torrc = tmp_path / "torrc"
    torrc.write_text(
        "TransPort 9041\nDNSPort 9054\nControlSocket /run/tor/ttp/control.sock\n"
    )

    assert _check_config(torrc) is True


def test_custom_ports_configured(tmp_path: Path):
    """torrc with custom ports -> is_configured = True when ports are passed or default fallback matches."""
    torrc = tmp_path / "torrc"
    torrc.write_text(
        "TransPort 9060\nDNSPort 9070\nControlSocket /run/tor/ttp/control.sock\n"
    )

    # 1. False if we check with default ports
    assert _check_config(torrc, transport_port=9041, dns_port=9054) is False

    # 2. True if we check with correct custom ports
    assert _check_config(torrc, transport_port=9060, dns_port=9070) is True


# Binary not found detection


def test_tor_not_installed():
    """which tor returns None -> is_installed = False."""
    with patch("ttp.tor_detect.shutil.which", return_value=None):
        result = detect_tor()

    assert result["is_installed"] is False
    assert result["is_running"] is False
    assert result["is_configured"] is False
    assert result["version"] == ""


# Process not running detection


def test_tor_not_running(tmp_path: Path):
    """pgrep -x tor fails -> is_running = False."""
    torrc = tmp_path / "torrc"
    torrc.write_text("TransPort 9041\nDNSPort 9054\n")

    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/tor"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
        patch("ttp.tor_detect.TORRC_PATH", torrc),
    ):
        mock_run.side_effect = _make_subprocess_side_effect(running=False)
        result = detect_tor()

    assert result["is_installed"] is True
    assert result["is_running"] is False


# Tor user detection


def test_detect_tor_user_from_ps_toranon():
    """Running process owned by 'toranon' -> returns 'toranon'.

    This is the CRITICAL test - many distros (Fedora, RHEL, openSUSE)
    use non-standard usernames.  The old code only checked for
    'debian-tor' and 'tor', causing nftables to block Tor's own
    traffic on those systems.
    """
    ps_output = "USER     COMMAND\nroot     systemd\ntoranon  tor\nroot     bash\n"
    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        assert _detect_tor_user() == "toranon"


@patch("ttp.tor_detect.subprocess.run")
def test_detect_tor_user_ps_fallback(mock_run):
    """Fallback to /etc/passwd if ps output is truncated or suspicious."""
    mock_run.side_effect = [
        # 1. ps returns truncated user
        MagicMock(returncode=0, stdout="debian-+ tor\n"),
    ]
    with patch("ttp.tor_detect.Path.read_text") as mock_read:
        mock_read.return_value = "debian-tor:x:110:110::/var/lib/tor:/bin/false\n"
        assert _detect_tor_user() == "debian-tor"


@patch("ttp.tor_detect.subprocess.run")
def test_detect_tor_user_not_running(mock_run):
    """Fallback to /etc/passwd if Tor is not running."""
    mock_run.return_value = MagicMock(returncode=0, stdout="")  # No tor process
    with patch("ttp.tor_detect.Path.read_text") as mock_read:
        mock_read.return_value = "toranon:x:110:110::/var/lib/tor:/bin/false\n"
        assert _detect_tor_user() == "toranon"


@patch("ttp.tor_detect.subprocess.run")
def test_detect_tor_user_custom_passwd(mock_run):
    """Handle custom users in /etc/passwd correctly."""
    mock_run.return_value = MagicMock(returncode=1)  # ps fails
    with patch("ttp.tor_detect.Path.read_text") as mock_read:
        mock_read.return_value = "my-custom-tor:x:110:110::/var/lib/tor:/bin/false\n"
        # Since 'my-custom-tor' is not in _KNOWN_USERS, it fallbacks to 'tor'
        # Unless we update _KNOWN_USERS or improve detection.
        assert _detect_tor_user() == "tor"


def test_detect_tor_user_from_ps_debian_tor():
    """Running process owned by 'debian-tor' -> returns 'debian-tor'."""
    ps_output = "USER         COMMAND\ndebian-tor   tor\n"
    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        assert _detect_tor_user() == "debian-tor"


def test_detect_tor_user_fallback_to_passwd():
    """No running tor process, 'toranon' in /etc/passwd -> returns 'toranon'."""
    passwd_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "toranon:x:964:964:Tor anonymizing user:/var/lib/tor:/sbin/nologin\n"
    )
    ps_output = "USER COMMAND\nroot systemd\n"

    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        with patch.object(Path, "read_text", return_value=passwd_content):
            assert _detect_tor_user() == "toranon"


def test_detect_tor_user_hard_fallback():
    """No process, no passwd match -> falls back to 'tor'."""
    passwd_content = (
        "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n"
    )
    ps_output = "USER COMMAND\nroot systemd\n"

    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        with patch.object(Path, "read_text", return_value=passwd_content):
            assert _detect_tor_user() == "tor"


def test_detect_tor_user_numeric_uid_rejected():
    """ps returns numeric UID (e.g. 524330) -> falls back to /etc/passwd."""
    ps_output = "USER     COMMAND\n524330   tor\n"
    passwd_content = "debian-tor:x:524330:524330::/var/lib/tor:/bin/false\n"

    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        with patch.object(Path, "read_text", return_value=passwd_content):
            assert _detect_tor_user() == "debian-tor"


# Firewalld detection


def test_is_firewalld_active_true():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        assert is_firewalld_active() is True
        mock_run.assert_called_with(
            ["pgrep", "-x", "firewalld"],
            capture_output=True,
            text=True,
            timeout=5,
        )


def test_is_firewalld_active_false():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        assert is_firewalld_active() is False


def test_is_firewalld_active_exception():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert is_firewalld_active() is False


def test_is_ipv6_supported_true():
    """is_ipv6_supported returns True when IPv6 socket binding succeeds."""
    from ttp.tor_detect import is_ipv6_supported

    mock_socket_instance = MagicMock()
    mock_socket_instance.__enter__.return_value = mock_socket_instance
    with patch("socket.socket", return_value=mock_socket_instance):
        assert is_ipv6_supported() is True
        mock_socket_instance.bind.assert_called_once_with(("::1", 0))


def test_is_ipv6_supported_false():
    """is_ipv6_supported returns False when IPv6 socket binding raises OSError."""
    from ttp.tor_detect import is_ipv6_supported

    mock_socket_instance = MagicMock()
    mock_socket_instance.__enter__.return_value = mock_socket_instance
    mock_socket_instance.bind.side_effect = OSError("IPv6 not supported")
    with patch("socket.socket", return_value=mock_socket_instance):
        assert is_ipv6_supported() is False


@patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/tor")
@patch("ttp.tor_detect.subprocess.run")
@patch("ttp.tor_detect._detect_tor_user", return_value="tor")
@patch("ttp.tor_detect.is_ipv6_supported")
def test_detect_tor_ipv6_propagation(mock_ipv6, mock_user, mock_run, mock_which):
    """detect_tor correctly propagates the return value of is_ipv6_supported."""
    mock_run.side_effect = _make_subprocess_side_effect(running=True)

    # 1. When IPv6 is supported
    mock_ipv6.return_value = True
    res_true = detect_tor()
    assert res_true["ipv6_supported"] is True

    # 2. When IPv6 is not supported
    mock_ipv6.return_value = False
    res_false = detect_tor()
    assert res_false["ipv6_supported"] is False
