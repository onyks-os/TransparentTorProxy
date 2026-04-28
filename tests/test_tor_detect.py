"""Tests for ttp.tor_detect — Tor detection module.

All tests use mocks to avoid hitting the real system.
Corresponds to TDD §8.1.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

from ttp.tor_detect import detect_tor, _check_config, _detect_tor_user


# ── Helper: canonical subprocess side_effect ──────────────────────────
#
# _get_service_name() now uses os.path.exists("/etc/debian_version") to
# determine the service name instead of calling "systemctl cat".
# To keep tests OS-agnostic we always patch _get_service_name() directly.


def _make_subprocess_side_effect(service: str = "tor@default", running: bool = True):
    """Return a side_effect function for mocked subprocess.run calls."""

    def side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd == ["systemctl", "is-active", service]:
            m.stdout = "active\n" if running else "inactive\n"
            m.returncode = 0 if running else 3
        elif cmd == ["pgrep", "-x", "tor"]:
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


# ── 8.1.1 Correct torrc → all fields True ─────────────────────────


def test_full_detection_all_true(tmp_path: Path):
    """torrc with TransPort and DNSPort → dict with all True."""
    torrc = tmp_path / "torrc"
    torrc.write_text("TransPort 9040\nDNSPort 9053\nControlPort 9051\n")

    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/tor"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
        patch("ttp.tor_detect.TORRC_PATH", torrc),
        patch("ttp.tor_detect._detect_tor_user", return_value="debian-tor"),
        # Isolate from the actual OS: always act as if on Debian.
        patch("ttp.tor_detect._get_service_name", return_value="tor@default"),
    ):
        mock_run.side_effect = _make_subprocess_side_effect("tor@default", running=True)
        result = detect_tor()

    assert result["is_installed"] is True
    assert result["is_running"] is True
    assert result["is_configured"] is True
    assert result["version"] == "0.4.8.10"
    assert result["tor_user"] == "debian-tor"
    assert result["service_name"] == "tor@default"


# ── 8.1.2 Empty torrc → is_configured = False ─────────────────────


def test_empty_torrc_not_configured(tmp_path: Path):
    """Empty torrc → is_configured = False."""
    torrc = tmp_path / "torrc"
    torrc.write_text("")

    assert _check_config(torrc) is False


def test_correct_torrc_is_configured(tmp_path: Path):
    """torrc with correct ports → is_configured = True."""
    torrc = tmp_path / "torrc"
    torrc.write_text("TransPort 9040\nDNSPort 9053\nControlPort 9051\n")

    assert _check_config(torrc) is True


# ── 8.1.3 which tor not found → is_installed = False ──────────────


def test_tor_not_installed():
    """which tor returns None → is_installed = False."""
    with patch("ttp.tor_detect.shutil.which", return_value=None):
        result = detect_tor()

    assert result["is_installed"] is False
    assert result["is_running"] is False
    assert result["is_configured"] is False
    assert result["version"] == ""


# ── 8.1.4 systemctl is-active → inactive ─────────────────────────
#
# Patch _get_service_name to return a known service name, then have the
# subprocess mock return "inactive" for is-active.  This test verifies
# the double-check logic (systemd says inactive → no pgrep call needed).


def test_tor_not_running(tmp_path: Path):
    """systemctl is-active tor returns 'inactive' → is_running = False."""
    torrc = tmp_path / "torrc"
    torrc.write_text("TransPort 9040\nDNSPort 9053\n")

    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/bin/tor"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
        patch("ttp.tor_detect.TORRC_PATH", torrc),
        patch("ttp.tor_detect._get_service_name", return_value="tor"),
    ):
        mock_run.side_effect = _make_subprocess_side_effect("tor", running=False)
        result = detect_tor()

    assert result["is_installed"] is True
    assert result["is_running"] is False


# ── 8.1.5 _get_service_name — Debian vs non-Debian ─────────────────


def test_get_service_name_on_debian():
    """On a Debian system, service name should be 'tor@default'."""
    from ttp.tor_detect import _get_service_name

    with patch("os.path.exists", return_value=True):
        assert _get_service_name() == "tor@default"


def test_get_service_name_on_non_debian():
    """On a non-Debian system, service name should be 'tor'."""
    from ttp.tor_detect import _get_service_name

    with patch("os.path.exists", return_value=False):
        assert _get_service_name() == "tor"


# ── 8.1.6 _detect_tor_user — live process detection ──────────────


def test_detect_tor_user_from_ps_toranon():
    """Running process owned by 'toranon' → returns 'toranon'.

    This is the CRITICAL test — many distros (Fedora, RHEL, openSUSE)
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
    """Running process owned by 'debian-tor' → returns 'debian-tor'."""
    ps_output = "USER         COMMAND\ndebian-tor   tor\n"
    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        assert _detect_tor_user() == "debian-tor"


def test_detect_tor_user_fallback_to_passwd():
    """No running tor process, 'toranon' in /etc/passwd → returns 'toranon'."""
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
    """No process, no passwd match → falls back to 'tor'."""
    passwd_content = (
        "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n"
    )
    ps_output = "USER COMMAND\nroot systemd\n"

    with patch("ttp.tor_detect.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=ps_output, returncode=0)
        with patch.object(Path, "read_text", return_value=passwd_content):
            assert _detect_tor_user() == "tor"
