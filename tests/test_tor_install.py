"""Tests for ttp.tor_install — Tor installation and configuration.

All tests mock subprocess.run and shutil.which.  No real packages are
installed or services touched.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from ttp.tor_install import (
    configure_torrc,
    detect_package_manager,
    install_tor,
    remove_selinux_module,
    setup_selinux_if_needed,
)
from ttp.tor_detect import is_selinux_module_installed
from ttp.exceptions import TorError


# ── detect_package_manager ─────────────────────────────────────────


def test_detect_package_manager_apt():
    """apt-get available → returns 'apt-get'."""
    with patch("ttp.tor_install.shutil.which") as mock_which:
        mock_which.side_effect = lambda name: (
            "/usr/bin/apt-get" if name == "apt-get" else None
        )
        assert detect_package_manager() == "apt-get"


def test_detect_package_manager_pacman():
    """Only pacman available → returns 'pacman'."""
    with patch("ttp.tor_install.shutil.which") as mock_which:
        mapping = {"pacman": "/usr/bin/pacman"}
        mock_which.side_effect = lambda name: mapping.get(name)
        assert detect_package_manager() == "pacman"


def test_detect_package_manager_none():
    """No package manager found → returns None."""
    with patch("ttp.tor_install.shutil.which", return_value=None):
        assert detect_package_manager() is None


# ── install_tor ────────────────────────────────────────────────────


def test_install_tor_success():
    """install_tor with apt-get → calls correct command."""
    with patch("ttp.tor_install.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        install_tor("apt-get")
        # For apt-get, we call update then install
        assert mock_run.call_count == 2
        mock_run.assert_any_call(["apt-get", "update"], check=True)
        mock_run.assert_any_call(["apt-get", "install", "-y", "tor"], check=True)


def test_install_tor_failure():
    """install_tor fails → raises TorError."""
    with patch("ttp.tor_install.subprocess.run") as mock_run:
        # First call (update) succeeds, second (install) fails
        mock_run.side_effect = [
            MagicMock(returncode=0),
            subprocess.CalledProcessError(
                1, ["apt-get", "install"], stderr="E: Unable to locate package tor"
            ),
        ]
        try:
            install_tor("apt-get")
            assert False, "Should have raised TorError"
        except (TorError, subprocess.CalledProcessError):
            pass


def test_install_tor_unsupported_pm():
    """install_tor with unknown pm → raises TorError."""
    try:
        install_tor("brew")
        assert False, "Should have raised TorError"
    except TorError as exc:
        assert "Unsupported" in str(exc)


# ── configure_torrc ───────────────────────────────────────────────


def test_configure_torrc_creates_file(tmp_path: Path):
    """configure_torrc creates a new file with TTP settings."""
    torrc = tmp_path / "torrc"
    modified = configure_torrc("debian-tor", torrc)
    assert modified is True

    content = torrc.read_text()
    assert "TransPort 9040" in content
    assert "DNSPort 9053" in content
    assert "ControlPort 9051" in content


def test_configure_torrc_backs_up_existing(tmp_path: Path):
    """configure_torrc backs up existing file to .bak."""
    torrc = tmp_path / "torrc"
    original = "SocksPort 9050\nLog notice file /var/log/tor/notices.log\n"
    torrc.write_text(original)

    modified = configure_torrc("debian-tor", torrc)
    assert modified is True

    backup = tmp_path / "torrc.bak"
    assert backup.exists()
    assert backup.read_text() == original

    content = torrc.read_text()
    assert "SocksPort 9050" in content
    assert "TransPort 9040" in content
    assert "ControlPort 9051" in content


def test_configure_torrc_idempotent(tmp_path: Path):
    """configure_torrc returns False if no changes needed."""
    torrc = tmp_path / "torrc"
    configure_torrc("debian-tor", torrc)

    # Second call should not modify
    modified = configure_torrc("debian-tor", torrc)
    assert modified is False


# ── SELinux ───────────────────────────────────────────────────────


def test_is_selinux_module_installed_true():
    """is_selinux_module_installed returns True if module listed in semodule -l."""
    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/sbin/semodule"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="ttp_tor_policy  1.0\nother_mod 2.1"
        )
        assert is_selinux_module_installed() is True


def test_is_selinux_module_installed_false():
    """is_selinux_module_installed returns False if module not listed."""
    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/sbin/semodule"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="other_mod 2.1")
        assert is_selinux_module_installed() is False


@patch("ttp.tor_detect.is_selinux_module_installed", return_value=False)
@patch("ttp.tor_detect.is_selinux_enforcing", return_value=True)
@patch("ttp.tor_detect.is_fedora_family", return_value=True)
@patch("ttp.tor_install.Path.exists", return_value=True)
@patch("ttp.tor_install._install_selinux_tools")
@patch("ttp.tor_install.shutil.which", return_value="/usr/bin/cmd")
@patch("ttp.tor_install.tempfile.TemporaryDirectory")
@patch("ttp.tor_install.subprocess.run")
def test_setup_selinux_if_needed_installs(
    mock_run,
    mock_tempdir,
    mock_which,
    mock_install_tools,
    mock_exists,
    mock_fedora,
    mock_enforcing,
    mock_installed,
):
    """setup_selinux_if_needed compiles and installs module on Fedora if enforcing and not installed."""
    mock_run.return_value = MagicMock(returncode=0)
    mock_tempdir.return_value.__enter__.return_value = "/tmp/fake"
    setup_selinux_if_needed()

    # Verify all 3 commands were executed
    assert any("checkmodule" in str(c) for c in mock_run.call_args_list)
    assert any("semodule_package" in str(c) for c in mock_run.call_args_list)
    assert any("semodule" in str(c) and "-i" in str(c) for c in mock_run.call_args_list)


@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.tor_install.Path.exists", return_value=True)
@patch("ttp.tor_install.subprocess.run")
def test_remove_selinux_module_calls_remove(mock_run, mock_exists, mock_installed):
    """remove_selinux_module calls semodule -r if installed."""
    mock_run.return_value = MagicMock(returncode=0)
    remove_selinux_module()
    assert any("semodule" in str(c) and "-r" in str(c) for c in mock_run.call_args_list)
