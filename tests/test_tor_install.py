"""Tests for ttp.tor_install - Tor installation and service management.

All tests mock subprocess.run, shutil.which, and system paths.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import tor_install
from ttp.tor_install import (
    detect_package_manager,
    install_tor,
    remove_selinux_module,
    setup_selinux_if_needed,
    generate_torrc,
    start_tor_service,
    stop_tor_service,
    _write_service_unit,
    TTP_SERVICE_NAME,
)
from ttp.tor_detect import is_selinux_module_installed
from ttp.exceptions import TorError


# Volatile Service Unit


@patch("ttp.tor_install.shutil.which", return_value="/usr/bin/tor")
def test_write_service_unit(mock_which, tmp_path: Path):
    """_write_service_unit writes a valid systemd unit to the expected path."""
    fake_path = tmp_path / "ttp-tor.service"

    with patch.object(tor_install, "TTP_SERVICE_PATH", fake_path):
        _write_service_unit("debian-tor")

    assert fake_path.exists()
    content = fake_path.read_text()
    assert "ExecStartPre=+/bin/mkdir -p" in content
    assert "ExecStartPre=+/bin/chown -R debian-tor:debian-tor" in content
    assert "/var/lib/tor/ttp" in content
    assert "/run/tor/ttp" in content
    assert "ExecStart=/usr/bin/tor -f" in content
    assert "--RunAsDaemon 0" in content
    assert "Type=simple" in content
    assert "LimitNOFILE=32768" in content


# Service Management


@patch("ttp.tor_install.subprocess.run")
@patch("ttp.tor_install._write_service_unit")
@patch("ttp.tor_install.generate_torrc")
def test_start_tor_service(mock_generate, mock_write_unit, mock_run):
    """start_tor_service generates torrc, writes unit, reloads, and starts."""
    mock_generate.return_value = Path("/run/tor/ttp/torrc")
    mock_run.return_value = MagicMock(returncode=0)

    start_tor_service("tor")

    mock_generate.assert_called_once_with("tor", transport_port=9041, dns_port=9054)
    mock_write_unit.assert_called_once_with("tor")
    assert mock_run.call_count == 2
    mock_run.assert_any_call(
        ["systemctl", "daemon-reload"],
        capture_output=True, text=True, check=True,
    )
    mock_run.assert_any_call(
        ["systemctl", "restart", TTP_SERVICE_NAME],
        capture_output=True, text=True, check=True,
    )


@patch("ttp.tor_install.subprocess.run")
@patch("ttp.tor_install._write_service_unit")
@patch("ttp.tor_install.generate_torrc")
def test_start_tor_service_failure(mock_generate, mock_write_unit, mock_run):
    """start_tor_service raises TorError if systemctl restart fails."""
    mock_generate.return_value = Path("/run/tor/ttp/torrc")
    # daemon-reload succeeds, restart fails
    mock_run.side_effect = [
        MagicMock(returncode=0),  # daemon-reload
        subprocess.CalledProcessError(1, "systemctl", stderr="Failed to start"),
    ]

    with pytest.raises(TorError, match="Failed to start"):
        start_tor_service("tor")


@patch("ttp.tor_install.subprocess.run")
def test_stop_tor_service(mock_run, tmp_path: Path):
    """stop_tor_service stops ttp-tor, removes unit, reloads daemon."""
    fake_unit = tmp_path / "ttp-tor.service"
    fake_unit.write_text("[Service]\n")
    mock_run.return_value = MagicMock(returncode=0)

    with patch.object(tor_install, "TTP_SERVICE_PATH", fake_unit):
        stop_tor_service()

    mock_run.assert_any_call(
        ["systemctl", "stop", TTP_SERVICE_NAME],
        capture_output=True, text=True, check=False,
    )
    assert not fake_unit.exists()  # Unit file was removed
    # daemon-reload was called after removal
    assert mock_run.call_count == 2


# Torrc Generation


@patch("ttp.tor_install.os.makedirs")
@patch("ttp.tor_install.shutil.chown")
@patch("ttp.tor_install.os.chmod")
def test_generate_torrc_creates_file(mock_chmod, mock_chown, mock_makedirs, tmp_path: Path):
    """generate_torrc writes a valid torrc and sets directory permissions."""
    runtime_dir = tmp_path / "run/tor"
    cache_dir = tmp_path / "lib/cache"
    
    with (
        patch.object(tor_install, "TOR_RUNTIME_DIR", runtime_dir),
        patch.object(tor_install, "TOR_CACHE_DIR", cache_dir),
    ):
        # We also need to mock Path.write_text and Path.mkdir to avoid actual FS changes during testing
        with patch("ttp.tor_install.Path.write_text"), patch("ttp.tor_install.Path.mkdir"):
            generate_torrc("debian-tor")

        # Verify directory creation
        mock_makedirs.assert_any_call(str(cache_dir), exist_ok=True)
        
        # Check chown calls
        mock_chown.assert_any_call(runtime_dir, user="debian-tor", group="debian-tor")
        mock_chown.assert_any_call(str(cache_dir), user="debian-tor")
        
        # Check chmod calls
        mock_chmod.assert_any_call(runtime_dir, 0o700)
        mock_chmod.assert_any_call(str(cache_dir), 0o700)


# Package Installation


def test_detect_package_manager_apt():
    """apt-get available -> returns 'apt-get'."""
    with patch("ttp.tor_install.shutil.which") as mock_which:
        mock_which.side_effect = lambda name: (
            "/usr/bin/apt-get" if name == "apt-get" else None
        )
        assert detect_package_manager() == "apt-get"


def test_detect_package_manager_pacman():
    """Only pacman available -> returns 'pacman'."""
    with patch("ttp.tor_install.shutil.which") as mock_which:
        mapping = {"pacman": "/usr/bin/pacman"}
        mock_which.side_effect = lambda name: mapping.get(name)
        assert detect_package_manager() == "pacman"


def test_detect_package_manager_none():
    """No package manager found -> returns None."""
    with patch("ttp.tor_install.shutil.which", return_value=None):
        assert detect_package_manager() is None


def test_install_tor_success():
    """install_tor with apt-get -> calls correct command."""
    with patch("ttp.tor_install.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        install_tor("apt-get")
        # For apt-get, we call update then install
        assert mock_run.call_count == 2
        mock_run.assert_any_call(["apt-get", "update"], check=True)
        mock_run.assert_any_call(["apt-get", "install", "-y", "tor"], check=True)


def test_install_tor_failure():
    """install_tor fails -> raises CalledProcessError."""
    with patch("ttp.tor_install.subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0),
            subprocess.CalledProcessError(
                1, ["apt-get", "install"], stderr="E: Unable to locate package tor"
            ),
        ]
        try:
            install_tor("apt-get")
            assert False, "Should have raised"
        except (TorError, subprocess.CalledProcessError):
            pass


def test_install_tor_unsupported_pm():
    """install_tor with unknown pm -> raises TorError."""
    try:
        install_tor("brew")
        assert False, "Should have raised TorError"
    except TorError as exc:
        assert "Unsupported" in str(exc)


# SELinux policy management


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
