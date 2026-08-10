# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.tor_install - Tor installation and service management.

All tests mock subprocess.run, shutil.which, and system paths.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from ttp import tor_config, tor_install, tor_service
from ttp.exceptions import TorError
from ttp.tor_detect import is_selinux_module_installed
from ttp.tor_install import (
    TTP_SERVICE_NAME,
    _write_service_unit,
    generate_torrc,
    remove_selinux_module,
    setup_selinux_if_needed,
    start_tor_service,
    stop_tor_service,
)

# Volatile Service Unit


@patch("ttp.tor_service.shutil.which", return_value="/usr/bin/tor")
def test_write_service_unit(mock_which, tmp_path: Path):
    """_write_service_unit writes a valid systemd unit to the expected path."""
    fake_path = tmp_path / "ttp-tor.service"

    with patch.object(tor_service, "TTP_SERVICE_PATH", fake_path):
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


@patch("ttp.tor_service.subprocess.run")
@patch("ttp.tor_service.label_ports_selinux")
@patch("ttp.tor_service._write_service_unit")
@patch("ttp.tor_service.generate_torrc")
def test_start_tor_service(mock_generate, mock_write_unit, mock_label, mock_run):
    """start_tor_service generates torrc, writes unit, reloads, and starts."""
    mock_generate.return_value = Path("/run/tor/ttp/torrc")
    mock_run.return_value = MagicMock(returncode=0)

    start_tor_service("tor")

    mock_generate.assert_called_once_with(
        "tor",
        transport_port=9041,
        dns_port=9054,
        block_doh=True,
        use_bridges=False,
        bridges=None,
        disable_ipv6=False,
    )
    mock_label.assert_called_once_with(9041, 9054)
    mock_write_unit.assert_called_once_with("tor")
    assert mock_run.call_count == 2
    mock_run.assert_any_call(
        ["systemctl", "daemon-reload"],
        capture_output=True,
        text=True,
        check=True,
    )
    mock_run.assert_any_call(
        ["systemctl", "restart", TTP_SERVICE_NAME],
        capture_output=True,
        text=True,
        check=True,
    )


@patch("ttp.tor_config.os.makedirs")
@patch("ttp.tor_config.shutil.chown")
@patch("ttp.tor_config.os.chmod")
def test_generate_torrc_doh_mitigation(mock_chmod, mock_chown, mock_makedirs, tmp_path: Path):
    """generate_torrc writes MapAddress use-application-dns.net 0.0.0.0 if block_doh is True."""
    runtime_dir = tmp_path / "run/tor"
    cache_dir = tmp_path / "lib/cache"
    torrc_path = runtime_dir / "torrc"

    with (
        patch.object(tor_config, "TOR_RUNTIME_DIR", runtime_dir),
        patch.object(tor_config, "TOR_CACHE_DIR", cache_dir),
    ):
        # Genera con block_doh=True (default)
        generate_torrc("debian-tor", block_doh=True)
        assert torrc_path.exists()
        content = torrc_path.read_text()
        assert "MapAddress use-application-dns.net 0.0.0.0" in content
        assert "MapAddress cloudflare-dns.com 0.0.0.0" in content
        assert "MapAddress dns.google 0.0.0.0" in content

        # Genera con block_doh=False
        generate_torrc("debian-tor", block_doh=False)
        content_no_doh = torrc_path.read_text()
        assert "MapAddress use-application-dns.net 0.0.0.0" not in content_no_doh


@patch("ttp.tor_config.os.makedirs")
@patch("ttp.tor_config.shutil.chown")
@patch("ttp.tor_config.os.chmod")
def test_generate_torrc_creates_file(mock_chmod, mock_chown, mock_makedirs, tmp_path: Path):
    """generate_torrc generates a valid torrc file with target ports."""
    runtime_dir = tmp_path / "run/tor"
    cache_dir = tmp_path / "lib/cache"
    torrc_path = runtime_dir / "torrc"

    with (
        patch.object(tor_config, "TOR_RUNTIME_DIR", runtime_dir),
        patch.object(tor_config, "TOR_CACHE_DIR", cache_dir),
    ):
        generate_torrc("debian-tor", transport_port=9041, dns_port=9054)

        assert torrc_path.exists()
        content = torrc_path.read_text()

        assert f"DataDirectory {cache_dir}" in content
        assert "TransPort 9041" in content
        assert "DNSPort 9054" in content
        assert "SocksPort 0" in content
        mock_makedirs.assert_called_with(str(cache_dir), exist_ok=True)
        mock_chmod.assert_any_call(str(cache_dir), 0o700)
        mock_chown.assert_any_call(str(cache_dir), user="debian-tor")


@patch("ttp.tor_service.subprocess.run")
def test_start_tor_service_failure(mock_run):
    """start_tor_service raises TorError if systemctl fails."""
    mock_run.side_effect = subprocess.CalledProcessError(1, "systemctl", stderr="Failed to restart")

    with (
        patch("ttp.tor_service._write_service_unit"),
        patch("ttp.tor_service.generate_torrc"),
        patch("ttp.tor_service.label_ports_selinux"),
        pytest.raises(TorError, match="Failed to start 'ttp-tor'"),
    ):
        start_tor_service("tor")


@patch("ttp.tor_service.subprocess.run")
def test_stop_tor_service(mock_run, tmp_path: Path):
    """stop_tor_service stops the unit and deletes the volatile file."""
    fake_path = tmp_path / "ttp-tor.service"
    fake_path.write_text("unit")

    with patch.object(tor_service, "TTP_SERVICE_PATH", fake_path):
        stop_tor_service()

        assert not fake_path.exists()
        assert mock_run.call_count == 2
        mock_run.assert_any_call(
            ["systemctl", "stop", TTP_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        mock_run.assert_any_call(
            ["systemctl", "daemon-reload"],
            capture_output=True,
            text=True,
            check=False,
        )


# Torrc Generation


# Package Installation


# SELinux policy management


def test_is_selinux_module_installed_true():
    """is_selinux_module_installed returns True if module listed in semodule -l."""
    with (
        patch("ttp.tor_detect.shutil.which", return_value="/usr/sbin/semodule"),
        patch("ttp.tor_detect.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="ttp_tor_policy  1.1\nother_mod 2.1")
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
@patch("ttp.selinux.Path.exists", return_value=True)
@patch("ttp.selinux.shutil.which", return_value="/usr/bin/cmd")
@patch("ttp.selinux.tempfile.TemporaryDirectory")
@patch("ttp.selinux.subprocess.run")
def test_setup_selinux_if_needed_installs(
    mock_run,
    mock_tempdir,
    mock_which,
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
@patch("ttp.tor_detect.is_selinux_enforcing", return_value=True)
@patch("ttp.tor_detect.is_fedora_family", return_value=True)
def test_setup_selinux_if_needed_skips_if_installed(mock_fedora, mock_enforcing, mock_installed):
    """setup_selinux_if_needed does nothing if module is already installed."""
    with patch("ttp.selinux.subprocess.run") as mock_run:
        setup_selinux_if_needed()
        mock_run.assert_not_called()


@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.tor_detect.shutil.which", return_value="/usr/sbin/semodule")
@patch("ttp.selinux.subprocess.run")
def test_remove_selinux_module(mock_run, mock_which, mock_installed):
    """remove_selinux_module runs semodule -r if installed."""
    mock_run.return_value = MagicMock(returncode=0)
    remove_selinux_module()
    assert any("semodule" in str(c) and "-r" in str(c) for c in mock_run.call_args_list)


@patch("ttp.tor_detect.is_selinux_module_installed", return_value=False)
def test_remove_selinux_module_skips(mock_installed):
    """remove_selinux_module does nothing if module is not installed."""
    with patch("ttp.selinux.subprocess.run") as mock_run:
        remove_selinux_module()
        mock_run.assert_not_called()


# Pluggable Transports & Bridges Tests


@patch("ttp.tor_config.os.makedirs")
@patch("ttp.tor_config.shutil.chown")
@patch("ttp.tor_config.os.chmod")
def test_generate_torrc_with_bridges(mock_chmod, mock_chown, mock_makedirs, tmp_path: Path):
    """generate_torrc writes correct bridge options and ClientTransportPlugins."""
    runtime_dir = tmp_path / "run/tor"
    cache_dir = tmp_path / "lib/cache"
    torrc_path = runtime_dir / "torrc"

    bridges = [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]

    with (
        patch.object(tor_config, "TOR_RUNTIME_DIR", runtime_dir),
        patch.object(tor_config, "TOR_CACHE_DIR", cache_dir),
        patch("ttp.tor_config.shutil.which") as mock_which,
    ):
        mock_which.side_effect = lambda binary: f"/usr/bin/{binary}"
        generate_torrc("debian-tor", use_bridges=True, bridges=bridges)

        assert torrc_path.exists()
        content = torrc_path.read_text()
        assert "UseBridges 1" in content
        assert "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" in content
        assert "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client" in content
        assert "Bridge obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0" in content
        assert "Bridge snowflake 192.0.2.2:4321 601234567890ABCDEF" in content


@patch("ttp.tor_install.shutil.which")
def test_ensure_pluggable_transports_already_installed(mock_which):
    """ensure_pluggable_transports does nothing if transport helper is already in PATH."""
    mock_which.return_value = "/usr/bin/obfs4proxy"
    with patch("subprocess.run") as mock_run:
        tor_install.ensure_pluggable_transports(["obfs4"])
        mock_run.assert_not_called()


@patch("ttp.tor_install.shutil.which")
def test_ensure_pluggable_transports_missing_raises(mock_which):
    """ensure_pluggable_transports exits with code 0 if transport binary is missing under No Auto-Install policy."""
    mock_which.return_value = None
    with pytest.raises(typer.Exit) as exc_info:
        tor_install.ensure_pluggable_transports(["obfs4"])
    assert exc_info.value.exit_code == 0


@patch("ttp.tor_install.shutil.which", return_value=None)
def test_ensure_pluggable_transports_unsupported_pt(mock_which):
    """ensure_pluggable_transports exits with code 0 for unsupported transports under No Auto-Install policy."""
    with pytest.raises(typer.Exit) as exc_info:
        tor_install.ensure_pluggable_transports(["shadow"])
    assert exc_info.value.exit_code == 0


# ---------------------------------------------------------------------------
# Pure string builders — Unit Tests (no filesystem/IO mock needed)
# ---------------------------------------------------------------------------


from ttp.tor_install import _build_service_unit_content, _build_torrc_content  # noqa: E402


def test_build_torrc_content_ipv4_only():
    content = _build_torrc_content(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        block_doh=False,
        use_bridges=False,
        bridges=None,
        ipv6_avail=False,
    )
    assert "User debian-tor" in content
    assert "TransPort 9041" in content
    assert "DNSPort 9054" in content
    assert "ClientUseIPv6 0" in content
    assert "[::1]" not in content
    assert "MapAddress" not in content
    assert "UseBridges" not in content


def test_build_torrc_content_ipv6_enabled():
    content = _build_torrc_content(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        block_doh=False,
        use_bridges=False,
        bridges=None,
        ipv6_avail=True,
    )
    assert "TransPort [::1]:9041" in content
    assert "DNSPort [::1]:9054" in content
    assert "ClientUseIPv6 1" in content


def test_build_torrc_content_block_doh():
    content = _build_torrc_content(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        block_doh=True,
        use_bridges=False,
        bridges=None,
        ipv6_avail=False,
    )
    assert "MapAddress use-application-dns.net 0.0.0.0" in content
    assert "MapAddress dns.google 0.0.0.0" in content


@patch("ttp.tor_install.shutil.which")
def test_build_torrc_content_with_bridges(mock_which):
    mock_which.side_effect = lambda binary: f"/usr/bin/{binary}" if "obfs4" in binary or "snowflake" in binary else None
    content = _build_torrc_content(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        block_doh=False,
        use_bridges=True,
        bridges=[
            "obfs4 192.0.2.1:1234 FINGERPRINT",
            "snowflake 192.0.2.2:4321 FP2",
        ],
        ipv6_avail=False,
    )
    assert "UseBridges 1" in content
    assert "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy" in content
    assert "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client" in content
    assert "Bridge obfs4 192.0.2.1:1234 FINGERPRINT" in content
    assert "Bridge snowflake 192.0.2.2:4321 FP2" in content


def test_build_torrc_content_root_user_excludes_user_directive():
    content = _build_torrc_content(
        tor_user="root",
        transport_port=9041,
        dns_port=9054,
        block_doh=False,
        use_bridges=False,
        bridges=None,
        ipv6_avail=False,
    )
    assert "User root" not in content


def test_build_service_unit_content():
    content = _build_service_unit_content(tor_user="debian-tor", tor_bin="/usr/sbin/tor")
    assert "Description=TTP Managed Tor Instance" in content
    assert "ExecStartPre=+/bin/mkdir -p" in content
    assert "ExecStart=/usr/sbin/tor -f" in content
    assert "LimitNOFILE=32768" in content
