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
from ttp.paths import resolve
from ttp.tor_detect import is_selinux_module_installed
from ttp.tor_install import (
    TTP_SERVICE_NAME,
    _get_distro_install_command,
    _write_service_unit,
    ensure_pluggable_transports,
    ensure_tor_ready,
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
        [resolve("systemctl"), "daemon-reload"],
        capture_output=True,
        text=True,
        check=True,
    )
    mock_run.assert_any_call(
        [resolve("systemctl"), "restart", TTP_SERVICE_NAME],
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
            [resolve("systemctl"), "stop", TTP_SERVICE_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        mock_run.assert_any_call(
            [resolve("systemctl"), "daemon-reload"],
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

    assert any(resolve("checkmodule") in str(c) for c in mock_run.call_args_list)
    assert any(resolve("semodule_package") in str(c) for c in mock_run.call_args_list)
    assert any(resolve("semodule") in str(c) and "-i" in str(c) for c in mock_run.call_args_list)


@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.tor_detect.is_selinux_enforcing", return_value=True)
@patch("ttp.tor_detect.is_fedora_family", return_value=True)
def test_setup_selinux_if_needed_skips_if_installed(mock_fedora, mock_enforcing, mock_installed):
    """setup_selinux_if_needed does nothing if module is already installed."""
    with patch("ttp.selinux.subprocess.run") as mock_run:
        setup_selinux_if_needed()
        mock_run.assert_not_called()


@patch("ttp.tor_detect.is_selinux_module_installed", return_value=True)
@patch("ttp.selinux.shutil.which", return_value="/usr/sbin/semodule")
@patch("ttp.selinux.subprocess.run")
def test_remove_selinux_module(mock_run, mock_which, mock_installed):
    """remove_selinux_module runs semodule -r if installed.

    The which() mock must target ttp.selinux, not ttp.tor_detect: patching the
    wrong module left the real filesystem probe in place, so this test passed on
    a Fedora workstation and failed on every CI runner without SELinux tooling.
    """
    mock_run.return_value = MagicMock(returncode=0)
    remove_selinux_module()
    assert any(resolve("semodule") in str(c) and "-r" in str(c) for c in mock_run.call_args_list)


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


# ---------------------------------------------------------------------------
# _get_distro_install_command — the no-auto-install policy in practice
#
# TTP never installs packages itself, so this string IS the remediation. A wrong
# package manager here leaves the user with a command that does not work on
# their machine, at the exact moment they cannot proxy their traffic.
# ---------------------------------------------------------------------------


def _only(*present: str):
    """A shutil.which that finds only the named binaries."""
    return lambda name: f"/usr/bin/{name}" if name in present else None


def test_install_command_prefers_apt_get() -> None:
    with patch("shutil.which", side_effect=_only("apt-get")):
        assert _get_distro_install_command("tor", "tor") == "sudo apt install tor"


def test_install_command_accepts_apt_without_apt_get() -> None:
    with patch("shutil.which", side_effect=_only("apt")):
        assert _get_distro_install_command("tor", "tor") == "sudo apt install tor"


def test_install_command_uses_dnf_on_fedora() -> None:
    with patch("shutil.which", side_effect=_only("dnf")):
        assert _get_distro_install_command("obfs4proxy", "obfs4") == "sudo dnf install obfs4"


def test_install_command_uses_pacman_on_arch() -> None:
    with patch("shutil.which", side_effect=_only("pacman")):
        got = _get_distro_install_command("obfs4proxy", "obfs4", pkg_arch="obfs4proxy-git")
        assert got == "sudo pacman -S obfs4proxy-git"


def test_arch_falls_back_to_the_debian_package_name() -> None:
    with patch("shutil.which", side_effect=_only("pacman")):
        assert _get_distro_install_command("tor", "tor") == "sudo pacman -S tor"


def test_install_command_uses_zypper_on_suse() -> None:
    with patch("shutil.which", side_effect=_only("zypper")):
        got = _get_distro_install_command("tor", "tor", pkg_suse="tor-suse")
        assert got == "sudo zypper install tor-suse"


def test_suse_falls_back_to_the_debian_package_name() -> None:
    with patch("shutil.which", side_effect=_only("zypper")):
        assert _get_distro_install_command("tor", "tor") == "sudo zypper install tor"


def test_unknown_distro_offers_both_common_commands() -> None:
    """On a distro we do not recognise, guess nothing and show the two likely forms."""
    with patch("shutil.which", side_effect=_only()):
        got = _get_distro_install_command("tor", "tor")
    assert "apt install tor" in got
    assert "dnf install tor" in got


def test_apt_wins_when_several_managers_are_present() -> None:
    """Containers often carry more than one; the first match must be deterministic."""
    with patch("shutil.which", side_effect=_only("apt-get", "dnf", "pacman")):
        assert _get_distro_install_command("tor", "tor").startswith("sudo apt")


# ---------------------------------------------------------------------------
# ensure_pluggable_transports
# ---------------------------------------------------------------------------


def test_present_transport_binaries_are_accepted() -> None:
    with patch("shutil.which", return_value="/usr/bin/obfs4proxy"):
        ensure_pluggable_transports(["obfs4"])  # must not raise


def test_transport_names_are_case_insensitive() -> None:
    with patch("shutil.which", return_value="/usr/bin/obfs4proxy"):
        ensure_pluggable_transports(["OBFS4"])


def test_missing_transport_binary_exits_zero_without_installing() -> None:
    """
    Exit code 0, not 1: a missing optional dependency is guidance, not a crash.
    And nothing may be installed - that is the documented policy.
    """
    with (
        patch("shutil.which", return_value=None),
        patch("subprocess.run") as run,
        pytest.raises(typer.Exit) as exc,
    ):
        ensure_pluggable_transports(["obfs4"])
    assert exc.value.exit_code == 0
    run.assert_not_called()


def test_unknown_transport_exits_without_touching_the_filesystem() -> None:
    with (
        patch("shutil.which") as which,
        pytest.raises(typer.Exit) as exc,
    ):
        ensure_pluggable_transports(["wireguard"])
    assert exc.value.exit_code == 0
    which.assert_not_called()


def test_the_first_missing_transport_stops_the_check() -> None:
    with (
        patch("shutil.which", return_value=None),
        pytest.raises(typer.Exit),
    ):
        ensure_pluggable_transports(["obfs4", "snowflake"])


def test_the_guidance_names_the_missing_binary_and_the_transport() -> None:
    """A message that does not say what is missing sends the user to a search engine."""
    printed: list[str] = []

    class _Console:
        def print(self, renderable):  # type: ignore[no-untyped-def]
            printed.append(str(getattr(renderable, "renderable", renderable)))

    with (
        patch("shutil.which", side_effect=_only("apt-get")),
        patch("ttp.commands._common.console", _Console()),
        pytest.raises(typer.Exit),
    ):
        ensure_pluggable_transports(["obfs4"])

    blob = " ".join(printed)
    assert "obfs4proxy" in blob
    assert "obfs4" in blob
    assert "apt install" in blob


# ---------------------------------------------------------------------------
# ensure_tor_ready
# ---------------------------------------------------------------------------


def test_ensure_tor_ready_exits_zero_when_tor_is_absent() -> None:
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": False}),
        patch("ttp.tor_install.start_tor_service") as start,
        patch("shutil.which", side_effect=_only("apt-get")),
        pytest.raises(typer.Exit) as exc,
    ):
        ensure_tor_ready()
    assert exc.value.exit_code == 0
    start.assert_not_called()


def test_ensure_tor_ready_starts_the_service_and_returns_the_detection() -> None:
    info = {"is_installed": True, "tor_user": "toranon", "version": "0.4.8.12"}
    with (
        patch("ttp.tor_install.detect_tor", return_value=info),
        patch("ttp.tor_install.start_tor_service") as start,
    ):
        assert ensure_tor_ready(transport_port=9051, dns_port=9053) is info

    assert start.call_args[0][0] == "toranon"
    assert start.call_args.kwargs["transport_port"] == 9051
    assert start.call_args.kwargs["dns_port"] == 9053


def test_ensure_tor_ready_defaults_the_tor_user() -> None:
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": True}),
        patch("ttp.tor_install.start_tor_service") as start,
    ):
        ensure_tor_ready()
    assert start.call_args[0][0] == "debian-tor"


def test_bridges_trigger_a_transport_check() -> None:
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": True}),
        patch("ttp.tor_install.start_tor_service"),
        patch("ttp.tor_install.ensure_pluggable_transports") as ensure_pt,
    ):
        ensure_tor_ready(use_bridges=True, bridges=["obfs4 192.0.2.1:9001 CERT=x"])
    ensure_pt.assert_called_once_with(["obfs4"])


def test_duplicate_transports_are_only_checked_once() -> None:
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": True}),
        patch("ttp.tor_install.start_tor_service"),
        patch("ttp.tor_install.ensure_pluggable_transports") as ensure_pt,
    ):
        ensure_tor_ready(
            use_bridges=True,
            bridges=["obfs4 192.0.2.1:9001", "obfs4 192.0.2.2:9001", "snowflake 192.0.2.3:1"],
        )
    ensure_pt.assert_called_once_with(["obfs4", "snowflake"])


def test_plain_ip_bridges_need_no_transport() -> None:
    """A vanilla bridge is just an address; requiring obfs4proxy for it would be wrong."""
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": True}),
        patch("ttp.tor_install.start_tor_service"),
        patch("ttp.tor_install.ensure_pluggable_transports") as ensure_pt,
    ):
        ensure_tor_ready(use_bridges=True, bridges=["192.0.2.1:9001"])
    ensure_pt.assert_not_called()


def test_bridges_without_the_flag_are_ignored() -> None:
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": True}),
        patch("ttp.tor_install.start_tor_service"),
        patch("ttp.tor_install.ensure_pluggable_transports") as ensure_pt,
    ):
        ensure_tor_ready(use_bridges=False, bridges=["obfs4 192.0.2.1:9001"])
    ensure_pt.assert_not_called()


def test_ensure_tor_ready_forwards_every_tor_option() -> None:
    with (
        patch("ttp.tor_install.detect_tor", return_value={"is_installed": True}),
        patch("ttp.tor_install.start_tor_service") as start,
    ):
        ensure_tor_ready(block_doh=False, disable_ipv6=True, use_bridges=False)
    assert start.call_args.kwargs["block_doh"] is False
    assert start.call_args.kwargs["disable_ipv6"] is True
