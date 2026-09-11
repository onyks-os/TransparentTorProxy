# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Behavioural tests for `ttp start`.

Mocks sit at the system boundary - `subprocess`, `pwd`, the filesystem, the Tor
control port - and the assertions are on what was *produced*: the generated
nftables ruleset, the lock file contents, the rendered CLI output.

That distinction is the whole point of this file. Its predecessor asserted on
the sequence of internal calls, which is how `ttp restart` shipped broken with a
dedicated passing test: the test encoded what the code did, so when the code was
wrong the test agreed with it.
"""

from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from ttp.cli import app
from ttp.commands._common import EXIT_UNVERIFIED
from ttp.exceptions import TorError

runner = CliRunner()


def _mock_cmd_tokens(cmd: object) -> list[str]:
    """Split mocked subprocess.run argv into tokens (avoids substring `in` on raw cmd)."""
    if isinstance(cmd, str):
        return cmd.split()
    if isinstance(cmd, (list, tuple)):
        return [str(arg) for arg in cmd]
    return str(cmd).split()


@pytest.fixture(autouse=True)
def _mock_logging():
    with patch("ttp.cli._setup_logging"):
        yield


@pytest.fixture(autouse=True)
def _mock_tmpfs_preflight():
    """start() calls check_tmpfs_space(); mock so CLI tests stay hermetic."""
    with patch("ttp.state.check_tmpfs_space"):
        yield


@pytest.fixture(autouse=True)
def _mock_root_euid():
    """Most CLI commands require root; mock geteuid to 0 by default."""
    with patch("os.geteuid", return_value=0):
        yield


@pytest.fixture
def mock_base_start():
    """Standard preflight/tor mocks for happy-path ttp start commands."""
    with (
        patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4")),
        patch("ttp.dns.apply_dns", return_value={"interface": "eth0"}),
        patch("ttp.dns.detect_active_interface", return_value="eth0"),
        patch(
            "ttp.tor_install.ensure_tor_ready",
            return_value={
                "is_installed": True,
                "is_running": True,
                "is_configured": True,
                "tor_user": "debian-tor",
                "version": "0.4.8.10",
            },
        ),
        patch("ttp.tor_install.setup_selinux_if_needed"),
        patch("ttp.state.read_lock", return_value=None),
        patch("ttp.state.is_orphan", return_value=False),
    ):
        yield


# start


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_happy_path(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """start with all systems go -> session active, ruleset generated, lock written."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    assert "Session active" in result.output

    # Assert produced artifact: generated nftables script
    assert mock_nft_str.call_count == 1
    ruleset = mock_nft_str.call_args[0][0]
    assert "127.0.0.1:9041" in ruleset
    assert "127.0.0.1:9054" in ruleset
    assert "meta skuid 110" in ruleset
    assert "policy drop" in ruleset

    # Assert lock artifact contents
    assert mock_write.call_count == 1
    lock_kwargs = mock_write.call_args.kwargs
    assert lock_kwargs["transport_port"] == 9041
    assert lock_kwargs["dns_port"] == 9054
    assert lock_kwargs["interface"] == "eth0"
    assert lock_kwargs["external_daemon"] is False


@patch("os.geteuid", return_value=1000)
def test_start_requires_root(mock_euid):
    """start without root -> exit code 1."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "root" in result.output


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.tor_install.setup_selinux_if_needed")
@patch("ttp.state.write_lock")
@patch("ttp.state.attempt_recovery")
@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.state.is_orphan", return_value=True)
def test_start_orphan_recovery(
    mock_orphan,
    mock_read,
    mock_recovery,
    mock_write,
    mock_selinux,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """start with orphaned session (PID dead) -> auto-recovers and continues."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 0
    assert "recovering" in result.output.lower()
    assert mock_recovery.call_count == 1
    assert mock_nft_str.call_count == 1
    assert "127.0.0.1:9041" in mock_nft_str.call_args[0][0]


@patch("ttp.state.read_lock", return_value={"pid": 1234})
@patch("ttp.state.is_orphan", return_value=False)
def test_start_concurrency_error(mock_orphan, mock_read):
    """start with another TTP instance running (PID alive) -> error."""
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "concurrency error" in result.output.lower()
    assert mock_read.call_count == 1


# stop


@patch("ttp.dns.apply_dns", return_value={"interface": "wlan0"})
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_with_interface_flag(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_apply_dns,
    mock_base_start,
):
    """start --interface wlan0 -> uses wlan0 instead of auto-detect."""
    result = runner.invoke(app, ["start", "--interface", "wlan0"])
    assert result.exit_code == 0
    assert mock_apply_dns.call_args.args[0] == "wlan0"
    assert mock_apply_dns.call_args.kwargs["dns_port"] == 9054
    assert mock_write.call_args.kwargs["interface"] == "wlan0"


# health check warning


@patch("ttp.state.delete_lock")
@patch("ttp.firewall.destroy_rules")
@patch("ttp.commands.start._verify_tor", return_value=(False, "1.2.3.4"))
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_tor_verification_fails(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_verify,
    mock_destroy,
    mock_delete_lock,
    mock_base_start,
):
    """
    Tor never bootstraps -> the session is *kept*, and the exit code says so.

    Reaching verification means the ruleset, the DNS overlay and the lock are
    already in place, so the host is fail-closed. Tearing it down here would
    trade a blocked network for an unannounced cleartext one, so the session
    stands; what changes is the signal. This used to exit 0, which let
    `ttp restart && ...` walk onto a blocked network believing it had succeeded.
    """
    result = runner.invoke(app, ["start"])
    assert result.exit_code == EXIT_UNVERIFIED
    assert "verification failed" in result.output
    assert "held fail-closed" in result.output
    assert mock_verify.call_count == 1

    # The session survives: rules produced, lock written, nothing torn down.
    assert mock_nft_str.call_count == 1
    assert "policy drop" in mock_nft_str.call_args[0][0]
    assert mock_write.call_count == 1
    assert mock_destroy.call_count == 0
    assert mock_delete_lock.call_count == 0


@patch("ttp.watchdog.start_watchdog")
@patch("ttp.commands.start._verify_tor", return_value=(False, "unknown"))
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_unverified_still_starts_the_watchdog(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_verify,
    mock_watchdog,
    mock_base_start,
):
    """The exit is raised *after* the watchdog gets its chance to start.

    An unverified session is the one that most needs watching; raising as soon
    as verification failed would have silently dropped `--watchdog`.
    """
    result = runner.invoke(app, ["start", "--watchdog"])
    assert result.exit_code == EXIT_UNVERIFIED
    assert mock_watchdog.call_count == 1


@patch("ttp.tor_install.ensure_tor_ready", side_effect=TorError("unit failed to start"))
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.state.write_lock")
def test_start_tor_unit_failure_leaves_the_host_in_cleartext(
    mock_write,
    mock_nft_str,
    mock_ensure,
    mock_base_start,
):
    """
    The other half of the recovery contract, and the reason it needs its own code.

    Tor fails at step 1, before a single rule is written, so the host is on
    plain clearnet rather than blocked - the exact opposite of the state above,
    reached from a failure that looks identical at the terminal. The assertion
    is on which state was produced (no ruleset, no lock), not merely that the
    command failed.
    """
    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert result.exit_code != EXIT_UNVERIFIED
    assert mock_nft_str.call_count == 0
    assert mock_write.call_count == 0


# uninstall


@patch("ttp.commands.start._verify_tor", return_value=(True, "1.2.3.4"))
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_with_bootstrap_timeout(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_verify,
    mock_base_start,
):
    result = runner.invoke(app, ["start", "--bootstrap-timeout", "300"])
    assert result.exit_code == 0
    assert mock_verify.call_args.kwargs["timeout"] == 300


# stop --restore-only


@patch("ttp.state.check_tmpfs_space")
@patch("ttp.state.read_lock", return_value=None)
def test_start_tmpfs_check_fails(mock_read, mock_check):
    """start aborts cleanly when /run has no space, without touching system state."""
    from ttp.exceptions import StateError

    mock_check.side_effect = StateError("Insufficient space on /run")

    result = runner.invoke(app, ["start"])
    assert result.exit_code == 1
    assert "Pre-flight Failed" in result.output
    assert "Insufficient space" in result.output
    assert mock_check.call_count == 1


# Custom Ports and Validation Tests


@patch("ttp.commands.start._is_port_in_use", return_value=False)
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_custom_ports_success(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_in_use,
    mock_base_start,
):
    """start with custom valid ports -> propagates them down into ruleset and lock."""
    result = runner.invoke(app, ["start", "--transport-port", "9080", "--dns-port", "9090"])
    assert result.exit_code == 0
    assert "Session active" in result.output

    # Assert ruleset artifact contains custom ports
    ruleset = mock_nft_str.call_args[0][0]
    assert "127.0.0.1:9080" in ruleset
    assert "127.0.0.1:9090" in ruleset
    assert "127.0.0.1:9041" not in ruleset

    # Assert lock artifact contains custom ports
    assert mock_write.call_args.kwargs["transport_port"] == 9080
    assert mock_write.call_args.kwargs["dns_port"] == 9090


def test_start_invalid_transport_port():
    """start with privileged or invalid transport port -> validation error."""
    # Under 1024
    result = runner.invoke(app, ["start", "-t", "80"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output

    # Over 65535
    result = runner.invoke(app, ["start", "-t", "70000"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output


def test_start_invalid_dns_port():
    """start with privileged or invalid dns port -> validation error."""
    # Under 1024
    result = runner.invoke(app, ["start", "-d", "53"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output

    # Over 65535
    result = runner.invoke(app, ["start", "-d", "65536"])
    assert result.exit_code == 1
    assert "Invalid Port" in result.output
    assert "between 1024 and 65535" in result.output


def test_start_duplicate_ports():
    """start with same port for transport and dns -> validation error."""
    result = runner.invoke(app, ["start", "-t", "9000", "-d", "9000"])
    assert result.exit_code == 1
    assert "Port Conflict" in result.output
    assert "cannot be the same" in result.output


@patch("ttp.commands.start._is_port_in_use", return_value=True)
def test_start_port_already_in_use(mock_in_use):
    """start with port already in use -> pre-flight check error."""
    result = runner.invoke(app, ["start", "-t", "9041"])
    assert result.exit_code == 1
    assert "Port In Use" in result.output
    assert "already in use by another process" in result.output
    assert mock_in_use.call_count == 1


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=110))
@patch("ttp.state.write_lock")
def test_start_with_allow_root_and_no_lan_bypass(
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """start with --allow-root and --no-lan-bypass flags -> ruleset contains root bypass & no LAN bypass."""
    result = runner.invoke(app, ["start", "--allow-root", "--no-lan-bypass"])
    assert result.exit_code == 0
    ruleset = mock_nft_str.call_args[0][0]
    assert "meta skuid 0 accept" in ruleset
    assert mock_write.call_args.kwargs["allow_root"] is True
    assert mock_write.call_args.kwargs["lan_bypass"] is False


# watchdog commands


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.state.write_lock")
@patch("pwd.getpwnam")
@patch("grp.getgrnam")
def test_start_with_bypass_user_and_group(
    mock_grp_nam,
    mock_pwd_nam,
    mock_write,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """Test start command with valid bypass users and groups."""
    mock_pwd_nam.side_effect = lambda name: (
        MagicMock(pw_uid=1001)
        if name == "user1"
        else (MagicMock(pw_uid=1002) if name == "user2" else MagicMock(pw_uid=110))
    )
    mock_grp_nam.return_value = MagicMock(gr_gid=2001)

    result = runner.invoke(app, ["start", "--bypass-user", "user1,user2", "--bypass-group", "group1"])
    assert result.exit_code == 0
    assert "Session active" in result.output

    # Assert ruleset artifact includes bypass user/group UIDs
    ruleset = mock_nft_str.call_args[0][0]
    assert "meta skuid 1001 accept" in ruleset
    assert "meta skuid 1002 accept" in ruleset
    assert "meta skgid 2001 accept" in ruleset

    # Check write_lock is called with bypass_users/bypass_groups
    kwargs_write = mock_write.call_args.kwargs
    assert kwargs_write["bypass_users"] == ["user1", "user2"]
    assert kwargs_write["bypass_groups"] == ["group1"]


@patch("pwd.getpwnam", side_effect=KeyError)
def test_start_with_invalid_bypass_user(mock_pwd_nam):
    """Test start command with invalid bypass user returns an error."""
    result = runner.invoke(app, ["start", "--bypass-user", "nonexistentuser"])
    assert result.exit_code == 1
    assert "User 'nonexistentuser' does not exist" in result.output
    assert mock_pwd_nam.call_count >= 1


# CLI Bridges Tests


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=MagicMock(pw_uid=110))
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_with_bridges_direct(
    mock_ensure,
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """Test start command with direct --bridge option."""
    result = runner.invoke(
        app,
        [
            "start",
            "--bridge",
            "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
            "--bridge",
            "snowflake 192.0.2.2:4321 601234567890ABCDEF",
        ],
    )
    assert result.exit_code == 0
    assert "Session active" in result.output

    # check ensure_tor_ready arguments
    kwargs_ensure = mock_ensure.call_args.kwargs
    assert kwargs_ensure["use_bridges"] is True
    assert kwargs_ensure["bridges"] == [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]

    # check write_lock arguments
    kwargs_write = mock_write.call_args.kwargs
    assert kwargs_write["use_bridges"] is True
    assert kwargs_write["bridges"] == [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=MagicMock(pw_uid=110))
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_with_bridge_file(
    mock_ensure,
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
    tmp_path,
):
    """Test start command with --bridge-file parsing comments and empty lines."""
    bridge_file = tmp_path / "my_bridges.txt"
    bridge_file.write_text(
        "# This is a comment\n"
        "\n"
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0\n"
        "   \n"
        "snowflake 192.0.2.2:4321 601234567890ABCDEF\n"
    )

    result = runner.invoke(app, ["start", "--bridge-file", str(bridge_file)])
    assert result.exit_code == 0
    assert "Session active" in result.output

    kwargs_ensure = mock_ensure.call_args.kwargs
    assert kwargs_ensure["use_bridges"] is True
    assert kwargs_ensure["bridges"] == [
        "obfs4 192.0.2.1:1234 501234567890ABCDEF iat-mode=0",
        "snowflake 192.0.2.2:4321 601234567890ABCDEF",
    ]


def test_start_with_invalid_bridge_format():
    """Test start command with invalid bridge format returns validation error."""
    result = runner.invoke(app, ["start", "--bridge", "obfs4_no_ip_port"])
    assert result.exit_code == 1
    assert "Invalid Bridge Line" in result.output


def test_start_use_bridges_without_bridges():
    """Test start command with --use-bridges but no bridges specified returns error."""
    result = runner.invoke(app, ["start", "--use-bridges"])
    assert result.exit_code == 1
    assert "No Bridges Provided" in result.output


# external-daemon (BYOD) mode tests


def test_start_external_daemon_watchdog_conflict():
    """Verify that passing --external-daemon and --watchdog raises a conflict error."""
    result = runner.invoke(app, ["start", "--external-daemon", "--watchdog"])
    assert result.exit_code == 1
    assert "Configuration Conflict" in result.output
    assert "Watchdog daemon cannot be used in external-daemon mode" in result.output


@patch("ttp.commands.start._is_port_listening_tcp", return_value=False)
@patch("ttp.commands.start._is_port_listening_udp", return_value=False)
def test_start_external_daemon_inactive(mock_udp, mock_tcp):
    """Verify that starting TTP in BYOD mode when ports are not active fails."""
    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 1
    assert "Tor Not Running" in result.output
    assert mock_tcp.call_count == 1


@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_happy_path_manual_uid(
    mock_ensure,
    mock_lock,
    mock_run_nft,
    mock_nft_str,
    mock_pwnam,
    mock_udp,
    mock_tcp,
    mock_base_start,
):
    """Verify happy path in BYOD mode with manual --tor-uid override."""
    mock_user = MagicMock()
    mock_user.pw_uid = 101
    mock_pwnam.return_value = mock_user

    result = runner.invoke(app, ["start", "--external-daemon", "--tor-uid", "debian-tor"])
    assert result.exit_code == 0
    assert "Tor daemon detected operating under UID: 101" in result.output

    assert mock_ensure.call_count == 0
    ruleset = mock_nft_str.call_args[0][0]
    assert "meta skuid 101" in ruleset

    kwargs_lock = mock_lock.call_args.kwargs
    assert kwargs_lock["external_daemon"] is True


@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("ttp.commands.start._get_uid_from_port", return_value=105)
@patch("pwd.getpwuid")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_happy_path_auto_uid(
    mock_ensure,
    mock_lock,
    mock_run_nft,
    mock_nft_str,
    mock_pwuid,
    mock_get_uid,
    mock_udp,
    mock_tcp,
    mock_base_start,
):
    """Verify happy path in BYOD mode with port-owner auto-detected UID."""
    mock_user = MagicMock()
    mock_user.pw_name = "tor-process"
    mock_pwuid.return_value = mock_user

    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 0
    assert "Tor daemon detected operating under UID: 105" in result.output

    assert mock_get_uid.call_args[0][0] == 9041
    ruleset = mock_nft_str.call_args[0][0]
    assert "meta skuid 105" in ruleset


@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("ttp.commands.start._get_uid_from_port", return_value=None)
@patch("pwd.getpwnam")
@patch("ttp.firewall.apply_rules")
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_happy_path_fallback_user(
    mock_ensure,
    mock_lock,
    mock_firewall,
    mock_pwnam,
    mock_get_uid,
    mock_udp,
    mock_tcp,
    mock_base_start,
):
    """Verify happy path in BYOD mode with fallback standard system users."""
    mock_user = MagicMock()
    mock_user.pw_uid = 110
    mock_pwnam.return_value = mock_user

    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 0
    assert "Tor daemon detected operating under UID: 110" in result.output

    mock_pwnam.assert_any_call("tor")


@patch("ttp.commands.start._is_port_listening_tcp", return_value=True)
@patch("ttp.commands.start._is_port_listening_udp", return_value=True)
@patch("ttp.commands.start._get_uid_from_port", return_value=None)
@patch("pwd.getpwnam", side_effect=KeyError("Not found"))
@patch("ttp.firewall.apply_rules")
@patch("ttp.state.write_lock")
@patch("ttp.tor_install.ensure_tor_ready")
def test_start_external_daemon_uid_resolution_failure(
    mock_ensure,
    mock_lock,
    mock_firewall,
    mock_pwnam,
    mock_get_uid,
    mock_udp,
    mock_tcp,
    mock_base_start,
):
    """Verify that startup fails if no Tor UID can be determined."""
    result = runner.invoke(app, ["start", "--external-daemon"])
    assert result.exit_code == 1
    assert "Tor UID Resolution Failed" in result.output


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=MagicMock(pw_uid=110))
@patch("ttp.state.write_lock")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_start_no_ipv6_unsupported(
    mock_ipv6,
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """Verify superfluous warning is printed when IPv6 is unsupported and --no-ipv6 is passed."""
    result = runner.invoke(app, ["start", "--no-ipv6"])
    assert result.exit_code == 0
    assert "superfluous" in result.output

    ruleset = mock_nft_str.call_args[0][0]
    assert "meta nfproto ipv6 drop" in ruleset
    assert mock_write.call_args.kwargs["no_ipv6"] is True


@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.firewall.runner.pwd.getpwnam", return_value=MagicMock(pw_uid=110))
@patch("ttp.state.write_lock")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_start_no_ipv6_supported(
    mock_ipv6,
    mock_write,
    mock_pwd,
    mock_run_nft,
    mock_nft_str,
    mock_base_start,
):
    """Verify info message is printed when IPv6 is supported and --no-ipv6 is passed."""
    result = runner.invoke(app, ["start", "--no-ipv6"])
    assert result.exit_code == 0
    assert "IPv6 traffic will be dropped" in result.output

    ruleset = mock_nft_str.call_args[0][0]
    assert "meta nfproto ipv6 drop" in ruleset
    assert mock_write.call_args.kwargs["no_ipv6"] is True


# ---------------------------------------------------------------------------
# Unit tests for private helpers extracted from start_command
# ---------------------------------------------------------------------------


import typer  # noqa: E402

from ttp.commands.start import (  # noqa: E402
    _parse_bridges,
    _parse_bypass_users_groups,
    _resolve_external_tor_uid,
)


class TestParseBypassUsersGroups:
    """Unit tests for _parse_bypass_users_groups()."""

    @patch("grp.getgrnam")
    @patch("pwd.getpwnam")
    def test_single_user_and_group(self, mock_pwnam, mock_grpnam):
        mock_pwnam.return_value = types.SimpleNamespace(pw_uid=1001)
        mock_grpnam.return_value = types.SimpleNamespace(gr_gid=2001)

        users, groups, uids, gids = _parse_bypass_users_groups(["alice"], ["staff"])
        assert users == ["alice"]
        assert groups == ["staff"]
        assert uids == [1001]
        assert gids == [2001]

    @patch("pwd.getpwnam")
    def test_comma_separated_users(self, mock_pwnam):
        mock_pwnam.return_value = types.SimpleNamespace(pw_uid=1001)
        users, _, uids, _ = _parse_bypass_users_groups(["alice,bob"], None)
        assert users == ["alice", "bob"]
        assert len(uids) == 2

    @patch("pwd.getpwuid")
    def test_numeric_uid_accepted(self, mock_pwuid):
        mock_pwuid.return_value = types.SimpleNamespace(pw_uid=1234)
        _users, _, uids, _ = _parse_bypass_users_groups(["1234"], None)
        assert uids == [1234]

    @patch("pwd.getpwnam", side_effect=KeyError)
    def test_invalid_user_raises_exit(self, mock_pwnam):
        with pytest.raises(typer.Exit):
            _parse_bypass_users_groups(["nonexistent"], None)

    @patch("grp.getgrnam", side_effect=KeyError)
    def test_invalid_group_raises_exit(self, mock_grpnam):
        with pytest.raises(typer.Exit):
            _parse_bypass_users_groups(None, ["nosuchgroup"])

    def test_none_inputs_returns_empty_lists(self):
        users, groups, uids, gids = _parse_bypass_users_groups(None, None)
        assert users == []
        assert groups == []
        assert uids == []
        assert gids == []


class TestParseBridges:
    """Unit tests for _parse_bridges()."""

    def test_valid_direct_bridge(self):
        lines, use_bridges = _parse_bridges(None, ["obfs4 192.0.2.1:1234 FINGERPRINT iat-mode=0"], False)
        assert lines == ["obfs4 192.0.2.1:1234 FINGERPRINT iat-mode=0"]
        assert use_bridges is True

    def test_multiple_bridges(self):
        bridges = [
            "obfs4 192.0.2.1:1234 FP iat-mode=0",
            "snowflake 192.0.2.2:4321 FP2",
        ]
        lines, use_bridges = _parse_bridges(None, bridges, False)
        assert len(lines) == 2
        assert use_bridges is True

    def test_use_bridges_without_lines_raises_exit(self):
        with pytest.raises(typer.Exit):
            _parse_bridges(None, None, True)

    def test_invalid_bridge_format_raises_exit(self):
        with pytest.raises(typer.Exit):
            _parse_bridges(None, ["notabridgeline"], False)

    def test_bridge_file_parsed_correctly(self, tmp_path):
        bf = tmp_path / "bridges.txt"
        bf.write_text("# comment\n\nobfs4 192.0.2.1:1234 FP iat-mode=0\n   \nsnowflake 192.0.2.2:4321 FP2\n")
        lines, use_bridges = _parse_bridges(bf, None, False)
        assert lines == [
            "obfs4 192.0.2.1:1234 FP iat-mode=0",
            "snowflake 192.0.2.2:4321 FP2",
        ]
        assert use_bridges is True

    def test_missing_bridge_file_raises_exit(self, tmp_path):
        missing = tmp_path / "missing.txt"
        with pytest.raises(typer.Exit):
            _parse_bridges(missing, None, False)

    def test_no_bridges_no_use_bridges_returns_empty(self):
        lines, use_bridges = _parse_bridges(None, None, False)
        assert lines == []
        assert use_bridges is False


class TestResolveExternalTorUid:
    """Unit tests for _resolve_external_tor_uid()."""

    @patch("pwd.getpwnam")
    def test_manual_override_by_name(self, mock_pwnam):
        mock_pwnam.return_value = types.SimpleNamespace(pw_uid=101)
        result = _resolve_external_tor_uid(9041, "debian-tor")
        assert result == "101"

    def test_manual_override_numeric(self):
        result = _resolve_external_tor_uid(9041, "999")
        assert result == "999"

    @patch("pwd.getpwnam", side_effect=KeyError)
    def test_manual_override_nonexistent_user_raises_exit(self, mock_pwnam):
        with pytest.raises(typer.Exit):
            _resolve_external_tor_uid(9041, "nosuchuser")

    @patch("pwd.getpwuid")
    @patch("ttp.commands.start._get_uid_from_port", return_value=105)
    def test_autodetect_via_port(self, mock_port, mock_pwuid):
        mock_pwuid.return_value = types.SimpleNamespace(pw_name="tor-process")
        result = _resolve_external_tor_uid(9041, None)
        assert result == "105"

    @patch("pwd.getpwuid")
    @patch("ttp.commands.start._get_uid_from_port", return_value=0)
    def test_autodetect_skips_root_uid(self, mock_port, mock_pwuid):
        # UID 0 (root) is not a valid Tor user - skip to next step
        mock_pwuid.return_value = types.SimpleNamespace(pw_name="root")
        with patch("pwd.getpwnam") as mock_pwnam:
            mock_pwnam.return_value = types.SimpleNamespace(pw_uid=110)
            result = _resolve_external_tor_uid(9041, None)
            # Should fall through to fallback user "tor"
            assert result == "110"

    @patch("ttp.commands.start._get_uid_from_port", return_value=None)
    @patch("pwd.getpwnam")
    def test_fallback_to_debian_tor(self, mock_pwnam, mock_port):
        mock_pwnam.side_effect = lambda u: (
            (_ for _ in ()).throw(KeyError("not found")) if u == "tor" else types.SimpleNamespace(pw_uid=110)
        )
        result = _resolve_external_tor_uid(9041, None)
        assert result == "110"

    @patch("ttp.commands.start._get_uid_from_port", return_value=None)
    @patch("pwd.getpwnam", side_effect=KeyError)
    def test_all_steps_fail_raises_exit(self, mock_pwnam, mock_port):
        with pytest.raises(typer.Exit):
            _resolve_external_tor_uid(9041, None)
