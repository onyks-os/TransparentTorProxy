# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Explicit link policy must not be confused with an inherited global value."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ttp import dns_policy
from ttp.cli import app
from ttp.exceptions import DNSError, DNSSECConflictError
from ttp.paths import UnsafeBinaryError


@pytest.fixture
def policy(tmp_path, monkeypatch):
    resolved = tmp_path / "resolved"
    networkd = tmp_path / "networkd"
    resolved.mkdir()
    networkd.mkdir()
    monkeypatch.setattr(dns_policy, "RESOLVED_LINKS", resolved)
    monkeypatch.setattr(dns_policy, "NETWORKD_LINKS", networkd)
    monkeypatch.setattr(dns_policy.dns_resolved, "is_resolved_active", lambda **kwargs: True)
    monkeypatch.setattr(dns_policy.socket, "if_nameindex", lambda: [(1, "lo"), (3, "wlo1")])
    modes = {"global": "yes", "link": "yes"}

    def run(cmd, **kwargs):
        assert "--auto-start=no" in cmd
        assert not any(token.startswith("Set") for token in cmd)
        if "GetLink" in cmd:
            reply = {"type": "o", "data": ["/org/freedesktop/resolve1/link/_33"]}
        else:
            value = modes["global" if "org.freedesktop.resolve1.Manager" in cmd else "link"]
            reply = {"type": "s", "data": value}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(reply), "")

    monkeypatch.setattr(dns_policy.subprocess, "run", run)
    return resolved / "3", networkd / "3", modes


@pytest.mark.parametrize("global_mode", ["yes", "no", "allow-downgrade"])
def test_global_policy_is_inherited_not_a_conflict(policy, global_mode):
    resolved, _, modes = policy
    resolved.write_text("# This is private data. Do not parse.\nSERVERS=9.9.9.9\n")
    modes.update({"global": global_mode, "link": global_mode})
    dns_policy.check_dnssec_policy()


def test_missing_saved_state_means_no_explicit_override(policy):
    dns_policy.check_dnssec_policy()


@pytest.mark.parametrize("mode", ["no", "allow-downgrade"])
def test_non_mandatory_link_policy_is_preserved(policy, mode):
    resolved, _, modes = policy
    text = f'DNSSEC="{mode}"\n'
    resolved.write_text(text)
    modes["link"] = mode
    dns_policy.check_dnssec_policy()
    assert resolved.read_text() == text


@pytest.mark.parametrize("global_mode", ["yes", "no"])
def test_explicit_resolved_requirement_is_refused_and_preserved(policy, global_mode):
    resolved, _, modes = policy
    modes["global"] = global_mode
    resolved.write_text("DNSSEC=yes\n")
    with pytest.raises(DNSSECConflictError, match="wlo1 explicitly requires DNSSEC=yes"):
        dns_policy.check_dnssec_policy()
    assert resolved.read_text() == "DNSSEC=yes\n"


@pytest.mark.parametrize("admin", ["configuring", "configured", "failed", "linger"])
def test_networkd_requirement_is_refused(policy, admin):
    _, networkd, _ = policy
    networkd.write_text(f"ADMIN_STATE={admin}\nDNSSEC=yes\n")
    with pytest.raises(DNSSECConflictError):
        dns_policy.check_dnssec_policy()


def test_networkd_ownership_ignores_stale_resolved_state(policy):
    resolved, networkd, _ = policy
    networkd.write_text("ADMIN_STATE=configured\n")
    resolved.write_text("DNSSEC=yes\n")
    dns_policy.check_dnssec_policy()


@pytest.mark.parametrize("admin", ["pending", "initialized", "unmanaged"])
def test_unmanaged_networkd_state_does_not_hide_resolved_requirement(policy, admin):
    resolved, networkd, _ = policy
    networkd.write_text(f"ADMIN_STATE={admin}\nDNSSEC=no\n")
    resolved.write_text("DNSSEC=yes\n")
    with pytest.raises(DNSSECConflictError):
        dns_policy.check_dnssec_policy()


@pytest.mark.parametrize(
    "content", ["DNSSEC=maybe\n", "DNSSEC=\n", "DNSSEC=yes no\n", 'DNSSEC="yes\n', "DNSSEC=no\nDNSSEC=yes\n"]
)
def test_unrecognized_saved_policy_is_not_treated_as_inheritance(policy, content):
    policy[0].write_text(content)
    with pytest.raises(DNSError, match="Cannot determine") as error:
        dns_policy.check_dnssec_policy()
    assert not isinstance(error.value, DNSSECConflictError)


def test_unknown_networkd_state_is_refused(policy):
    policy[1].write_text("ADMIN_STATE=future-state\n")
    with pytest.raises(DNSError, match="Unrecognized networkd"):
        dns_policy.check_dnssec_policy()


def test_networkd_state_without_ownership_information_is_refused(policy):
    policy[1].write_text("DNSSEC=no\n")
    with pytest.raises(DNSError, match="Missing networkd administrative state"):
        dns_policy.check_dnssec_policy()


@pytest.mark.parametrize("reply", ["/org/freedesktop/resolve1/link/_33", [], [4]])
def test_malformed_getlink_reply_is_an_inspection_error(policy, reply):
    original = dns_policy.subprocess.run

    def run(cmd, **kwargs):
        if "GetLink" in cmd:
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"type": "o", "data": reply}))
        return original(cmd, **kwargs)

    with patch.object(dns_policy.subprocess, "run", side_effect=run):
        with pytest.raises(DNSError, match="Unexpected GetLink reply"):
            dns_policy.check_dnssec_policy()


@pytest.mark.parametrize("status,rc", [("", 0), ("activating", 3), ("active", 1)])
def test_indeterminate_service_state_is_not_treated_as_inactive(status, rc):
    with patch.object(dns_policy.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, status)):
        with pytest.raises(DNSError, match="Cannot inspect systemd-resolved"):
            dns_policy.check_dnssec_policy()


@pytest.mark.parametrize("status,rc", [("inactive", 3), ("failed", 3), ("unknown", 4)])
def test_known_inactive_service_requires_no_dnssec_policy(status, rc):
    with patch.object(dns_policy.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, status)):
        dns_policy.check_dnssec_policy()


def test_dbus_and_saved_policy_must_agree(policy):
    policy[2]["link"] = "no"
    with pytest.raises(DNSError, match="disagrees"):
        dns_policy.check_dnssec_policy()


@pytest.mark.parametrize(
    "payload",
    ["not json", "[]", "{}", '{"type":"b","data":true}', '{"type":"s","data":"future"}', '{"type":"s","data":[]}'],
)
def test_unrecognized_bus_reply_refuses_start(policy, payload):
    with patch.object(dns_policy.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, payload)):
        with pytest.raises(DNSError):
            dns_policy.check_dnssec_policy()


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("busctl missing"),
        UnsafeBinaryError("busctl permissions are unsafe"),
        subprocess.TimeoutExpired("busctl", 10),
        subprocess.CalledProcessError(1, "busctl"),
    ],
)
def test_bus_failure_is_visible(policy, error):
    with patch.object(dns_policy.subprocess, "run", side_effect=error):
        with pytest.raises(DNSError, match="Cannot determine"):
            dns_policy.check_dnssec_policy()


def test_unreadable_state_is_not_treated_as_inheritance(policy):
    with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
        with pytest.raises(DNSError, match="denied"):
            dns_policy.check_dnssec_policy()


def test_network_change_during_check_requires_retry(policy):
    with patch.object(dns_policy.socket, "if_nameindex", side_effect=[[(3, "wlo1")], [(4, "eth0")]]):
        with pytest.raises(DNSError, match="changed during preflight"):
            dns_policy.check_dnssec_policy()


def test_no_resolved_needs_no_bus_or_state_access():
    with patch.object(dns_policy.dns_resolved, "is_resolved_active", return_value=False):
        with patch.object(dns_policy.subprocess, "run") as run:
            dns_policy.check_dnssec_policy()
        run.assert_not_called()


@pytest.mark.parametrize("command", ["start", "restart"])
@pytest.mark.parametrize("quiet", [False, True])
def test_cli_conflict_exits_four_before_any_network_mutation(policy, command, quiet):
    policy[0].write_text("DNSSEC=yes\n")
    with (
        patch("ttp.cli._setup_logging"),
        patch("os.geteuid", return_value=0),
        patch("ttp.commands.start.require_systemd"),
        patch("ttp.commands.stop_restart.require_systemd"),
        patch("ttp.commands.start.validate_ports"),
        patch("ttp.commands.start.setup_managed_tor") as tor,
        patch("ttp.commands.start.check_session_state") as recovery,
        patch("ttp.firewall.apply_rules") as firewall,
        patch("ttp.dns.apply_dns") as dns,
        patch("ttp.commands.stop_restart._do_stop") as stop,
        patch("ttp.state.write_lock") as lock,
    ):
        result = CliRunner().invoke(app, (["--quiet"] if quiet else []) + [command])
    assert result.exit_code == 4, result.output
    assert "explicitly requires DNSSEC=yes" in result.output
    unwrapped = "".join(line.strip(" │") for line in result.output.splitlines())
    assert dns_policy.DNSSEC_HELP in unwrapped
    for mutation in (tor, recovery, firewall, dns, stop, lock):
        mutation.assert_not_called()
    # The CLI's console state is global; do not let --quiet affect later tests.
    from ttp.commands._common import console

    console.quiet = False


def test_cli_unknown_policy_is_an_error_not_a_proven_conflict(policy):
    policy[0].write_text("DNSSEC=unknown\n")
    with (
        patch("ttp.cli._setup_logging"),
        patch("os.geteuid", return_value=0),
        patch("ttp.commands.start.require_systemd"),
        patch("ttp.commands.start.validate_ports"),
        patch("ttp.firewall.apply_rules") as firewall,
    ):
        result = CliRunner().invoke(app, ["start"])
    assert result.exit_code == 1
    assert "Cannot determine" in result.output
    firewall.assert_not_called()
