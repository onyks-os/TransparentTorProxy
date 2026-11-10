# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Adversarial public VPN evidence and independent guard recovery contracts."""

from __future__ import annotations

import copy
import json
import subprocess
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ttp import vpn, vpn_guard
from ttp.cli import app

UUID = "12345678-1234-4234-8234-123456789012"
ACTIVE = vpn.ROOT + "/ActiveConnection/1"
DEVICE = vpn.ROOT + "/Devices/2"
PEER = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def policy() -> vpn.VPNPolicy:
    return vpn.VPNPolicy(UUID, ACTIVE, "wg0", 7, "eth0", 2, PEER, "192.0.2.1", 51820, 51820, False)


@pytest.fixture
def host(monkeypatch):
    config = {
        "connection": {"type": "wireguard", "uuid": UUID},
        "wireguard": {"peers": [{"public-key": PEER, "endpoint": "192.0.2.1:51820", "allowed-ips": ["0.0.0.0/0"]}]},
    }
    properties = {
        (vpn.ROOT, "ActiveConnections"): [ACTIVE],
        (ACTIVE, "Uuid"): UUID,
        (ACTIVE, "State"): 2,
        (ACTIVE, "Devices"): [DEVICE],
        (DEVICE, "Interface"): "wg0",
    }
    replies = {
        ("wg", "show", "wg0", "endpoints"): f"{PEER}\t192.0.2.1:51820",
        ("wg", "show", "wg0", "allowed-ips"): f"{PEER}\t0.0.0.0/0",
        ("wg", "show", "wg0", "fwmark"): "0xca6c",
        ("wg", "show", "wg0", "latest-handshakes"): f"{PEER}\t0",
    }

    def run(binary, *args):
        if binary == "busctl":
            command = list(args)[4:]
            if command[0] == "get-property":
                return json.dumps({"data": properties[(command[2], command[4])]})
            elif command[4] == "GetConnectionByUuid":
                data = vpn.ROOT + "/Settings/1"
            else:
                assert command[4] == "GetSettings"  # Never GetSecrets.
                data = config
            return json.dumps({"data": [data]})
        if binary == "ip":
            if "route" in args:
                return json.dumps([{"dev": "eth0" if "192.0.2.1" in args else "wg0"}])
            name = args[-1]
            return json.dumps(
                [
                    {
                        "ifindex": 7 if name == "wg0" else 2,
                        "flags": ["UP"],
                        "linkinfo": {"info_kind": "wireguard" if name == "wg0" else "veth"},
                    }
                ]
            )
        return replies[(binary, *args)]

    monkeypatch.setattr(vpn, "_run", run)
    return config, properties, replies


def test_public_profile_and_kernel_must_agree(host):
    assert vpn.inspect_profile(UUID, no_ipv6=True, tor_uid=100) == policy()


@pytest.mark.parametrize(
    "change", ["hostname", "inactive", "multiple_peers", "roaming", "missing_mark", "wrong_allowed", "ipv6"]
)
def test_unsupported_or_changed_path_is_refused(host, change):
    config, props, replies = host
    if change == "hostname":
        config["wireguard"]["peers"][0]["endpoint"] = "vpn.example:51820"
    elif change == "inactive":
        props[(ACTIVE, "State")] = 1
    elif change == "multiple_peers":
        config["wireguard"]["peers"] *= 2
    elif change == "roaming":
        replies[("wg", "show", "wg0", "endpoints")] = f"{PEER}\t192.0.2.2:51820"
    elif change == "missing_mark":
        replies[("wg", "show", "wg0", "fwmark")] = "off"
    elif change == "wrong_allowed":
        replies[("wg", "show", "wg0", "allowed-ips")] = f"{PEER}\t192.0.2.0/24"
    with pytest.raises(vpn.VPNError):
        vpn.inspect_profile(UUID, no_ipv6=change != "ipv6")


@pytest.mark.parametrize(
    "remote", ["localhost:123", "example.org:443", "[::1]:42", "[fe80::1%eth0]:42", "192.0.2.1:0", "192.0.2.1:65536"]
)
def test_numeric_endpoint_validation(remote):
    with pytest.raises(vpn.VPNError):
        vpn.endpoint(remote)


@pytest.mark.parametrize("field,value", [("policy", "accept"), ("hook", "output")])
def test_guard_cannot_be_adopted_from_a_tampered_kernel(monkeypatch, field, value):
    expected = vpn_guard.specification(policy(), 100)
    changed = copy.deepcopy(expected)
    changed[1]["chain"][field] = value
    monkeypatch.setattr(
        vpn_guard, "_nft", lambda *a, **k: subprocess.CompletedProcess([], 0, json.dumps({"nftables": changed}), "")
    )
    with pytest.raises(vpn.VPNError, match="frozen contract"):
        vpn_guard.verify(policy(), 100)


def test_failed_guard_install_keeps_exclusive_private_intent(tmp_path, monkeypatch):
    intent = tmp_path / "intent"
    monkeypatch.setattr(vpn_guard, "INTENT", intent)
    monkeypatch.setattr(vpn_guard, "_table_exists", lambda: False)
    monkeypatch.setattr(vpn_guard, "_nft", lambda *a, **k: subprocess.CompletedProcess([], 1, "", "failed"))
    with pytest.raises(vpn.VPNError, match="intent retained"):
        vpn_guard.install(policy(), 100)
    assert intent.stat().st_mode & 0o777 == 0o600
    assert json.loads(intent.read_text())["vpn"] == policy().snapshot()
    with pytest.raises(vpn.VPNError, match="earlier attempt"):
        vpn_guard.install(policy(), 100)


def test_uncertain_tor_stop_cannot_release_guard(tmp_path, monkeypatch):
    intent = tmp_path / "intent"
    intent.write_text("{}")
    monkeypatch.setattr(vpn_guard, "INTENT", intent)
    monkeypatch.setattr(vpn_guard, "resolve", lambda name: name)
    monkeypatch.setattr(
        vpn_guard.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess([], 0, "ActiveState=active\nMainPID=42\nControlPID=0\n", ""),
    )
    with pytest.raises(vpn.VPNError, match="retained"):
        vpn_guard.release_after_stop()
    assert intent.exists()


@pytest.mark.parametrize(
    "flags", [[], ["--no-lan-bypass"], ["--watchdog"], ["--watchdog", "--no-lan-bypass", "--allow-root"]]
)
def test_vpn_requirements_fail_before_network_mutation(flags, monkeypatch):
    monkeypatch.setattr("ttp.commands.start._require_root", lambda: None)
    monkeypatch.setattr("ttp.commands.start.require_systemd", lambda: None)
    with (
        patch("ttp.cli._setup_logging"),
        patch("ttp.commands.start.setup_managed_tor") as tor,
        patch("ttp.firewall.apply_rules") as fw,
    ):
        result = CliRunner().invoke(app, ["start", "--require-vpn", UUID, *flags])
    assert result.exit_code == 10
    tor.assert_not_called()
    fw.assert_not_called()
    assert "watchdog" in result.output


def test_restart_refuses_vpn_session_before_stop(monkeypatch):
    monkeypatch.setattr("ttp.commands.stop_restart._require_root", lambda: None)
    monkeypatch.setattr("ttp.commands.stop_restart.require_systemd", lambda: None)
    monkeypatch.setattr("ttp.commands.stop_restart.require_dnssec_compatibility", lambda: None)
    monkeypatch.setattr("ttp.state.read_lock", lambda **kw: {"vpn": policy().snapshot()})
    with patch("ttp.cli._setup_logging"), patch("ttp.commands.stop_restart._do_stop") as stop:
        result = CliRunner().invoke(app, ["restart"])
    assert result.exit_code == 10
    stop.assert_not_called()


def test_guard_failure_prevents_managed_tor_start(monkeypatch):
    from ttp import tor_install

    monkeypatch.setattr(tor_install, "detect_tor", lambda **kw: {"is_installed": True, "tor_user": "tor"})
    monkeypatch.setattr(tor_install, "_assert_is_tor_system_account", lambda user: None)

    def failed_guard(user):
        raise vpn.VPNError("Guard installation unconfirmed")

    with patch.object(tor_install, "start_tor_service") as start:
        with pytest.raises(vpn.VPNError):
            tor_install.ensure_tor_ready(before_start=failed_guard)
    start.assert_not_called()


def test_manual_check_contains_missing_vpn_before_external_probe(monkeypatch):
    from ttp import session_report
    from ttp.evidence import Result, VerificationState

    lock = {"session_id": "s", "vpn": policy().snapshot()}
    monkeypatch.setattr(session_report.state, "read_lock", lambda **kw: lock)
    monkeypatch.setattr(session_report, "emergency_latched", lambda lock: False)
    monkeypatch.setattr(session_report, "observe_session", lambda: {"vpn": {"state": "unknown"}})
    with (
        patch("ttp.probe.verify_session") as probe,
        patch.object(session_report, "request_emergency", return_value=Result()) as contain,
    ):
        verification, _ = session_report.check_session()
    assert verification.state is VerificationState.NOT_RUN
    contain.assert_called_once()
    probe.assert_not_called()


def test_watchdog_identifies_vpn_fault_before_other_components(monkeypatch):
    from ttp.watchdog.integrity import check_system_integrity

    monkeypatch.setattr("ttp.state.read_lock", lambda: {"vpn": policy().snapshot(), "tor_uid": 100})
    monkeypatch.setattr(vpn, "observe", lambda *a: {"state": "unknown", "reason": "vpn.path_lost"})
    assert check_system_integrity() == ("vpn", "vpn.path_lost")


def test_missing_session_with_startup_intent_is_not_reported_absent(tmp_path, monkeypatch):
    from ttp.session_report import observe_session

    intent = tmp_path / "intent"
    intent.write_text("{}")
    monkeypatch.setattr(vpn_guard, "INTENT", intent)
    monkeypatch.setattr("ttp.state.read_lock", lambda **kw: None)
    report = observe_session()
    assert report["phase"] == "protection_retained" and report["session_exit_code"] == 10


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"uuid": "bad"},
        {**policy().snapshot(), "uuid": UUID.upper()},
        {**policy().snapshot(), "active_path": "/bad"},
        {**policy().snapshot(), "interface": "lo"},
        {**policy().snapshot(), "underlay": "wg0"},
        {**policy().snapshot(), "ifindex": True},
        {**policy().snapshot(), "mark": 2**32},
        {**policy().snapshot(), "peer": "YQ=="},
        {**policy().snapshot(), "address": "2001:0db8::1"},
    ],
)
def test_corrupt_frozen_policy_is_refused(value):
    # UUID is numeric-only in the sample; this case still exercises a valid round trip.
    if value == policy().snapshot():
        assert vpn.VPNPolicy.from_snapshot(value) == policy()
    else:
        with pytest.raises(vpn.VPNError):
            vpn.VPNPolicy.from_snapshot(value)


@pytest.mark.parametrize("output", ["not json", '{"data": []}', '{"missing": 1}'])
def test_bad_bus_replies_never_become_vpn_evidence(monkeypatch, output):
    monkeypatch.setattr(vpn, "_run", lambda *a: output)
    with pytest.raises(vpn.VPNError):
        vpn._bus("call")


def test_bus_variants_preserve_values_without_requesting_secrets():
    assert vpn._unpack({"x": {"type": "s", "data": "public"}}) == {"x": "public"}


@pytest.mark.parametrize(
    "response",
    [
        subprocess.CompletedProcess([], 0, " ok \n", ""),
        subprocess.CompletedProcess([], 1, "", ""),
        subprocess.CompletedProcess([], 0, "x" * 262145, ""),
        OSError(),
        subprocess.TimeoutExpired("tool", 2),
    ],
)
def test_external_observations_are_bounded_and_fail_closed(monkeypatch, response):
    monkeypatch.setattr(vpn, "resolve", lambda name: name)

    def run(*a, **kw):
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(vpn.subprocess, "run", run)
    if isinstance(response, subprocess.CompletedProcess) and response.stdout == " ok \n":
        assert vpn._run("wg", "show", "wg0", "fwmark") == "ok"
    else:
        with pytest.raises(vpn.VPNError):
            vpn._run("wg", "show", "wg0", "fwmark")


@pytest.mark.parametrize("reply", ["[]", '[{"type":"blackhole"}]', "invalid"])
def test_failed_effective_route_is_unknown(monkeypatch, reply):
    monkeypatch.setattr(vpn, "_run", lambda *a: reply)
    with pytest.raises(vpn.VPNError):
        vpn._route("192.0.2.1")


@pytest.mark.parametrize(
    "change",
    [
        "type",
        "uuid",
        "devices",
        "interface",
        "link",
        "underlay_down",
        "underlay_tunnel",
        "route",
        "key",
        "invalid_reply",
    ],
)
def test_profile_identity_and_routing_must_be_supported(host, monkeypatch, change):
    config, props, replies = host
    original = vpn._run
    if change == "type":
        config["connection"]["type"] = "vpn"
    elif change == "uuid":
        config["connection"]["uuid"] = "wrong"
    elif change == "devices":
        props[(ACTIVE, "Devices")] = []
    elif change == "interface":
        props[(DEVICE, "Interface")] = "invalid/name"
    elif change == "key":
        replies[("wg", "show", "wg0", "allowed-ips")] = "another-key 0.0.0.0/0"

    def run(binary, *args):
        if binary == "ip":
            if change == "invalid_reply":
                return "{}"
            if "route" in args and change == "route":
                return '[{"dev":"eth0"}]'
            if "link" in args:
                row = json.loads(original(binary, *args))[0]
                if change == "link":
                    row["flags"] = []
                if args[-1] == "eth0" and change == "underlay_down":
                    row["flags"] = []
                if args[-1] == "eth0" and change == "underlay_tunnel":
                    row["linkinfo"]["info_kind"] = "wireguard"
                return json.dumps([row])
        return original(binary, *args)

    monkeypatch.setattr(vpn, "_run", run)
    with pytest.raises(vpn.VPNError):
        vpn.inspect_profile(UUID, no_ipv6=True)


@pytest.mark.parametrize(
    "changed,broken_guard,handshake",
    [(False, False, "0"), (True, False, "0"), (False, True, "0"), (False, False, "invalid")],
)
def test_vpn_path_and_guard_are_independent_evidence(monkeypatch, changed, broken_guard, handshake):
    monkeypatch.setattr(vpn, "inspect_profile", lambda *a, **k: None if changed else policy())
    monkeypatch.setattr(vpn, "_run", lambda *a: f"{PEER}\t{handshake}")

    def verify(*args):
        if broken_guard:
            raise vpn.VPNError("Unreadable kernel")

    monkeypatch.setattr(vpn_guard, "verify", verify)
    report = vpn.observe(policy(), 100)
    assert report["guard_verified"] is not broken_guard
    assert (report["state"] == "constrained") is (not changed and not broken_guard and handshake == "0")


@pytest.mark.parametrize("payload", [None, {"nftables": [None]}, {"nftables": [{"set": {}}]}])
def test_unknown_kernel_objects_cannot_be_guard_proof(payload):
    with pytest.raises(vpn.VPNError):
        vpn_guard._normalized(payload)


def test_guard_kernel_metadata_does_not_mask_device_replacement(monkeypatch):
    obj = {"nftables": [{"metainfo": {}}, {"rule": {"handle": 1, "expr": [vpn_guard._meta("oif", "wg0")]}}]}
    monkeypatch.setattr(vpn_guard.socket, "if_nametoindex", lambda name: 9)
    result = vpn_guard._normalized(copy.deepcopy(obj))
    assert result[0]["rule"]["expr"][0]["match"]["right"] == 9

    def disappeared(name):
        raise OSError()

    monkeypatch.setattr(vpn_guard.socket, "if_nametoindex", disappeared)
    with pytest.raises(vpn.VPNError):
        vpn_guard._normalized(obj)


@pytest.mark.parametrize(
    "status,output,expected",
    [
        (0, '{"nftables": []}', False),
        (0, '{"nftables": [{"table":{"family":"inet","name":"ttp_vpn"}}]}', True),
        (1, "", None),
        (0, "invalid", None),
    ],
)
def test_guard_presence_requires_successful_kernel_inspection(monkeypatch, status, output, expected):
    monkeypatch.setattr(vpn_guard, "_nft", lambda *a, **k: subprocess.CompletedProcess([], status, output, ""))
    if expected is None:
        with pytest.raises(vpn.VPNError):
            vpn_guard._table_exists()
    else:
        assert vpn_guard._table_exists() is expected


@pytest.mark.parametrize("failure", [False, True])
def test_nft_boundary_uses_trusted_binary_and_json(monkeypatch, failure):
    monkeypatch.setattr(vpn_guard, "resolve", lambda name: "/trusted/" + name)

    def run(argv, **kwargs):
        assert argv[0] == "/trusted/nft" and kwargs["timeout"] == 2
        if failure:
            raise OSError()
        assert json.loads(kwargs["input"]) == {"nftables": []}
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(vpn_guard.subprocess, "run", run)
    if failure:
        with pytest.raises(vpn.VPNError):
            vpn_guard._nft("-j", payload={"nftables": []})
    else:
        assert vpn_guard._nft("-j", payload={"nftables": []}).returncode == 0


@pytest.mark.parametrize("fault", ["none", "stop_timeout", "guard_stuck", "concurrent"])
def test_guard_recovery_releases_only_after_verified_stop(tmp_path, monkeypatch, fault):
    intent = tmp_path / "intent"
    monkeypatch.setattr(vpn_guard, "INTENT", intent)
    exists = [False]
    monkeypatch.setattr(vpn_guard, "_table_exists", lambda: exists[0])

    def nft(*args, payload=None):
        if args[-1] == "-":
            exists[0] = True
        elif args[0] == "delete" and fault != "guard_stuck":
            exists[0] = False
        output = json.dumps({"nftables": vpn_guard.specification(policy(), 100)})
        return subprocess.CompletedProcess([], 0, output, "")

    monkeypatch.setattr(vpn_guard, "_nft", nft)
    if fault == "concurrent":

        def link(*args):
            raise FileExistsError()

        monkeypatch.setattr(vpn_guard.os, "link", link)
        with pytest.raises(vpn.VPNError, match="Concurrent"):
            vpn_guard.install(policy(), 100)
        return
    vpn_guard.install(policy(), 100)
    assert intent.exists() and exists[0]
    monkeypatch.setattr(vpn_guard, "resolve", lambda name: name)

    def stopped(*args, **kw):
        if fault == "stop_timeout":
            raise subprocess.TimeoutExpired("systemctl", 5)
        return subprocess.CompletedProcess([], 0, "ActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n", "")

    monkeypatch.setattr(vpn_guard.subprocess, "run", stopped)
    if fault != "none":
        with pytest.raises(vpn.VPNError):
            vpn_guard.release_after_stop()
        assert intent.exists()
    else:
        vpn_guard.release_after_stop()
        assert not exists[0] and not intent.exists()
        vpn_guard.release_after_stop()


def test_guard_rejects_root_tor_and_invalid_kernel_json(monkeypatch):
    with pytest.raises(vpn.VPNError):
        vpn_guard.specification(policy(), 0)
    monkeypatch.setattr(vpn_guard, "_nft", lambda *a: subprocess.CompletedProcess([], 0, "not json", ""))
    with pytest.raises(vpn.VPNError):
        vpn_guard.verify(policy(), 100)


@pytest.mark.parametrize(
    "group,events,allowed",
    [
        (None, "", False),
        ("relative", "", False),
        ("/system.slice/ttp-tor.service", "populated 1\n", False),
        ("/system.slice/ttp-tor.service", "populated 0\n", True),
        ("/system.slice/ttp-tor.service", FileNotFoundError(), True),
        ("/system.slice/ttp-tor.service", PermissionError(), False),
    ],
)
def test_no_live_descendants_can_outlast_guard_removal(tmp_path, monkeypatch, group, events, allowed):
    from pathlib import Path

    intent = tmp_path / "intent"
    intent.write_text("{}")
    monkeypatch.setattr(vpn_guard, "INTENT", intent)
    monkeypatch.setattr(vpn_guard, "resolve", lambda name: name)
    body = "ActiveState=inactive\nMainPID=0\nControlPID=0\n"
    if group is not None:
        body += f"ControlGroup={group}\n"
    monkeypatch.setattr(vpn_guard.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, body, ""))
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path.name == "cgroup.events":
            if isinstance(events, Exception):
                raise events
            return events
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(vpn_guard, "_nft", lambda *a: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(vpn_guard, "_table_exists", lambda: False)
    if allowed:
        vpn_guard.release_after_stop()
    else:
        with pytest.raises(vpn.VPNError):
            vpn_guard.release_after_stop()
    assert intent.exists() is (not allowed)


def test_no_external_probe_while_startup_recovery_is_pending(tmp_path, monkeypatch):
    from ttp.evidence import VerificationState
    from ttp.session_report import check_session

    intent = tmp_path / "intent"
    intent.write_text("{}")
    monkeypatch.setattr(vpn_guard, "INTENT", intent)
    monkeypatch.setattr("ttp.state.read_lock", lambda **kw: None)
    with patch("ttp.probe.verify_session") as probe:
        verification, result = check_session()
    assert verification.state is VerificationState.NOT_RUN and result.exit_code == 10
    probe.assert_not_called()


@pytest.mark.parametrize("phase", ["running", "protection_retained"])
def test_status_displays_vpn_guard_without_claiming_remote_liveness(monkeypatch, phase):
    report = {
        "phase": phase,
        "health": "unknown",
        "transport_port": 9041,
        "dns_port": 9054,
        "lan_bypass": False,
        "allow_root": False,
        "ipv6": "disabled",
        "rejected_packets": None,
        "watchdog_requested": True,
        "watchdog": {"value": "unknown"},
        "vpn": {"state": "unknown", "guard_verified": True},
        "verification": {"state": "confirmed", "age_seconds": 3600},
        "emergency": {"requested": False, "applied": None, "verified": None},
        "started": "earlier",
        "notifications": {"state": "disabled"},
        "diagnostics": [{"reason": "vpn.test", "message": "Unavailable"}],
    }
    monkeypatch.setattr("ttp.session_report.observe_session", lambda: report)
    with patch("ttp.cli._setup_logging"):
        result = CliRunner().invoke(app, ["status"])
    assert result.exit_code == 0
    if phase == "running":
        assert "Required VPN: unknown" in result.output and "verified: True" in result.output
        assert "vpn.test" in result.output
    else:
        assert "restore-only" in result.output


def test_main_firewall_allows_only_specific_vpn_transport_and_disables_cgroup_bypass(monkeypatch):
    from ttp.firewall import runner

    scripts = []
    monkeypatch.setattr(runner, "_apply_table_atomically", scripts.append)
    monkeypatch.setattr("ttp.tor_detect.is_ipv6_supported", lambda: True)

    def no_account(user):
        raise KeyError(user)

    monkeypatch.setattr(runner.pwd, "getpwnam", no_account)

    def forbidden_probe():
        raise AssertionError("Must not enable cgroup bypass in VPN mode")

    monkeypatch.setattr(runner, "_has_cgroup_bypass_support", forbidden_probe)
    runner.apply_rules("100", vpn=policy().snapshot(), lan_bypass=False, disable_ipv6=True)
    assert len(scripts) == 1
    assert "meta mark 51820 ip daddr 192.0.2.1 udp dport 51820 accept" in scripts[0]
    assert "ttp-bypass.slice" not in scripts[0]
