# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tests for ttp.firewall - Stateless nftables management.

All tests mock subprocess.run so no real firewall rules are ever touched.
"""

from __future__ import annotations

import pytest
import subprocess
from unittest.mock import patch, MagicMock
from ttp.firewall import apply_rules, destroy_rules
from ttp.exceptions import FirewallError


@pytest.fixture(autouse=True)
def mock_cgroup_support():
    with (
        patch("ttp.firewall.runner._has_cgroup_bypass_support", return_value=True),
        patch("ttp.firewall.builder._has_cgroup_bypass_support", return_value=True),
    ):
        yield


# apply_rules


@patch("ttp.firewall.runner.RULES_TEMP_PATH")
@patch("ttp.firewall.runner.LOCK_DIR")
@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner.subprocess.run")
def test_apply_rules_orchestration(mock_run, mock_pwd, mock_lock_dir, mock_rules_path):
    """apply_rules must create, flush and then inject the ruleset."""
    mock_run.return_value = MagicMock(returncode=0)
    mock_pwd.return_value = MagicMock(pw_uid=123)

    apply_rules(tor_user="debian-tor")

    # Check sequence: add table -> flush table -> inject ruleset (nft -f <temp_file>)
    calls = mock_run.call_args_list
    assert ["nft", "add", "table", "inet", "ttp"] in [c.args[0] for c in calls]
    assert ["nft", "flush", "table", "inet", "ttp"] in [c.args[0] for c in calls]

    # Check nft -f call
    nft_f_call = [c.args[0] for c in calls if "-f" in str(c.args[0])]
    assert len(nft_f_call) == 1
    assert nft_f_call[0][0] == "nft"
    assert nft_f_call[0][1] == "-f"


@patch("ttp.firewall.runner.RULES_TEMP_PATH")
@patch("ttp.firewall.runner.LOCK_DIR")
@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner.subprocess.run")
def test_apply_rules_failure_triggers_destroy(
    mock_run, mock_pwd, mock_lock_dir, mock_rules_path
):
    """If rule injection fails, it must attempt to destroy the table."""
    mock_pwd.return_value = MagicMock(pw_uid=123)
    # First two calls (add/flush) succeed, third call (inject) fails
    mock_run.side_effect = [
        MagicMock(returncode=0),  # add
        MagicMock(returncode=0),  # flush
        subprocess.CalledProcessError(1, "nft", stderr="syntax error"),  # inject
        MagicMock(returncode=0),  # destroy: flush (rollback)
        MagicMock(returncode=0),  # destroy: destroy (rollback)
    ]

    try:
        apply_rules(tor_user="debian-tor")
    except FirewallError:
        pass

    # Check that destroy was called
    assert any("destroy" in str(c) for c in mock_run.call_args_list)


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_logic_content(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify the generated ruleset string contains critical safety rules in order."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor")

    # Capture the ruleset string passed to _run_nft_string
    ruleset = mock_run_string.call_args[0][0]

    # 1. Check for the Kill-Switch and forwarding filter chains
    assert "chain filter_out" in ruleset
    assert "chain filter_forward" in ruleset

    # 2. Check for UID exemptions in the NAT output chain (Order is critical)
    output_block = ruleset.split("chain output")[1].split("chain filter_out")[0]
    # Tor exemption must be first
    assert "meta skuid 110 accept" in output_block
    assert output_block.find("meta skuid 110 accept") < output_block.find("dnat")
    # Verify cgroups level 1 bypass rule
    assert 'socket cgroupv2 level 1 "ttp-bypass.slice" accept' in output_block

    # 3. Check for exemptions in the filter_out chain
    filter_block = ruleset.split("chain filter_out")[1].split("chain filter_forward")[0]
    assert "meta skuid 110 accept" in filter_block
    assert 'socket cgroupv2 level 1 "ttp-bypass.slice" accept' in filter_block
    # By default, root is NOT exempted (allow_root=False)
    assert "meta skuid 0 accept" not in filter_block
    assert "ip daddr 127.0.0.0/8 accept" in filter_block

    # Default LAN bypass should be present
    lan_bypass_rule = (
        "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"
    )
    assert lan_bypass_rule in output_block
    assert lan_bypass_rule in filter_block

    # DoT leak prevention must be present
    assert "tcp dport 853 reject" in filter_block

    # DoH leak prevention must be present (IPv4)
    assert (
        "ip daddr { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222, 208.67.220.220 } tcp dport 443 reject"
        in filter_block
    )

    # 4. DNAT targets match shifted TTP ports (9041 TransPort, 9054 DNSPort)
    assert "127.0.0.1:9041" in ruleset
    assert "127.0.0.1:9054" in ruleset

    # 5. DNS redirect MUST appear before LAN bypass in the output chain.
    #    Browsers often use the LAN gateway (e.g. 192.168.1.1) as DNS resolver.
    #    If LAN bypass came first, those queries would escape to the real ISP.
    dns_pos = output_block.find("dnat ip to 127.0.0.1:9054")
    lan_pos = output_block.find(lan_bypass_rule)
    assert dns_pos != -1, "DNS redirect rule not found in output chain"
    assert lan_pos != -1, "LAN bypass rule not found in output chain"
    assert dns_pos < lan_pos, (
        "DNS redirect must appear BEFORE LAN bypass in the output chain "
        "(LAN gateway DNS queries would otherwise bypass Tor)"
    )

    # 6. Check for IPv6 drop and final reject
    assert "meta nfproto ipv6 drop" in filter_block
    assert "reject" in filter_block
    # Reject must be the last rule
    clean_filter = filter_block.strip()
    while clean_filter.endswith("}"):
        clean_filter = clean_filter[:-1].strip()
    assert clean_filter.endswith("reject")


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_ruleset_logic_content_ipv6(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify the generated ruleset string contains IPv6 redirection rules."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor")

    # Capture the ruleset string passed to _run_nft_string
    ruleset = mock_run_string.call_args[0][0]

    # 1. Check loopback IPv6
    assert "ip6 daddr ::1 accept" in ruleset

    # 2. Check LAN bypass IPv6
    assert "ip6 daddr { fc00::/7, fe80::/10 } accept" in ruleset

    # 3. Check redirection targets
    assert "udp dport 53 dnat ip6 to [::1]:9054" in ruleset
    assert "meta l4proto tcp dnat ip6 to [::1]:9041" in ruleset

    # 4. Ensure IPv6 is NOT dropped in filter_out
    assert "meta nfproto ipv6 drop" not in ruleset

    # 5. Check DoH IPv6 block
    assert (
        "ip6 daddr { 2606:4700:4700::1111, 2606:4700:4700::1001, 2001:4860:4860::8888, 2001:4860:4860::8844, 2620:fe::fe, 2620:fe::9, 2620:0:ccc::2, 2620:0:ccd::2 } tcp dport 443 reject"
        in ruleset
    )


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_allow_root(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify that allow_root=True injects meta skuid 0 accept in filter_out."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor", allow_root=True)

    ruleset = mock_run_string.call_args[0][0]
    filter_block = ruleset.split("chain filter_out")[1]
    assert "meta skuid 0 accept" in filter_block


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_no_lan_bypass(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify that lan_bypass=False removes local subnet exemptions."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor", lan_bypass=False)

    ruleset = mock_run_string.call_args[0][0]
    lan_bypass_rule = (
        "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"
    )
    assert lan_bypass_rule not in ruleset


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_custom_ports(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify that custom ports are correctly injected in the ruleset."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor", transport_port=9060, dns_port=9070)

    # Capture the ruleset string passed to _run_nft_string
    ruleset = mock_run_string.call_args[0][0]

    # Verify our custom ports are used
    assert "127.0.0.1:9060" in ruleset
    assert "127.0.0.1:9070" in ruleset
    assert "127.0.0.1:9041" not in ruleset
    assert "127.0.0.1:9054" not in ruleset


# destroy_rules


@patch("ttp.firewall.runner.RULES_TEMP_PATH")
@patch("ttp.firewall.runner.subprocess.run")
def test_destroy_rules(mock_run, mock_rules_path):
    """destroy_rules calls 'nft flush' and then 'nft destroy table inet ttp'."""
    mock_run.return_value = MagicMock(returncode=0)

    destroy_rules()

    # Verify both flush and destroy are called
    calls = [c.args[0] for c in mock_run.call_args_list]
    assert ["nft", "flush", "table", "inet", "ttp"] in calls
    assert ["nft", "destroy", "table", "inet", "ttp"] in calls
    mock_rules_path.unlink.assert_called_once_with(missing_ok=True)


@patch("ttp.firewall.runner.subprocess.run")
def test_destroy_rules_idempotent(mock_run):
    """destroy_rules does not raise if nft returns non-zero (table missing)."""
    mock_run.return_value = MagicMock(returncode=1, stderr="Error: No such file")

    # Should not raise exception
    destroy_rules()
    assert mock_run.called


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_bypass_rules(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify that generating rules with bypass_uids and bypass_gids adds skuid/skgid rules."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(
        tor_user="debian-tor",
        bypass_uids=[1001, 1002],
        bypass_gids=[2001],
    )

    ruleset = mock_run_string.call_args[0][0]

    # Verify output chain contains bypass rules
    output_block = ruleset.split("chain output")[1].split("chain filter_out")[0]
    assert "meta skuid 1001 ip daddr != 127.0.0.1 accept" in output_block
    assert "meta skuid 1002 ip daddr != 127.0.0.1 accept" in output_block
    assert "meta skgid 2001 ip daddr != 127.0.0.1 accept" in output_block

    # Verify filter_out chain contains bypass rules
    filter_block = ruleset.split("chain filter_out")[1]
    assert "meta skuid 1001 accept" in filter_block
    assert "meta skuid 1002 accept" in filter_block
    assert "meta skgid 2001 accept" in filter_block


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_ruleset_logic_disable_ipv6(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify that disable_ipv6=True drops all IPv6 and avoids IPv6 redirects even if system supports it."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor", disable_ipv6=True)

    # Capture the ruleset string passed to _run_nft_string
    ruleset = mock_run_string.call_args[0][0]

    # Ensure IPv6 is dropped in filter_out
    assert "meta nfproto ipv6 drop" in ruleset
    # Ensure no IPv6 redirect
    assert "udp dport 53 dnat ip6 to" not in ruleset
    assert "meta l4proto tcp dnat ip6 to" not in ruleset
    # Ensure no IPv6 LAN bypass
    assert "ip6 daddr { fc00::/7, fe80::/10 } accept" not in ruleset


@patch("ttp.firewall.emergency._run_nft")
def test_apply_teardown_lockdown(mock_run_nft):
    """Verify that apply_teardown_lockdown constructs and executes the correct nft command."""
    from ttp.firewall import apply_teardown_lockdown

    # Test with a specific UID
    apply_teardown_lockdown(123)
    mock_run_nft.assert_called_once_with(
        [
            "insert",
            "rule",
            "inet",
            "ttp",
            "filter_out",
            "meta",
            "skuid",
            "!=",
            "123",
            "oifname",
            "!=",
            "lo",
            "drop",
        ]
    )

    mock_run_nft.reset_mock()

    # Test with None (no UID)
    apply_teardown_lockdown(None)
    mock_run_nft.assert_called_once_with(
        [
            "insert",
            "rule",
            "inet",
            "ttp",
            "filter_out",
            "oifname",
            "!=",
            "lo",
            "drop",
        ]
    )


@patch("ttp.firewall.emergency._run_nft")
def test_apply_active_socket_slaughter(mock_run_nft):
    """Verify that apply_active_socket_slaughter constructs and executes the correct nft reject rules."""
    from ttp.firewall import apply_active_socket_slaughter

    apply_active_socket_slaughter()

    assert mock_run_nft.call_count == 2
    calls = mock_run_nft.call_args_list
    assert calls[0].args[0] == [
        "insert",
        "rule",
        "inet",
        "ttp",
        "filter_out",
        "meta",
        "l4proto",
        "udp",
        "counter",
        "reject",
    ]
    assert calls[1].args[0] == [
        "insert",
        "rule",
        "inet",
        "ttp",
        "filter_out",
        "meta",
        "l4proto",
        "tcp",
        "counter",
        "reject",
        "with",
        "tcp",
        "reset",
    ]


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_ruleset_systemd_resolved_rules(
    mock_ipv6, mock_run_nft, mock_run_string, mock_pwd
):
    """Verify that systemd-resolved drop rules are injected when the system user exists."""

    def mock_getpwnam(name):
        mock_user = MagicMock()
        if name == "debian-tor":
            mock_user.pw_uid = 110
        elif name == "systemd-resolve":
            mock_user.pw_uid = 105
        else:
            raise KeyError("User not found")
        return mock_user

    mock_pwd.side_effect = mock_getpwnam

    # 1. Test with IPv6 active
    apply_rules(tor_user="debian-tor", disable_ipv6=False)
    ruleset = mock_run_string.call_args[0][0]

    assert "meta skuid 105 ip daddr != 127.0.0.1 drop" in ruleset
    assert "meta skuid 105 ip6 daddr != ::1 drop" in ruleset

    # 2. Test with IPv6 disabled
    apply_rules(tor_user="debian-tor", disable_ipv6=True)
    ruleset_no_ipv6 = mock_run_string.call_args[0][0]

    assert "meta skuid 105 ip daddr != 127.0.0.1 drop" in ruleset_no_ipv6
    assert "meta skuid 105 ip6 daddr != ::1 drop" not in ruleset_no_ipv6


@patch("ttp.firewall.runner.pwd.getpwnam")
@patch("ttp.firewall.runner._run_nft_string")
@patch("ttp.firewall.runner._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=True)
def test_ruleset_systemd_resolved_rules_missing_user(
    mock_ipv6, mock_run_nft, mock_run_string, mock_pwd
):
    """Verify that systemd-resolved drop rules are NOT injected if the user does not exist on the system."""

    def mock_getpwnam(name):
        if name == "debian-tor":
            mock_user = MagicMock()
            mock_user.pw_uid = 110
            return mock_user
        raise KeyError("User not found")

    mock_pwd.side_effect = mock_getpwnam

    apply_rules(tor_user="debian-tor")
    ruleset = mock_run_string.call_args[0][0]

    assert "meta skuid 105" not in ruleset


# ---------------------------------------------------------------------------
# _build_ruleset — pure function tests (no subprocess, no root required)
# ---------------------------------------------------------------------------


from ttp.firewall import _build_ruleset  # noqa: E402


def _base_kwargs(**overrides) -> dict:
    """Return a baseline set of arguments for _build_ruleset."""
    defaults = dict(
        tor_uid=1000,
        transport_port=9041,
        dns_port=9054,
        ipv6_avail=False,
        allow_root=False,
        lan_bypass=True,
        bypass_uids=None,
        bypass_gids=None,
        resolved_uid=None,
        cgroup_bypass=False,
    )
    defaults.update(overrides)
    return defaults


class TestBuildRuleset:
    """Verify _build_ruleset() returns correct nftables rule strings."""

    def test_returns_string(self):
        result = _build_ruleset(**_base_kwargs())
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_ttp_table(self):
        result = _build_ruleset(**_base_kwargs())
        assert "table inet ttp" in result

    def test_tor_uid_exempt(self):
        result = _build_ruleset(**_base_kwargs(tor_uid=555))
        assert "meta skuid 555 accept" in result

    def test_transport_port_in_redirect(self):
        result = _build_ruleset(**_base_kwargs(transport_port=19041))
        assert "127.0.0.1:19041" in result

    def test_dns_port_in_redirect(self):
        result = _build_ruleset(**_base_kwargs(dns_port=19054))
        assert "127.0.0.1:19054" in result

    def test_ipv4_only_no_ipv6_rules(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=False))
        assert "::1" not in result
        assert "ip6" not in result

    def test_ipv6_avail_adds_ipv6_rules(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=True))
        assert "ip6" in result
        assert "::1" in result

    def test_ipv6_leak_prevention_when_disabled(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=False))
        assert "meta nfproto ipv6 drop" in result

    def test_no_ipv6_leak_prevention_when_enabled(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=True))
        assert "meta nfproto ipv6 drop" not in result

    def test_allow_root_adds_root_rule(self):
        result = _build_ruleset(**_base_kwargs(allow_root=True))
        assert "meta skuid 0 accept" in result

    def test_disallow_root_no_root_rule(self):
        result = _build_ruleset(**_base_kwargs(allow_root=False))
        assert "meta skuid 0 accept" not in result

    def test_lan_bypass_adds_rfc1918_rules(self):
        result = _build_ruleset(**_base_kwargs(lan_bypass=True))
        assert "10.0.0.0/8" in result
        assert "192.168.0.0/16" in result

    def test_no_lan_bypass_omits_rfc1918_rules(self):
        result = _build_ruleset(**_base_kwargs(lan_bypass=False))
        assert "10.0.0.0/8" not in result
        assert "192.168.0.0/16" not in result

    def test_bypass_uid_nat_and_filter(self):
        result = _build_ruleset(**_base_kwargs(bypass_uids=[1001, 1002]))
        assert "meta skuid 1001 ip daddr != 127.0.0.1 accept" in result
        assert "meta skuid 1002 ip daddr != 127.0.0.1 accept" in result
        assert "meta skuid 1001 accept" in result

    def test_bypass_gid_nat_and_filter(self):
        result = _build_ruleset(**_base_kwargs(bypass_gids=[2001]))
        assert "meta skgid 2001 ip daddr != 127.0.0.1 accept" in result
        assert "meta skgid 2001 accept" in result

    def test_bypass_uid_ipv6_rules_when_ipv6_enabled(self):
        result = _build_ruleset(**_base_kwargs(bypass_uids=[1001], ipv6_avail=True))
        assert "meta skuid 1001 ip6 daddr != ::1 accept" in result

    def test_no_bypass_uid_ipv6_rules_when_ipv6_disabled(self):
        result = _build_ruleset(**_base_kwargs(bypass_uids=[1001], ipv6_avail=False))
        assert "meta skuid 1001 ip6 daddr != ::1 accept" not in result

    def test_cgroup_bypass_rule_present(self):
        result = _build_ruleset(**_base_kwargs(cgroup_bypass=True))
        assert 'socket cgroupv2 level 1 "ttp-bypass.slice" accept' in result

    def test_no_cgroup_bypass_rule_absent(self):
        result = _build_ruleset(**_base_kwargs(cgroup_bypass=False))
        assert "ttp-bypass.slice" not in result

    def test_resolved_uid_drop_rule(self):
        result = _build_ruleset(**_base_kwargs(resolved_uid=999))
        assert "meta skuid 999 ip daddr != 127.0.0.1 drop" in result

    def test_no_resolved_uid_no_drop_rule(self):
        result = _build_ruleset(**_base_kwargs(resolved_uid=None))
        # No resolved drop rule should appear (there is no uid to reference)
        assert "ip daddr != 127.0.0.1 drop" not in result

    def test_doh_reject_ipv4_always_present(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=False))
        assert "1.1.1.1" in result
        assert "8.8.8.8" in result
        assert "tcp dport 443 reject" in result

    def test_doh_reject_ipv6_present_when_ipv6_enabled(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=True))
        assert "2606:4700:4700::1111" in result

    def test_doh_reject_ipv6_absent_when_ipv6_disabled(self):
        result = _build_ruleset(**_base_kwargs(ipv6_avail=False))
        assert "2606:4700:4700::1111" not in result

    def test_dot_reject_always_present(self):
        result = _build_ruleset(**_base_kwargs())
        assert "tcp dport 853 reject" in result

    def test_catchall_reject_present(self):
        result = _build_ruleset(**_base_kwargs())
        # The catch-all reject must appear in filter_out, before filter_forward
        filter_out_idx = result.index("chain filter_out")
        filter_forward_idx = result.index("chain filter_forward")
        filter_out_block = result[filter_out_idx:filter_forward_idx]
        assert "reject" in filter_out_block

    def test_filter_forward_policy_drop(self):
        result = _build_ruleset(**_base_kwargs())
        assert "filter_forward" in result
        assert "policy drop" in result

    def test_prerouting_chain_present(self):
        result = _build_ruleset(**_base_kwargs())
        assert "chain prerouting" in result
        assert "hook prerouting" in result

    def test_nat_output_chain_present(self):
        result = _build_ruleset(**_base_kwargs())
        assert "chain output" in result
        assert "hook output" in result

    def test_pure_function_idempotent(self):
        """Same inputs must always produce identical output."""
        kwargs = _base_kwargs(
            tor_uid=42, bypass_uids=[100], bypass_gids=[200], ipv6_avail=True
        )
        assert _build_ruleset(**kwargs) == _build_ruleset(**kwargs)
