"""Tests for ttp.firewall - Stateless nftables management.

All tests mock subprocess.run so no real firewall rules are ever touched.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock
from ttp.firewall import apply_rules, destroy_rules
from ttp.exceptions import FirewallError

# apply_rules


@patch("ttp.firewall.RULES_TEMP_PATH")
@patch("ttp.firewall.LOCK_DIR")
@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall.subprocess.run")
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


@patch("ttp.firewall.RULES_TEMP_PATH")
@patch("ttp.firewall.LOCK_DIR")
@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall.subprocess.run")
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
        MagicMock(returncode=0),  # destroy (rollback)
    ]

    try:
        apply_rules(tor_user="debian-tor")
    except FirewallError:
        pass

    # Check that destroy was called
    assert any("destroy" in str(c) for c in mock_run.call_args_list)


@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall._run_nft_string")
@patch("ttp.firewall._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_logic_content(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify the generated ruleset string contains critical safety rules in order."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor")

    # Capture the ruleset string passed to _run_nft_string
    ruleset = mock_run_string.call_args[0][0]

    # 1. Check for the Kill-Switch chain
    assert "chain filter_out" in ruleset

    # 2. Check for UID exemptions in the NAT output chain (Order is critical)
    output_block = ruleset.split("chain output")[1].split("chain filter_out")[0]
    # Tor exemption must be first
    assert "meta skuid 110 accept" in output_block
    assert output_block.find("meta skuid 110 accept") < output_block.find("dnat")

    # 3. Check for exemptions in the filter_out chain
    filter_block = ruleset.split("chain filter_out")[1]
    assert "meta skuid 110 accept" in filter_block
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


@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall._run_nft_string")
@patch("ttp.firewall._run_nft")
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


@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall._run_nft_string")
@patch("ttp.firewall._run_nft")
@patch("ttp.tor_detect.is_ipv6_supported", return_value=False)
def test_ruleset_allow_root(mock_ipv6, mock_run_nft, mock_run_string, mock_pwd):
    """Verify that allow_root=True injects meta skuid 0 accept in filter_out."""
    mock_pwd.return_value = MagicMock(pw_uid=110)
    apply_rules(tor_user="debian-tor", allow_root=True)

    ruleset = mock_run_string.call_args[0][0]
    filter_block = ruleset.split("chain filter_out")[1]
    assert "meta skuid 0 accept" in filter_block


@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall._run_nft_string")
@patch("ttp.firewall._run_nft")
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


@patch("ttp.firewall.pwd.getpwnam")
@patch("ttp.firewall._run_nft_string")
@patch("ttp.firewall._run_nft")
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


@patch("ttp.firewall.RULES_TEMP_PATH")
@patch("ttp.firewall.subprocess.run")
def test_destroy_rules(mock_run, mock_rules_path):
    """destroy_rules calls 'nft destroy table inet ttp'."""
    mock_run.return_value = MagicMock(returncode=0)

    destroy_rules()

    # Called once for nft destroy (unlink is on a mock Path object)
    assert any("destroy" in str(c) for c in mock_run.call_args_list)
    mock_rules_path.unlink.assert_called_once_with(missing_ok=True)


@patch("ttp.firewall.subprocess.run")
def test_destroy_rules_idempotent(mock_run):
    """destroy_rules does not raise if nft returns non-zero (table missing)."""
    mock_run.return_value = MagicMock(returncode=1, stderr="Error: No such file")

    # Should not raise exception
    destroy_rules()
    assert mock_run.called
