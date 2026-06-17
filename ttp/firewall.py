"""Stateless Firewall Module - Isolation via dedicated nftables tables.

This module implements a "Safe-Release" architecture:
1. No system backups are performed (Stateless).
2. All rules are isolated in the 'inet ttp' table.
3. Cleanup is atomic: 'nft destroy table inet ttp'.
"""

import subprocess
import logging
import pwd
from ttp.exceptions import FirewallError
from ttp.state import LOCK_DIR

logger = logging.getLogger("ttp")

# Path to the temporary ruleset file for better debugging (line numbers)
RULES_TEMP_PATH = LOCK_DIR / "ttp.rules"


def apply_rules(
    tor_user: str,
    transport_port: int = 9041,
    dns_port: int = 9054,
    allow_root: bool = False,
    lan_bypass: bool = True,
    bypass_uids: list[int] | None = None,
    bypass_gids: list[int] | None = None,
) -> None:
    """Create the 'ttp' table and inject redirection rules.

    Orchestrates the process: Create -> Flush -> Inject.
    If any step fails, it triggers an automatic rollback (destruction).
    """
    # Resolve numeric UID for the tor user to avoid nft resolution issues
    try:
        tor_uid = pwd.getpwnam(tor_user).pw_uid
    except KeyError as e:
        raise FirewallError(f"Tor user '{tor_user}' not found on system.") from e

    # Construct dynamic rules based on options
    from ttp.tor_detect import is_ipv6_supported

    ipv6_avail = is_ipv6_supported()

    lan_rule = ""
    lan6_rule = ""
    if lan_bypass:
        lan_rule = "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"
        if ipv6_avail:
            lan6_rule = "ip6 daddr { fc00::/7, fe80::/10 } accept"

    root_rule = ""
    if allow_root:
        root_rule = "meta skuid 0 accept"

    # Construct bypass rules
    bypass_rules_nat = []
    bypass_rules_filter = []
    if bypass_uids:
        for uid in bypass_uids:
            bypass_rules_nat.append(f"meta skuid {uid} ip daddr != 127.0.0.1 accept")
            if ipv6_avail:
                bypass_rules_nat.append(f"meta skuid {uid} ip6 daddr != ::1 accept")
            bypass_rules_filter.append(f"meta skuid {uid} accept")
    if bypass_gids:
        for gid in bypass_gids:
            bypass_rules_nat.append(f"meta skgid {gid} ip daddr != 127.0.0.1 accept")
            if ipv6_avail:
                bypass_rules_nat.append(f"meta skgid {gid} ip6 daddr != ::1 accept")
            bypass_rules_filter.append(f"meta skgid {gid} accept")
    bypass_rules_nat_str = (
        "\n                ".join(bypass_rules_nat) if bypass_rules_nat else ""
    )
    bypass_rules_filter_str = (
        "\n                ".join(bypass_rules_filter) if bypass_rules_filter else ""
    )

    # Local loopback checks
    loopback_ipv4 = "ip daddr 127.0.0.0/8 accept"
    loopback_ipv6 = "ip6 daddr ::1 accept" if ipv6_avail else ""

    # Redirection rules
    dns_redirect_ipv4 = f"udp dport 53 dnat ip to 127.0.0.1:{dns_port}\n                tcp dport 53 dnat ip to 127.0.0.1:{dns_port}"
    dns_redirect_ipv6 = (
        f"\n                udp dport 53 dnat ip6 to [::1]:{dns_port}\n                tcp dport 53 dnat ip6 to [::1]:{dns_port}"
        if ipv6_avail
        else ""
    )

    tcp_redirect_ipv4 = f"ip protocol tcp dnat ip to 127.0.0.1:{transport_port}"
    tcp_redirect_ipv6 = (
        f"\n                meta l4proto tcp dnat ip6 to [::1]:{transport_port}"
        if ipv6_avail
        else ""
    )

    ipv6_leak_prevention = "" if ipv6_avail else "meta nfproto ipv6 drop"

    # DoH IP blocks
    doh_ips_v4 = "{ 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222, 208.67.220.220 }"
    doh_reject_ipv4 = f"ip daddr {doh_ips_v4} tcp dport 443 reject"

    doh_reject_ipv6 = ""
    if ipv6_avail:
        doh_ips_v6 = "{ 2606:4700:4700::1111, 2606:4700:4700::1001, 2001:4860:4860::8888, 2001:4860:4860::8844, 2620:fe::fe, 2620:fe::9, 2620:0:ccc::2, 2620:0:ccd::2 }"
        doh_reject_ipv6 = f"ip6 daddr {doh_ips_v6} tcp dport 443 reject"

    # Define the ruleset using a single atomic string.
    ruleset = f"""
    table inet ttp {{
        chain prerouting {{
            # Handle incoming traffic from other interfaces (e.g., if used as a gateway)
            type nat hook prerouting priority dstnat; policy accept;
            # DNS MUST be redirected before LAN bypass
            {dns_redirect_ipv4}
            {dns_redirect_ipv6}
            {lan_rule}
            {lan6_rule}
            {tcp_redirect_ipv4}
            {tcp_redirect_ipv6}
        }}

        chain output {{
            type nat hook output priority -150; policy accept;

            # 1. Tor user EXEMPTION: Allow the Tor daemon to reach the real internet
            meta skuid {tor_uid} accept

            # 1b. Bypass users and groups
            {bypass_rules_nat_str}

            # 2. DNS Redirection: MUST come before LAN bypass.
            {dns_redirect_ipv4}
            {dns_redirect_ipv6}

            # 3. LAN Bypass: Allow local subnet communication (non-DNS)
            {lan_rule}
            {lan6_rule}

            # 4. Local Exemption: Allow traffic to localhost
            {loopback_ipv4}
            {loopback_ipv6}

            # 5. TCP Redirection: Redirect all remaining TCP traffic to Tor's TransPort
            {tcp_redirect_ipv4}
            {tcp_redirect_ipv6}
        }}

        chain filter_out {{
            type filter hook output priority filter; policy accept;

            # 1. Allow the Tor daemon
            meta skuid {tor_uid} accept

            # 1b. Bypass users and groups
            {bypass_rules_filter_str}

            # 2. Allow root processes (system maintenance, Tor bootstrapping) if explicitly allowed
            {root_rule}

            # 3. LAN Bypass: Allow local subnet communication
            {lan_rule}
            {lan6_rule}

            # 4. Allow traffic to localhost
            {loopback_ipv4}
            {loopback_ipv6}

            # 5. DoT (DNS-over-TLS) Leak Prevention: Block direct connections to port 853
            tcp dport 853 reject

            # 6. DoH (DNS-over-HTTPS) Leak Prevention: Block common public DoH resolvers on port 443
            {doh_reject_ipv4}
            {doh_reject_ipv6}

            # 7. IPv6 Leak Prevention
            {ipv6_leak_prevention}

            # 7. Brutal Reject: Kill any cleartext traffic that bypassed NAT (e.g., pre-existing connections)
            reject
        }}
    }}
    """

    try:
        # 1. Create and sanitize the dedicated table
        _run_nft(["add", "table", "inet", "ttp"])
        _run_nft(["flush", "table", "inet", "ttp"])
        _run_nft_string(ruleset)
        logger.info(
            f"Stateless rules applied. Tor user ({tor_user}, UID {tor_uid}) is exempt."
        )
    except Exception as e:
        logger.error(f"Firewall injection failed: {e}. Rolling back...")
        destroy_rules()
        if not isinstance(e, FirewallError):
            raise FirewallError(f"Failed to apply stateless rules: {e}") from e
        raise


def apply_emergency_killswitch() -> None:
    """Apply an emergency lock/killswitch on the network.

    This replaces the 'inet ttp' table with a minimal, ultra-restrictive ruleset
    that drops all inbound, outbound, and forwarded network traffic on physical
    interfaces, allowing only local loopback communication.
    """
    ruleset = """
    table inet ttp {
        chain filter_out {
            type filter hook output priority filter; policy drop;
            oifname "lo" accept
        }
        chain filter_forward {
            type filter hook forward priority filter; policy drop;
        }
        chain filter_input {
            type filter hook input priority filter; policy drop;
            iifname "lo" accept
        }
    }
    """
    try:
        # 1. Create and sanitize the dedicated table
        _run_nft(["add", "table", "inet", "ttp"])
        _run_nft(["flush", "table", "inet", "ttp"])

        # 2. Total isolation: drop everything except loopback
        _run_nft_string(ruleset)
        logger.warning("Emergency killswitch applied: network traffic isolated.")
    except Exception as e:
        logger.error(f"Failed to apply emergency killswitch: {e}")
        if not isinstance(e, FirewallError):
            raise FirewallError(f"Failed to apply emergency killswitch: {e}") from e
        raise


def destroy_rules() -> bool:
    """Destroy the 'ttp' table and clean up firewall rules.

    This is the atomic cleanup operation. It attempts to destroy the table
    and verifies success.

    Returns:
        bool: True if the table was successfully destroyed or already gone, False otherwise.
    """
    result = subprocess.run(
        ["nft", "destroy", "table", "inet", "ttp"], capture_output=True, check=False
    )
    # returncode 1 with table absent = already clean, not an error
    # to distinguish it, check if the table exists
    if result.returncode != 0:
        # Check: does the table still exist?
        check = subprocess.run(
            ["nft", "list", "table", "inet", "ttp"], capture_output=True, check=False
        )
        if check.returncode != 0:
            # The table is gone - destroy "failed" because it was already clean
            return True
        # The table still exists - destroy actually failed
        logger.error(f"nft destroy failed: {result.stderr.strip()}")
        return False

    RULES_TEMP_PATH.unlink(missing_ok=True)
    return True


def _run_nft(args: list[str]) -> None:
    """Helper to run nft commands."""
    subprocess.run(["nft"] + args, capture_output=True, text=True, check=True)


def _run_nft_string(ruleset: str) -> None:
    """Inject a complex ruleset string directly into nft via a temporary file."""
    try:
        # Ensure the state directory exists
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        # Write to temporary file to get better error messages with line numbers
        RULES_TEMP_PATH.write_text(ruleset.strip() + "\n", encoding="utf-8")

        subprocess.run(
            ["nft", "-f", str(RULES_TEMP_PATH)],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        error_msg = str(e)
        if hasattr(e, "stderr") and e.stderr:
            error_msg = e.stderr.strip()
        raise FirewallError(error_msg)
