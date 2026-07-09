# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

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


def _has_cgroup_bypass_support() -> bool:
    """Check if the system supports cgroupv2 socket bypass by trying to load a test rule."""
    from pathlib import Path

    cgroup_path = Path("/sys/fs/cgroup/ttp-bypass.slice")
    try:
        cgroup_path.mkdir(exist_ok=True)
    except Exception:
        pass

    test_ruleset = """
    table inet ttp_cgroup_test {
        chain output {
            type filter hook output priority filter;
            socket cgroupv2 level 1 "ttp-bypass.slice" accept
        }
    }
    """
    try:
        res = subprocess.run(
            ["nft", "--check", "-f", "-"],
            input=test_ruleset,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode == 0:
            return True
    except Exception:
        pass

    return False


def apply_rules(
    tor_user: str,
    transport_port: int = 9041,
    dns_port: int = 9054,
    allow_root: bool = False,
    lan_bypass: bool = True,
    bypass_uids: list[int] | None = None,
    bypass_gids: list[int] | None = None,
    disable_ipv6: bool = False,
) -> None:
    """Create the 'ttp' table and inject redirection rules.

    Orchestrates the process: Create -> Flush -> Inject.
    If any step fails, it triggers an automatic rollback (destruction).
    """
    # Resolve numeric UID for the tor user to avoid nft resolution issues
    try:
        if tor_user.isdigit():
            tor_uid = int(tor_user)
        else:
            tor_uid = pwd.getpwnam(tor_user).pw_uid
    except KeyError as e:
        raise FirewallError(f"Tor user '{tor_user}' not found on system.") from e

    # Construct dynamic rules based on options
    from ttp.tor_detect import is_ipv6_supported

    ipv6_avail = is_ipv6_supported() and not disable_ipv6

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
    if _has_cgroup_bypass_support():
        bypass_rules_nat.append('socket cgroupv2 level 1 "ttp-bypass.slice" accept')
        bypass_rules_filter.append('socket cgroupv2 level 1 "ttp-bypass.slice" accept')
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

    # Resolve systemd-resolved user UID dynamically if present
    resolved_rules = []
    resolved_uid = None
    for user in ("systemd-resolve", "systemd-resolved"):
        try:
            resolved_uid = pwd.getpwnam(user).pw_uid
            break
        except KeyError:
            continue

    if resolved_uid is not None:
        resolved_rules.append(f"meta skuid {resolved_uid} ip daddr != 127.0.0.1 drop")
        if ipv6_avail:
            resolved_rules.append(f"meta skuid {resolved_uid} ip6 daddr != ::1 drop")
    resolved_rules_str = "\n            ".join(resolved_rules) if resolved_rules else ""

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
    # Invariant properties:
    # 1. Non-exempt local traffic (not Tor, not bypassed UIDs/GIDs) MUST NOT leave the system in cleartext.
    # 2. DNS traffic (UDP/TCP port 53) MUST be redirected to Tor DNSPort (dns_port) or dropped.
    # 3. TCP traffic MUST be redirected to Tor TransPort (transport_port) or dropped.
    # 4. Non-TCP, non-DNS traffic (ICMP, generic UDP, etc.) MUST be rejected in the filter_out chain.
    ruleset = f"""
    table inet ttp {{
        # nat prerouting: Handles redirection for incoming traffic from other network namespaces/interfaces
        # (e.g., virtual interfaces for VMs or Docker containers).
        # Hook: prerouting (runs before routing decisions are made for incoming packets).
        # Invariant: Redirection rules mirror output chain to ensure gateway traffic is equally sandboxed.
        chain prerouting {{
            type nat hook prerouting priority dstnat; policy accept;
            # Redirect external DNS queries to local Tor DNSPort
            {dns_redirect_ipv4}
            {dns_redirect_ipv6}
            # Exempt LAN/local subnets from redirection
            {lan_rule}
            {lan6_rule}
            # Redirect external TCP connections to local Tor TransPort
            {tcp_redirect_ipv4}
            {tcp_redirect_ipv6}
        }}

        # nat output: Hijacks local outbound TCP and DNS traffic, redirecting it to Tor ports.
        # Hook: output, priority -150 (dstnat, runs before routing decisions are finalized).
        # Invariant: Traffic from Tor daemon, bypassed processes, LAN destination, and loopback bypasses redirection.
        chain output {{
            type nat hook output priority -150; policy accept;

            # 1. Tor user EXEMPTION: Allow the Tor daemon to reach the real internet to build circuits.
            meta skuid {tor_uid} accept

            # 1b. Bypass users and groups: Allow whitelisted processes to connect to cleartext WAN.
            {bypass_rules_nat_str}

            # 2. DNS Redirection: Redirect outbound cleartext DNS queries (UDP/TCP port 53) to local Tor DNSPort.
            # Positioned before LAN bypass to prevent DNS leaking via local DNS servers.
            {dns_redirect_ipv4}
            {dns_redirect_ipv6}

            # 3. LAN Bypass: Allow direct local subnet communication (non-DNS) for printer/shares.
            {lan_rule}
            {lan6_rule}

            # 4. Local Exemption: Allow loopback traffic to loopback interface.
            {loopback_ipv4}
            {loopback_ipv6}

            # 5. TCP Redirection: Redirect all remaining outbound TCP traffic to Tor's TransPort.
            {tcp_redirect_ipv4}
            {tcp_redirect_ipv6}
        }}

        # filter_out: The fail-safe "guillotine". Rejects any cleartext packet that escapes nat output.
        # Hook: output, priority filter (standard filter hook, runs after routing decisions).
        # Invariant: ∀ packet ∉ (Tor daemon, bypassed, LAN, loopback) → REJECT.
        chain filter_out {{
            type filter hook output priority filter; policy accept;

            # 1. Allow the Tor daemon to send TCP traffic directly to WAN guards/bridges.
            meta skuid {tor_uid} accept

            # 1b. Bypass users and groups: Allow whitelisted processes to transmit in cleartext.
            {bypass_rules_filter_str}

            # 1c. systemd-resolved fail-closed policy: Prevent resolved from leaking DNS queries directly to WAN.
            {resolved_rules_str}

            # 2. Allow root processes if explicitly requested (e.g. system updates/Tor bootstrapping).
            {root_rule}

            # 3. LAN Bypass: Allow local subnet filter bypass.
            {lan_rule}
            {lan6_rule}

            # 4. Allow loopback traffic.
            {loopback_ipv4}
            {loopback_ipv6}

            # 5. DoT (DNS-over-TLS) Leak Prevention: Block direct connections to port 853.
            tcp dport 853 reject

            # 6. DoH (DNS-over-HTTPS) Leak Prevention: Block common public DoH resolvers on port 443.
            {doh_reject_ipv4}
            {doh_reject_ipv6}

            # 7. IPv6 Leak Prevention: Drop all IPv6 traffic if disabled or unrouteable.
            {ipv6_leak_prevention}

            # 8. Catch-all Reject: Drop/Reject all cleartext traffic not matching exemptions (e.g. UDP, ICMP, raw sockets, or pre-existing TCP connections).
            reject
        }}

        chain filter_forward {{
            # filter_forward: Complete isolation of forwarding plane to prevent bypass via Docker/VM routing.
            # Hook: forward (runs for packets routed through this host).
            # Invariant: Policy drop ensures no unproxied forwarding is permitted.
            type filter hook forward priority filter; policy drop;
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


def apply_teardown_lockdown(tor_uid: int | None = None) -> None:
    """Insert a lockdown drop rule at the top of the filter_out chain in table inet ttp.

    This ensures that all outbound traffic is dropped (exempting loopback and the Tor daemon UID)
    during the graceful shutdown.
    """
    rule = ["insert", "rule", "inet", "ttp", "filter_out"]
    if tor_uid is not None:
        rule += ["meta", "skuid", "!=", str(tor_uid)]
    rule += ["oifname", "!=", "lo", "drop"]

    try:
        _run_nft(rule)
        logger.warning("Teardown lockdown applied: outbound traffic locked.")
    except Exception as e:
        # Gracefully handle cases where the table or chain does not exist (e.g., already stopped)
        logger.debug(
            "Could not apply teardown lockdown (table/chain may not exist): %s", e
        )


def apply_active_socket_slaughter() -> None:
    """Inject temporary reject rules at the top of the filter_out chain to actively terminate pending local connections."""
    try:
        # 1. Uccide le connessioni UDP pendenti (invia ICMP Port Unreachable al processo locale)
        _run_nft(
            [
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
        )
        # 2. Uccide le connessioni TCP pendenti istantaneamente (invia RST al processo locale)
        _run_nft(
            [
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
        )
        logger.warning(
            "Active socket slaughter rules applied: resetting pending connections."
        )
    except Exception as e:
        # Gracefully handle cases where the table or chain does not exist (e.g., already stopped)
        logger.debug("Could not apply active socket slaughter: %s", e)


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
    # Flush the table first for absolute cleanup safety
    subprocess.run(
        ["nft", "flush", "table", "inet", "ttp"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    result = subprocess.run(
        ["nft", "destroy", "table", "inet", "ttp"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    # returncode 1 with table absent = already clean, not an error
    # to distinguish it, check if the table exists
    if result.returncode != 0:
        # Check: does the table still exist?
        check = subprocess.run(
            ["nft", "list", "table", "inet", "ttp"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if check.returncode != 0:
            # The table is gone - destroy "failed" because it was already clean
            return True
        # The table still exists - destroy actually failed
        err_msg = result.stderr.decode().strip() if result.stderr else "unknown error"
        logger.error(f"nft destroy failed: {err_msg}")
        raise FirewallError(f"Failed to destroy nftables ruleset: {err_msg}")

    RULES_TEMP_PATH.unlink(missing_ok=True)
    return True


def _run_nft(args: list[str]) -> None:
    """Helper to run nft commands."""
    subprocess.run(
        ["nft"] + args,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )


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
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        error_msg = str(e)
        if hasattr(e, "stderr") and e.stderr:
            error_msg = e.stderr.strip()
        raise FirewallError(error_msg)
