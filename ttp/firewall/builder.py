# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Stateless Firewall Module - Pure ruleset string generator."""

import subprocess

from ttp.paths import resolve


def _has_cgroup_bypass_support() -> bool:
    """Check if the kernel supports cgroupv2 socket bypass by testing a dummy rule.

    Returns:
        bool: True if ``nft --check`` succeeds for cgroupv2 matching rules, False otherwise.
    """
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
            [resolve("nft"), "--check", "-f", "-"],
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


def _build_ruleset(
    tor_uid: int,
    transport_port: int,
    dns_port: int,
    ipv6_avail: bool,
    allow_root: bool,
    lan_bypass: bool,
    bypass_uids: list[int] | None,
    bypass_gids: list[int] | None,
    resolved_uid: int | None,
    cgroup_bypass: bool,
) -> str:
    """Build and return the nftables ruleset string for the TTP session.

    This is a **pure function**: it takes all required configuration data as arguments
    and renders the complete nftables ruleset string with no side effects.
    It never calls ``nft`` directly or touches system state.

    Invariant properties encoded in the ruleset:
        1. Non-exempt local traffic MUST NOT leave the system in cleartext.
        2. DNS traffic (UDP/TCP port 53) MUST be redirected to Tor DNSPort.
        3. TCP traffic MUST be redirected to Tor TransPort.
        4. Non-TCP, non-DNS traffic (ICMP, generic UDP) MUST be rejected.

    Args:
        tor_uid: System UID of the Tor daemon process to exempt from transparent proxying.
        transport_port: Local TCP port where Tor is listening for transparent proxying.
        dns_port: Local UDP/TCP port where Tor is listening for DNS resolution.
        ipv6_avail: Whether IPv6 routing is active and supported on the host loopback.
        allow_root: If True, allows root (UID 0) processes to bypass proxying.
        lan_bypass: If True, excludes RFC 1918 and Link-Local subnets from redirection.
        bypass_uids: Optional list of UIDs exempted from transparent proxying.
        bypass_gids: Optional list of GIDs exempted from transparent proxying.
        resolved_uid: Optional UID of ``systemd-resolved`` to enforce fail-closed DNS drops.
        cgroup_bypass: If True, enables cgroupv2 socket bypass for ``ttp-bypass.slice``.

    Returns:
        str: Rendered nftables ruleset string ready for ``nft -f``.
    """
    lan_rule = ""
    lan6_rule = ""
    if lan_bypass:
        lan_rule = "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"
        if ipv6_avail:
            lan6_rule = "ip6 daddr { fc00::/7, fe80::/10 } accept"

    root_rule = "meta skuid 0 accept" if allow_root else ""

    # Bypass rules for nat output and filter_out chains
    bypass_rules_nat: list[str] = []
    bypass_rules_filter: list[str] = []
    if cgroup_bypass:
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
    bypass_rules_nat_str = "\n                ".join(bypass_rules_nat) if bypass_rules_nat else ""
    bypass_rules_filter_str = "\n                ".join(bypass_rules_filter) if bypass_rules_filter else ""

    # systemd-resolved leak-prevention rules
    resolved_rules: list[str] = []
    if resolved_uid is not None:
        resolved_rules.append(f"meta skuid {resolved_uid} ip daddr != 127.0.0.1 drop")
        if ipv6_avail:
            resolved_rules.append(f"meta skuid {resolved_uid} ip6 daddr != ::1 drop")
    resolved_rules_str = "\n            ".join(resolved_rules) if resolved_rules else ""

    # Loopback rules
    loopback_ipv4 = "ip daddr 127.0.0.0/8 accept"
    loopback_ipv6 = "ip6 daddr ::1 accept" if ipv6_avail else ""

    # DNS redirection
    dns_redirect_ipv4 = (
        f"udp dport 53 dnat ip to 127.0.0.1:{dns_port}\n                tcp dport 53 dnat ip to 127.0.0.1:{dns_port}"
    )
    dns_redirect_ipv6 = (
        f"\n                udp dport 53 dnat ip6 to [::1]:{dns_port}"
        f"\n                tcp dport 53 dnat ip6 to [::1]:{dns_port}"
        if ipv6_avail
        else ""
    )

    # TCP transparent proxy redirection
    tcp_redirect_ipv4 = f"ip protocol tcp dnat ip to 127.0.0.1:{transport_port}"
    tcp_redirect_ipv6 = f"\n                meta l4proto tcp dnat ip6 to [::1]:{transport_port}" if ipv6_avail else ""

    ipv6_leak_prevention = "" if ipv6_avail else "meta nfproto ipv6 drop"

    # DoH IP blocks (TCP & QUIC/UDP 443)
    doh_ips_v4 = "{ 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222, 208.67.220.220 }"
    doh_reject_ipv4 = f"ip daddr {doh_ips_v4} tcp dport 443 reject"
    quic_doh_reject_ipv4 = f"ip daddr {doh_ips_v4} udp dport 443 reject"
    doh_reject_ipv6 = ""
    quic_doh_reject_ipv6 = ""
    if ipv6_avail:
        doh_ips_v6 = "{ 2606:4700:4700::1111, 2606:4700:4700::1001, 2001:4860:4860::8888, 2001:4860:4860::8844, 2620:fe::fe, 2620:fe::9, 2620:0:ccc::2, 2620:0:ccd::2 }"
        doh_reject_ipv6 = f"ip6 daddr {doh_ips_v6} tcp dport 443 reject"
        quic_doh_reject_ipv6 = f"ip6 daddr {doh_ips_v6} udp dport 443 reject"

    return f"""
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

            # 6. DoH (DNS-over-HTTPS) & QUIC Leak Prevention: Block common public DoH resolvers on port 443.
            # Note: For non-bypassed TCP, NAT output (priority -150) redirects TCP/443 to Tor TransPort
            # before filter_out runs. These TCP reject rules serve as a safety net if NAT fails and
            # apply to bypassed users. The UDP rules block HTTP/3 (QUIC) DoH queries which NAT does not redirect.
            {doh_reject_ipv4}
            {doh_reject_ipv6}
            {quic_doh_reject_ipv4}
            {quic_doh_reject_ipv6}

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
