# Explanation: Security Assessment & STRIDE Threat Model

This document outlines the threat model, security boundaries, and mitigations implemented in TTP.

---

## 1. Trust Boundaries

1. **User Boundary**: Unprivileged processes vs. root privileges.
2. **Network Interception Boundary**: Applications transmitting packets vs. kernel `nftables` NAT/filter rules.
3. **DNS Boundary**: System resolver vs. kernel bind-mount overlay & Tor DNSPort.

---

## 2. Threat Analysis (STRIDE)

| Threat Category | Potential Risk | TTP Mitigation Control |
|---|---|---|
| **Spoofing** | Rogue process impersonates Tor daemon | Strict `meta skuid` checks in nftables ruleset. |
| **Tampering** | External process modifies `/etc/resolv.conf` | Inotify double-watch + watchdog FSM auto-repair. |
| **Repudiation** | Unlogged crash during network teardown | Lockfile recovery on subsequent `ttp start` invocation. |
| **Information Disclosure** | DNS-over-HTTPS (DoH) leak via public resolvers | Block port 853 (DoT) and port 443 IP blocks for known DoH resolvers (plus UDP/443 QUIC drops). |
| **Denial of Service** | Unclean shutdown leaving broken network | Teardown lockdown + active socket slaughter + atomic table destruction. |
| **Elevation of Privilege** | Bypassed UIDs abuse root privileges | Explicit UID/GID resolution validation before firewall rule generation. |
