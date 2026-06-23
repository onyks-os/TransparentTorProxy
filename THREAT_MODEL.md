# Threat Modeling and Attack Surface Analysis for TTP v0.4.6

## Assets to Protect
- User's real IP address
- DNS queries
- Unencrypted cleartext traffic

## Identified Threats
| Threat               | Description                                                         | Mitigation in TTP                                                                                    |
| -------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| DNS Leak             | The system resolves DNS queries outside of the Tor network          | Forced through Tor's `DNSPort` using nftables redirect rules                                         |
| IPv6 Leak            | Outgoing IPv6 traffic bypasses Tor                                  | All IPv6 traffic is disabled/blocked via nftables                                                    |
| Firewall Bypass      | Users or processes modify firewall rules while TTP is active        | Atomic nftables loading, automatic validation, and watchdog kill-switch                              |
| Privilege Escalation | Malicious users manipulate runtime or lock files to execute code    | All lock, socket, and configuration files are stored in `/run/ttp/` (tmpfs) write-restricted to root |
| Crash Recovery       | Unexpected daemon termination leaves the system with broken routing | Runtime watchdog daemon automatically heals the system or triggers a network lock                    |

## Attack Surface
- **CLI interface**: `ttp start/stop/status` commands – accessible only to users with `sudo`/root privileges.
- **Tor Control Port** (localhost:9051): Protected by a cryptographically strong random password generated dynamically at startup.
- **nftables table `inet ttp`**: Dedicated table isolated and managed solely by TTP using atomic rulesets.
- **Lock and state files**: `/run/ttp/ttp.lock` – restricted to permission `600` (root-only access).

## Conclusion
The key identified security threats are fully mitigated by TTP's design. This threat modeling and attack surface analysis will be updated for every major release.
