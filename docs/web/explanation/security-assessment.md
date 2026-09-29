# Explanation: Security Assessment & STRIDE Threat Model

This document outlines the security architecture, trust boundaries, STRIDE threat analysis, and non-goals of TTP.

---

## 1. Security Trust Boundaries

```text
+-------------------------------------------------------------------+
|                        UNPRIVILEGED USER SPACE                    |
|  Un-sandboxed Applications / Browsers / CLI Tools                  |
+---------------------------------+---------------------------------+
                                  | Outbound Network Traffic
                                  v
+---------------------------------+---------------------------------+
|                        KERNEL SPACE INTERCEPTION                  |
|  nftables (inet ttp)  <--->  VFS Mount Overlay (/etc/resolv.conf) |
+---------------------------------+---------------------------------+
                                  | Redirection (127.0.0.1:9041 / 9054)
                                  v
+---------------------------------+---------------------------------+
|                        PRIVILEGED DAEMON SPACE                    |
|  ttp-tor.service (Tor Process / SOCKS / Control Socket)           |
+-------------------------------------------------------------------+
```

1. **User / Root Boundary**: Unprivileged user applications cannot alter `nftables` tables or `/etc/resolv.conf` bind-mounts.
2. **Network Interception Boundary**: Intercepts TCP traffic at netfilter output hooks before packets hit physical network interfaces.
3. **DNS Boundary**: System DNS - `/etc/resolv.conf` and `systemd-resolved` alike - ends at Tor's DNSPort (`127.0.0.1:9054` by default). Application-level DoH and DoT are TCP, so they go through Tor like any connection.

---

## 2. Threat Analysis (STRIDE Matrix)

| Threat Category | Potential Risk Scenario | TTP Security Countermeasure |
|---|---|---|
| **Spoofing** | A rogue process impersonates the `ttp-tor` daemon to capture redirected network traffic. | `nftables` rules enforce `skuid` matching against the verified UID of the running `ttp-tor` service. |
| **Tampering** | A local process or daemon modifies `/etc/resolv.conf` or flushes or alters the `inet ttp` table. | With `--watchdog`: an inotify watch and an nftables event subscription wake the watchdog, which compares the table rule for rule with the one the session applied and engages the emergency killswitch on any difference (31-48 ms measured). It does not try to repair a changed table; it holds the killswitch until `ttp stop`. |
| **Repudiation** | An abrupt system crash leaves network interfaces in an inconsistent state. | Session state is stored in `tmpfs` (`/run/ttp`). Re-running `sudo ttp start` or `sudo ttp stop` forces lock recovery. |
| **Information Disclosure** | Application-layer DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) queries bypass Tor's DNSPort. | Structural, not a blocklist: for every non-bypassed process all TCP (DoH, DoT included) goes to Tor's TransPort and every other packet (QUIC DoH included) is rejected, so the resolver sees a Tor exit. See [ADR 0012](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0012-doh-dot-and-browser-leaks-are-out-of-scope.md) and [Applications that resolve DNS on their own](../how-to/apps-with-own-dns.md). |
| **Denial of Service** | Unclean shutdown leaves orphan sockets or blocked network interfaces. | Teardown applies a lockdown, kills open sockets, flushes connection tracking, removes the `inet ttp` table and restores DNS, deleting the lock last even if a step fails. After a crash, the next `ttp start` or `ttp stop --restore-only` recovers. |
| **Elevation of Privilege** | A bypassed command keeps root's privileges or groups. | `sudo ttp bypass` runs the command via `systemd-run` in `ttp-bypass.slice` as `SUDO_UID` / `SUDO_GID`, wrapped in `setpriv --init-groups` so root's supplementary groups are not inherited. |

---

## 3. Non-Goals and Explicit Limitations

TTP provides network-level transparent proxying. The following protections fall outside its operational scope:

* **Application-Layer Fingerprinting**: TTP does not alter browser TLS Client Hellos, HTTP headers, User-Agent strings, or JavaScript canvas fingerprinting.
* **Non-TCP Protocols**: Tor does not carry ICMP or UDP (except DNS). Non-DNS UDP and ICMP are rejected.
* **Reboot**: A session does not survive a reboot and TTP has no start-at-boot mode. After a reboot all traffic is in cleartext until `ttp start` is run again.
* **WebRTC**: STUN over UDP is rejected like all UDP, but WebRTC's serious leaks - host ICE candidates with private addresses, local interface enumeration - happen inside the browser and reach the page through JavaScript. They are not packets, so no firewall sees them. Disable WebRTC in the browser (`media.peerconnection.enabled` in Firefox).
