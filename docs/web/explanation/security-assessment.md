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
                                  | Redirection (127.0.0.1:9040 / 5353)
                                  v
+---------------------------------+---------------------------------+
|                        PRIVILEGED DAEMON SPACE                    |
|  ttp-tor.service (Tor Process / SOCKS / Control Socket)           |
+-------------------------------------------------------------------+
```

1. **User / Root Boundary**: Unprivileged user applications cannot alter `nftables` tables or `/etc/resolv.conf` bind-mounts.
2. **Network Interception Boundary**: Intercepts TCP traffic at netfilter output hooks before packets hit physical network interfaces.
3. **DNS Boundary**: Binds system DNS queries to Tor DNSPort (`127.0.0.1:5353`), dropping unencrypted DoT/DoH leaks.

---

## 2. Threat Analysis (STRIDE Matrix)

| Threat Category | Potential Risk Scenario | TTP Security Countermeasure |
|---|---|---|
| **Spoofing** | A rogue process impersonates the `ttp-tor` daemon to capture redirected network traffic. | `nftables` rules enforce `skuid` matching against the verified UID of the running `ttp-tor` service. |
| **Tampering** | A local process or daemon modifies `/etc/resolv.conf` or flushes `nftables` chains. | Inotify double-watch monitors mount points; Watchdog FSM auto-repairs tables within 5 seconds. |
| **Repudiation** | An abrupt system crash leaves network interfaces in an inconsistent state. | Session state is stored in `tmpfs` (`/run/ttp`). Re-running `sudo ttp start` or `sudo ttp stop` forces lock recovery. |
| **Information Disclosure** | Application-layer DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) queries bypass Tor DNSPort. | `nftables` explicitly drops port 853 (DoT), UDP port 443 (QUIC), and known public DoH resolver IP ranges. |
| **Denial of Service** | Unclean shutdown leaves orphan sockets or blocked network interfaces. | Emergency teardown routines unmount overlays, slaughter active sockets, and flush `inet ttp` tables atomically. |
| **Elevation of Privilege** | Bypassed UIDs or groups abuse root privileges to bypass system firewall rules. | `sudo ttp bypass` delegates execution to `systemd-run` in `ttp-bypass.slice`, strictly dropping privileges to `SUDO_UID` / `SUDO_GID`. |

---

## 3. Non-Goals and Explicit Limitations

TTP provides network-level transparent proxying. The following protections fall outside its operational scope:

* **Application-Layer Fingerprinting**: TTP does not alter browser TLS Client Hellos, HTTP headers, User-Agent strings, or JavaScript canvas fingerprinting.
* **Non-TCP Protocols**: Tor does not support native raw ICMP or UDP transport (except DNS). Non-DNS UDP traffic is dropped or blocked.
* **Un-sandboxed WebRTC**: WebRTC in standard web browsers can leak local IP addresses if STUN/TURN requests bypass proxying. Use browser extensions or hardened browser profiles to disable WebRTC.
