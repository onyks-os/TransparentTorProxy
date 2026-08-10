# Explanation: System Architecture & Execution Flow

TTP transparently routes all network traffic by orchestrating standard Linux kernel subsystems, system utilities, and Tor's control interfaces.

---

## 1. Component Diagram

```mermaid
flowchart LR
    App["Application"] --> Local["Local Network"]
    Local --> DNS["systemd-resolved (Intercepted)"]
    DNS --> NFT["nftables (inet ttp table)"]
    NFT --> Tor["Tor Daemon (ttp-tor.service)"]
    Tor --> Internet["Tor Network / WAN"]
```

---

## 2. Technical Building Blocks

### Volatile Runtime (`tmpfs`)
The entire session state, temporary configurations, lockfiles, and logs reside exclusively in volatile memory (`/run/ttp/` and `/run/tor/ttp/`). Zero persistent configuration state or residue is left on host storage.

### Atomic Firewall Redirection (`nftables`)
Generates and loads an isolated `inet ttp` nftables ruleset atomically to intercept TCP and DNS traffic, redirecting them to Tor while preventing IPv6 and DoT/DoH leaks.

### DNS Bind-Mount Overlay
Overlays `/etc/resolv.conf` with a volatile RAM-backed configuration via a kernel-level bind-mount (`mount --bind`), ensuring DNS calls are resolved by Tor without modifying the original file on disk.

### Systemd-Native Service (`ttp-tor.service`)
Manages Tor via a dedicated, volatile `ttp-tor.service` systemd unit running on non-standard ports (TransPort `9041`, DNSPort `9054`), coexisting with standard system Tor instances.
