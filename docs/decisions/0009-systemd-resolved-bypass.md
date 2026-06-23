<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0009: systemd-resolved DNS Bypass

## Status

Accepted (v0.4.6)

## Context

On modern Linux distributions, `systemd-resolved` is typically active by default. It manages the system's DNS settings and local stub resolver. Even when TTP binds an overlay to `/etc/resolv.conf`, some system services and user applications (like modern web browsers or network configuration managers) bypass `/etc/resolv.conf` entirely by querying systemd-resolved directly via:
1. **D-Bus interface**: Calling `/org/freedesktop/resolve1` methods.
2. **NSS Module**: Using `nss-resolve` defined in `/etc/nsswitch.conf`.

When these APIs are queried, systemd-resolved resolves the names using the interface-specific DNS servers pushed via DHCP/NetworkManager, completely bypassing TTP's loopback and leaking user DNS queries in cleartext to the upstream ISP.

## Decision

To prevent D-Bus and NSS DNS leaks, TTP hijacks the systemd-resolved configuration natively and volatilely, routing all systemd-resolved upstream queries directly through Tor's local DNSPort, protected by a kernel-level firewall fail-closed policy.

We implement a three-layer defense-in-depth bypass strategy:

### 1. Volatile Configuration Drop-in
When TTP starts, if `systemd-resolved` is active, it writes a volatile configuration drop-in file to `/run/systemd/resolved.conf.d/ttp.conf`:
```ini
[Resolve]
DNS=127.0.0.1:{dns_port}
FallbackDNS=
Domains=~.
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
Cache=no-negative
```
* **Volatile Storage**: Storing in `/run` means the configuration resides on `tmpfs` and evaporates automatically on reboot/power loss, preventing a broken DNS state if the host crashes or shuts down abruptly.
* **Wildcard Routing**: `Domains=~.` configures this loopback resolver as the catch-all routing domain, prioritizing it for all queries.
* **Negative Cache Disable**: `Cache=no-negative` prevents caching temporary resolution failures during Tor bootstrapping.

### 2. Service Restart & Cache Flush Sequence
To enforce the new drop-in configuration, TTP executes:
* `systemctl reload-or-restart systemd-resolved`
* `resolvectl flush-caches`

Upon teardown, TTP deletes the volatile config, restarts systemd-resolved, and flushes the cache once more to restore original DNS functionality.

### 3. Kernel Guillotine (Fail-Closed Firewall)
Since `systemd-resolved` runs under a dedicated system user (typically `systemd-resolve` or `systemd-resolved`), TTP dynamically resolves this user's UID and appends strict drop rules to the `filter_out` chain in its `nftables` ruleset:
* For IPv4: `meta skuid {resolved_uid} ip daddr != 127.0.0.1 drop`
* For IPv6: `meta skuid {resolved_uid} ip6 daddr != ::1 drop` (if IPv6 is enabled)

Even if a configuration manager attempts to push ISP DNS servers via D-Bus, or systemd-resolved config gets corrupted, the kernel will immediately drop any outbound DNS queries originating from the resolved daemon owner that are not directed to localhost.

## Consequences

* **Pros**:
  * Prevents DNS leaks via D-Bus and NSS APIs.
  * Configuration naturally clean on reboot (volatile).
  * High-assurance security model: kernel-level drop rules enforce a secure fail-closed posture.
* **Cons**:
  * Restarting systemd-resolved introduces a brief delay during startup and shutdown.
