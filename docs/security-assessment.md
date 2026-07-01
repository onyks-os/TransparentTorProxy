# TTP – Security Assessment & Threat Model

**Version:** 1.0  
**Last Updated:** 2026-06-11  
**Scope:** Transparent Tor Proxy (TTP) v0.4.x  
**Methodology:** STRIDE per component

> This document provides a structured threat model and risk assessment for TTP. It is intended for security auditors, contributors evaluating the security posture of the project, and users who want to understand the residual risks before deploying TTP in high-risk scenarios.

---

## Table of Contents

1. [Security Objectives](#1-security-objectives)
2. [Trust Boundaries & Assets](#2-trust-boundaries--assets)
3. [Threat Model (STRIDE)](#3-threat-model-stride)
4. [Known Limitations & Residual Risks](#4-known-limitations--residual-risks)
5. [Supply Chain Security](#5-supply-chain-security)
6. [Security Controls Summary](#6-security-controls-summary)
7. [Out of Scope](#7-out-of-scope)

---

## 1. Security Objectives

TTP is designed to achieve the following security properties, in order of priority:

| #    | Objective                          | Description                                                                                                                                 |
| :--- | :--------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | **Traffic Confidentiality**        | All TCP traffic from the host must be routed through Tor. No cleartext traffic must reach the ISP.                                          |
| 2    | **DNS Leak Prevention**            | All DNS queries must be resolved by Tor's internal resolver. System, application, or browser-level DNS must not bypass the Tor network.     |
| 3    | **IPv6 Routing & Leak Prevention** | Native transparent IPv6 support through Tor when supported; dropped to prevent leaks if IPv6 loopback is unavailable.                       |
| 4    | **Crash-Safety / Fail-Closed**     | If TTP crashes, the network must be restored to a known state. The system must never be left in a half-configured state that leaks traffic. |
| 5    | **Integrity of Session State**     | The session lock and runtime configuration must not be tampered with by unprivileged processes.                                             |
| 6    | **Supply Chain Integrity**         | TTP release artifacts must be signed. Dependencies must be audited for known CVEs.                                                          |

> **Critical Disclaimer:** TTP is a best-effort privacy tool. It is **not** a guarantee of anonymity. See [Section 4](#4-known-limitations--residual-risks) for explicit residual risks.

---

## 2. Trust Boundaries & Assets

### 2.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: Root Process (ttp running as root)      │
│                                                           │
│  ┌──────────────┐   ┌────────────┐   ┌───────────────┐  │
│  │  ttp CLI     │──▶│  nftables  │──▶│  Linux Kernel │  │
│  │  (Python)    │   │  (inet ttp)│   │  (netfilter)  │  │
│  └──────────────┘   └────────────┘   └───────────────┘  │
│         │                                                 │
│         │           ┌────────────┐   ┌───────────────┐  │
│         └──────────▶│  systemd   │──▶│  ttp-tor.svc  │  │
│                     └────────────┘   └───────────────┘  │
│         │                                                 │
│         └──────────▶ /run/ttp/ (tmpfs) — volatile lock   │
└─────────────────────────────────────────────────────────┘
         │
         ▼ (all traffic exits via)
┌──────────────────────────────────┐
│  TRUST BOUNDARY: Tor Network      │
│  (Entry Guards → Relays → Exit)  │
└──────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  PUBLIC INTERNET │
└──────────────────┘
```

### 2.2 Protected Assets

| Asset                           | Classification          | Where Stored                                      |
| :------------------------------ | :---------------------- | :------------------------------------------------ |
| Session lock file (PID, config) | Sensitive (runtime)     | `/run/ttp/ttp.lock` (tmpfs, root-only)            |
| Tor control auth cookie         | Secret                  | `/run/tor/ttp/auth_cookie` (tmpfs, tor-user-only) |
| Tor Entry Guard state           | Sensitive (performance) | `/var/lib/tor/ttp/` (root-owned)                  |
| Generated `torrc`               | Configuration           | `/run/tor/ttp/torrc` (tmpfs, root-only)           |
| User's real IP address          | **Highly sensitive**    | Never stored by TTP                               |
| User's DNS queries              | **Highly sensitive**    | Routed through Tor's DNSPort, never logged by TTP |

---

## 3. Threat Model (STRIDE)

### 3.1 `firewall.py` — nftables Rules

| Threat                                            | STRIDE Category        | Description                                                                                    | Mitigation                                                                                                                              | Residual Risk                                                   |
| :------------------------------------------------ | :--------------------- | :--------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------- |
| Rule injection via concurrent `nft` command       | Tampering              | An attacker with root access runs `nft` to add bypass rules to `inet ttp` table                | Atomic rule load via `nft -f` ensures consistent state at load time. Watchdog re-applies rules if the table is modified.                | **Low.** Requires root compromise; watchdog detects within 15s. |
| Pre-existing connections survive rule application | Information Disclosure | TCP connections established before `ttp start` continue in cleartext                           | Kill-switch chain (`REJECT`) terminates pre-existing connections that aren't Tor-routed                                                 | **Low.** RST is sent immediately.                               |
| LAN bypass creates cleartext side-channel         | Information Disclosure | Local LAN traffic (RFC 1918) bypasses Tor, revealing internal network topology                 | Default behavior; explicitly documented. Disabled with `--no-lan-bypass`.                                                               | **Medium.** Accepted design tradeoff; user-controlled.          |
| Outbound traffic leak during session teardown     | Information Disclosure | During graceful teardown, closing active Tor circuits could leak in-flight packets in cleartext | A temporary teardown lockdown rule drops all non-loopback outbound traffic (excluding Tor UID). conntrack state is also flushed.        | **Low.** Outgoing paths are locked before rules are destroyed.  |
| nftables rule persistence after crash             | Elevation of Privilege | If TTP crashes, `inet ttp` rules might remain without DNS overlay, creating inconsistent state | Watchdog detects inconsistency; `ttp stop --restore-only` performs forced cleanup; `ttp start` detects orphaned lock and auto-restores. | **Low.** Multiple recovery paths exist.                         |

### 3.2 `dns.py` — DNS Overlay

| Threat                                  | STRIDE Category        | Description                                                                        | Mitigation                                                                                                                         | Residual Risk                                                                                                            |
| :-------------------------------------- | :--------------------- | :--------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------- |
| Application-level DNS bypass (DoH)      | Information Disclosure | Browsers using DNS-over-HTTPS bypass the system resolver entirely                  | `torrc` maps DoH canary domains to `0.0.0.0`; nftables blocks DoT (port 853) and well-known DoH IPs; routes other DoH through Tor. | **Medium.** Mitigations are best-effort; custom unlisted DoH resolvers are routed through Tor but can degrade anonymity. |
| Stale mount stack from prior crash      | Denial of Service      | Multiple stale bind-mounts on `/etc/resolv.conf` block normal operation            | Pre-start cleanup iterates `/proc/mounts` and removes stale layers                                                                 | **Low.** Handled at startup.                                                                                             |
| Symlink attack on `/etc/resolv.conf`    | Tampering              | On systemd systems, `/etc/resolv.conf` is a symlink; an attacker could redirect it | TTP resolves the real path via `os.path.realpath()` before mounting                                                                | **Low.** Mitigated; requires root to modify the symlink target.                                                          |
| DNS query content analysis by exit node | Information Disclosure | Tor exit nodes can observe DNS queries if not using Tor's internal resolver        | TTP forces all DNS through Tor's `DNSPort` — queries never leave the Tor circuit as plaintext                                      | **Low (by design).** Tor DNS resolution is used.                                                                         |

### 3.3 `tor_install.py` / `tor_control.py` — Tor Daemon

| Threat                                  | STRIDE Category        | Description                                                                                   | Mitigation                                                                                                | Residual Risk                                                      |
| :-------------------------------------- | :--------------------- | :-------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------- |
| Malicious Tor package from distribution | Tampering              | A compromised package manager provides a backdoored Tor binary                                | TTP uses the OS-native package manager (apt, dnf, pacman) which verifies package signatures               | **Low.** Depends on distribution integrity; outside TTP's control. |
| Tor control socket unauthorized access  | Elevation of Privilege | An unprivileged process connects to `/run/tor/ttp/control.sock` and sends `SHUTDOWN`          | Socket permissions: `CookieAuthentication 1` + `ControlSocketsGroupWritable 1` with the Tor service group | **Low.** Cookie auth required; socket group-restricted.            |
| Tor bootstrap failure → traffic leak    | Information Disclosure | If Tor fails to bootstrap, nftables rules are already applied, causing traffic to be rejected | Kill-switch `REJECT` rule blocks all traffic if Tor is unavailable. Bootstrap timeout triggers cleanup.   | **Low.** Fail-closed by design.                                    |
| Malicious Tor exit node                 | Information Disclosure | Tor exit node observes unencrypted cleartext traffic (HTTP, unencrypted protocols)            | Out of scope for TTP. Users must use TLS at the application layer.                                        | **High (inherent Tor limitation).** Not addressable by TTP.        |

### 3.4 `state.py` — Lock File & Session

| Threat                                   | STRIDE Category        | Description                                                          | Mitigation                                                           | Residual Risk                 |
| :--------------------------------------- | :--------------------- | :------------------------------------------------------------------- | :------------------------------------------------------------------- | :---------------------------- |
| Lock file tampering by unprivileged user | Tampering              | An attacker modifies `/run/ttp/ttp.lock` to spoof session state      | Lock file is owned by root (`chmod 600`); tmpfs path is root-managed | **Low.** Requires root.       |
| TOCTOU race on orphan detection          | Elevation of Privilege | Between orphan detection and cleanup, a new session could be started | Atomic lock write + PID validation; only root can run `ttp start`    | **Low.** Root-only execution. |

### 3.5 `watchdog.py` — Session Watchdog

| Threat                               | STRIDE Category   | Description                                                                        | Mitigation                                                                                              | Residual Risk                                                                                       |
| :----------------------------------- | :---------------- | :--------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------ | :-------------------------------------------------------------------------------------------------- |
| Watchdog service killed by attacker  | Denial of Service | An attacker with root access kills `ttp-watchdog.service` to disable monitoring    | Watchdog is optional; its absence does not degrade the firewall or DNS protection                       | **Medium.** Without watchdog, no auto-healing or killswitch. Mitigated by always-on nftables rules. |
| False-positive killswitch activation | Denial of Service | A transient system event (e.g., systemd reload) triggers the two-strike killswitch | Two-strike policy (first failure triggers healing, second triggers killswitch); 3s stabilization window | **Low.** Designed to minimize false positives.                                                      |

### 3.6 `cli.py` — Entry Point & Privilege Escalation

| Threat                                       | STRIDE Category        | Description                                                          | Mitigation                                                                                                               | Residual Risk                                                      |
| :------------------------------------------- | :--------------------- | :------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------- |
| `ttp` binary replaced with malicious version | Tampering              | An attacker replaces the `ttp` binary installed in `/usr/local/bin/` | Release artifacts are signed via Sigstore; native packages use OS package manager signature verification                 | **Low.** Requires root or write access to installation path.       |
| Argument injection via `--bypass-user`       | Elevation of Privilege | Malicious input in `--bypass-user` could be passed to shell commands | User/group names are resolved via Python's `pwd`/`grp` libraries to numeric UIDs/GIDs before use; no shell interpolation | **Low.** Mitigated by library-level resolution.                    |
| Python dependency compromise                 | Tampering              | A compromised version of `typer`, `stem`, or `rich` is installed     | Dependabot monitors for CVEs; `pip-audit --path .` is part of the security workflow                                      | **Medium.** Inherent supply-chain risk for any Python application. |

---

## 4. Known Limitations & Residual Risks

This section documents risks that are **by design**, **inherent to Tor**, or **out of scope** for TTP to mitigate.

> [!CAUTION]
> If you are a whistleblower, journalist, or person at high personal risk, **do not rely on TTP alone**. Use [Tails OS](https://tails.net/) or the official [Tor Browser](https://www.torproject.org/) instead.

| Risk                                       | Severity   | Description                                                                                                                  | User Mitigation                                                                  |
| :----------------------------------------- | :--------- | :--------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------- |
| **Malicious Tor exit node**                | High       | Exit nodes can read unencrypted traffic (HTTP, SMTP, etc.)                                                                   | Always use HTTPS/TLS at the application layer                                    |
| **Browser-level DNS-over-HTTPS**           | Medium     | Normal browsers may bypass system DNS via DoH (port 443). TTP routes unlisted DoH through Tor, but it compromises anonymity. | Disable "Secure DNS" in browser settings for all standard browsers               |
| **Double Tor hop (Tor Browser)**           | Low/Medium | Using Tor Browser while TTP is active creates a double-hop that degrades anonymity                                           | Use a standard browser (Firefox) while TTP is active                             |
| **Application-level identifier leaks**     | High       | Cookies, browser fingerprint, logged-in accounts, and WebRTC can deanonymize you regardless of IP routing                    | Use a fresh browser profile; avoid logging into personal accounts                |
| **IPv6 loopback unsupported**              | Low/Medium | If IPv6 loopback is unsupported by the host OS, IPv6 connectivity is lost since TTP drops all IPv6 to prevent leaks          | Ensure the host kernel supports IPv6 loopback for full dual-stack routing        |
| **Kernel network namespace bypass**        | High       | Applications using their own network namespaces (e.g., Docker containers, VMs) bypass nftables entirely                      | Out of scope; TTP only controls the host network namespace                       |
| **Timing correlation attacks**             | High       | A global passive adversary can correlate entry/exit traffic timing to deanonymize users                                      | Inherent Tor limitation; not addressable by TTP                                  |
| **Physical access / kernel-level rootkit** | Critical   | If the host OS is compromised at the kernel level, no user-space tool can provide security guarantees                        | Use full disk encryption; operate from a live OS (Tails) for high-risk scenarios |

### 4.1 Toggleable Proxy Model vs. Whonix Gateway/Workstation Compartmentalization

TTP runs as a local transparent proxy on the host, meaning it can be toggled on and off at runtime. This introduces fundamental design differences and increased risks compared to dedicated gateway architectures like Whonix:

1. **Lack of Physical/Virtual Isolation**:
   In Whonix, the workstation VM is completely isolated and has no physical network path to the WAN; its only network interface connects to the gateway VM, which forces all traffic through Tor. Under TTP, everything runs in the same host namespace. If the TTP firewall or service fails, or if a user-space application bypasses the routing rules (e.g. via specific namespaces, custom routing tables, or raw socket creation by privileged processes), cleartext leaks can occur.

2. **Transition and Toggle Leak Risks**:
   Since TTP is toggleable, active connections, sockets, and local caches (such as DNS) exist before `ttp start` and after `ttp stop`. Applications may establish cleartext sessions that survive TTP's initialization, or leak packets during startup/shutdown phases before rulesets are atomically committed.

3. **No Defense-in-Depth against Root Compromise**:
   If a host running TTP is compromised, root processes can easily disable nftables, bypass UID/GID exemptions, or read memory directly. In a segmented Gateway/Workstation model, compromising the Workstation VM does not compromise the Gateway's routing integrity.

### 4.2 Leak Testing Requirements (Zero-Leak Assertions)

TTP's Network Sandbox Engine (NSE) test suite programmatically validates the firewall ruleset against leaks. The testing requirements are modeled after official industry leak-testing protocols:
- **Whonix Dev Leak Tests**: Ref. [Whonix Dev/Leak Tests Wiki](https://www.whonix.org/wiki/Dev/Leak_Tests)
- **Tor Project Wiki Leak Tests**: Ref. [Tor Project Torify Leak Testing](https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TorifyHOWTO)

The NSE environment asserts at the link layer that:
1. No TCP/UDP packets escape the WAN interface except those generated by the Tor daemon user (UID) or explicit cgroup bypasses.
2. All DNS traffic is intercepted and redirected to Tor's DNSPort, with zero cleartext DNS queries escaping to standard nameservers.
3. No IPv6 traffic escapes to the WAN if IPv6 routing is disabled or unsupported.

---

## 5. Supply Chain Security

### 5.1 Release Artifact Integrity

All TTP release artifacts (`.deb`, `.rpm`, `.whl`, `.tar.gz`) are signed using **Sigstore** (keyless signing via GitHub Actions OIDC). Signatures can be verified with:

```bash
cosign verify-blob \
  --certificate <artifact.sigstore.crt> \
  --signature <artifact.sigstore.sig> \
  --certificate-identity "https://github.com/onyks-os/TransparentTorProxy/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <artifact>
```

### 5.2 Dependency Monitoring

Dependency CVE scanning, Dependabot configuration, and the remediation SLA are documented in the authoritative source:

**[`DEPENDENCIES.md § 2.3 — Vulnerability Monitoring & Remediation`](../DEPENDENCIES.md#23-vulnerability-monitoring--remediation)**

### 5.3 Trusted Code Paths

- All commits to `main` require a Pull Request with maintainer review.
- Security-critical files (`firewall.py`, `dns.py`, `tor_control.py`, `watchdog.py`, `.github/workflows/`) require explicit sign-off from the Project Lead (see [MAINTAINERS.md](../MAINTAINERS.md)).
- All commits must include a `Signed-off-by` header (DCO) — see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## 6. Security Controls Summary

| Control                                           | Type                   | Status                      |
| :------------------------------------------------ | :--------------------- | :-------------------------- |
| Atomic nftables rule loading                      | Preventive             | ✅ Implemented               |
| Kill-switch (reject all on failure)               | Preventive             | ✅ Implemented               |
| IPv6 routing or fallback blocking                 | Preventive             | ✅ Implemented               |
| DoT (port 853) blocking                           | Preventive             | ✅ Implemented               |
| DoH canary domain mitigation                      | Preventive             | ✅ Implemented (best-effort) |
| Teardown outbound traffic lockdown                | Preventive             | ✅ Implemented               |
| Conntrack table flush during teardown             | Preventive             | ✅ Implemented               |
| DNS bind-mount overlay (no disk writes)           | Preventive             | ✅ Implemented               |
| Volatile runtime (tmpfs, zero persistent configuration residue) | Preventive             | ✅ Implemented               |
| Cookie-authenticated Tor control socket           | Preventive             | ✅ Implemented               |
| Session watchdog with auto-healing                | Detective + Corrective | ✅ Implemented (optional)    |
| Emergency killswitch (two-strike policy)          | Corrective             | ✅ Implemented               |
| Crash recovery (orphaned lock detection)          | Corrective             | ✅ Implemented               |
| Sigstore artifact signing                         | Preventive             | ✅ Implemented               |
| Dependabot CVE monitoring                         | Detective              | ✅ Enabled                   |
| `pip-audit` scoped to project                     | Detective              | ✅ Documented                |
| DCO commit sign-off                               | Preventive             | ✅ Required                  |
| PR review for security-critical files             | Preventive             | ✅ Policy (MAINTAINERS.md)   |

---

## 7. Out of Scope

The following threats are **explicitly out of scope** for TTP's security model:

- **Anonymity against a global passive adversary** (timing attacks, traffic analysis at internet scale)
- **Security of the Tor network itself** (malicious relays, Tor protocol vulnerabilities)
- **Application-layer deanonymization** (browser fingerprinting, cookie tracking, WebRTC leaks)
- **Host OS compromise** (kernel rootkits, malicious hardware, physical access attacks)
- **Non-host network namespaces** (Docker, LXC, VMs running on the same host)
- **User behavioral deanonymization** (logging into personal accounts, metadata in documents)

For high-risk use cases, refer to [Tails OS](https://tails.net/) or [Whonix](https://www.whonix.org/).
