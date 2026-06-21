<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0007: Ruleset Testing with Network Sandbox Engine (NSE)

## Status

Accepted (v0.4.5)

## Context

To guarantee that TTP's firewall configuration (`nftables`) is completely leak-proof, we need programmatic validation.
Testing firewall rules on the active host interface:
1. Is risky, as it disrupts the host's actual network during tests.
2. Can lead to transient packet drops or leaks on the host.
3. Is hard to automate securely in a CI/CD environment without affecting the pipeline worker's network.

## Decision

We integrated the **Network Sandbox Engine (NSE)**, published on PyPI, as a build and testing dependency.
* NSE creates isolated network namespaces and virtual ethernet topologies programmatically.
* We load TTP's actual `nftables` ruleset inside the isolated namespace.
* We use Scapy to inject test packets (DNS queries, HTTP connections, bypassed UID/GID traffic) and run an `AsyncSniffer` on the host-side `veth` interface to capture any outgoing WAN packets.
* We perform **Zero-Leak PCAP Assertions**: any packets escaping the namespace on the WAN interface that are not routed through Tor or explicitly bypassed represent a failure.
* We also filter out kernel-level noise (like IPv6 MLD/NDP and IPv4 IGMP multicast packets) to prevent false-positive assertions.

## Consequences

* **Pros**:
  * Programmatic, 100% isolated, and safe verification of firewall rules.
  * Captures actual packet leaks at the link layer before code release.
  * Can be run inside Docker containers during CI/CD checks (using `nsenter` and `pyroute2` to avoid mount restrictions).
* **Cons**:
  * Adds development dependencies (`network-sandbox-engine` and `pyroute2`).
  * Running tests requires root privileges to manipulate namespaces and run packet sniffers.
