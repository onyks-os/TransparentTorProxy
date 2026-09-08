<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0007: Ruleset Testing with Network Sandbox Engine (NSE)

## Status

Accepted (v0.4.7). Amended (v0.4.8) — see *Amendment*.

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

## Amendment (v0.4.8): a negative assertion needs a positive control

The decision above was sound; the *implementation* had a hole that took a year
to notice, and it is worth recording because it is a general trap.

Every assertion in the suite had the shape `assert len(leaks) == 0`. That is true
when the firewall works. It is also true when the `AsyncSniffer` failed to start,
when the interface name is wrong, when the BPF filter excludes the traffic, or
when the stimulus never left the process. Four wrong reasons and one right one,
indistinguishable in the result.

Worse, the suite ran nowhere: no make target, no CI job, no step in
`scripts/verify.sh`, and the `nse` marker is excluded from the default pytest
run. So the strongest claim in the README rested on assertions that could not
fail, executed by nothing.

Amendments:

1. **Every containment test runs twice.** First with the ruleset *flushed*, where
   the packet MUST be observed — this proves the instrument works, on this
   machine, for this traffic, in this run. Only then is the zero-leak assertion
   made. A failing control fails the test.
2. **A reverse assertion**: traffic from a bypassed UID must still reach the LAN.
   Without it, a firewall that blocked everything would pass the whole suite.
3. **The suite is executed**: `make test-nse`, a CI job on every push, and a step
   in the pre-release pipeline. `TTP_REQUIRE_NSE=1` makes a missing, shadowed or
   too-old NSE a hard error rather than a skip, because a gate that skips itself
   is not a gate.
4. **NSE pinned to `>=2.1.0,<3`.** Below 2.1.0 the engine's own runner reported
   PASSED when its oracle observed nothing, and its trace monitor could stop
   reading mid-run without saying so. Our test being green against such an engine
   would not have been evidence of anything. The upper bound is real: 2.0.0
   already rewrote `run_test_pipeline`'s signature once.
5. **Determinism**: permanent neighbour entries for the veth gateway. Without
   them the first packet of a stimulus is held while the kernel resolves ARP/NDP,
   which the sniffer's `not arp` filter hides — making the positive control fail
   intermittently for a reason unrelated to the firewall.

The general form of the lesson: **a test that asserts an absence must first
demonstrate it can detect a presence.**

## Consequences

* **Pros**:
  * Programmatic, 100% isolated, and safe verification of firewall rules.
  * Captures actual packet leaks at the link layer before code release.
  * Can be run inside Docker containers during CI/CD checks (using `nsenter` and `pyroute2` to avoid mount restrictions).
* **Cons**:
  * Adds development dependencies (`network-sandbox-engine` and `pyroute2`).
  * Running tests requires root privileges to manipulate namespaces and run packet sniffers.
  * TTP's strongest claim now depends on a second project being correct. That is
    a real coupling and the reason for the hard version floor: the oracle is a
    dependency of the evidence, not just of the tooling.
