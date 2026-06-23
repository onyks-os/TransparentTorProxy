<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0003: Watchdog & Emergency Killswitch

## Status

Accepted (v0.3.5)

## Context

Once transparent proxying is established, the user relies on Tor for anonymity. However, critical system changes can cause silent leaks or connection drops:
1. The Tor daemon could crash or be terminated.
2. The user or another daemon could flush/manipulate the firewall rules (`nftables`), removing redirection blocks.
3. The DNS overlay could be unmounted.
A static firewall ruleset does not protect the user against runtime changes or daemon failures.

## Decision

We introduced a proactive watchdog background daemon (`ttp-watchdog`) and an emergency fail-closed killswitch.
* The watchdog service periodically (every 5 seconds) verifies the integrity of the Tor process socket, the `nftables` ruleset presence, and the DNS overlay mount.
* On the first integrity check failure, the watchdog attempts "auto-healing" (restarting Tor, re-injecting rules, or re-mounting DNS).
* If the auto-healing step fails or a subsequent check fails (two-strike rule), TTP immediately triggers an emergency fail-closed lockout (killswitch).
* The killswitch flushes all rules and drops all incoming, outgoing, and forwarding network traffic on all interfaces except loopback (`lo`), preventing any cleartext data from leaving the host.

## Consequences

* **Pros**:
  * Proactive safety. Prevents cleartext leaks in the event of Tor service failures.
  * Auto-healing mitigates minor transient glitches before dropping the network.
* **Cons**:
  * Requires running a continuous background daemon.
  * Can lock the user out of the network if Tor fails persistently, requiring manual intervention to run `ttp stop` or restore services.
