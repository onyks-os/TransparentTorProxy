<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0003: Watchdog & Emergency Killswitch

## Status

Accepted (v0.3.5). Amended (v0.4.9) — see *Amendment*.

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

## Amendment (v0.4.9): what the watchdog actually does

The decision above stands - a watchdog, and a fail-closed killswitch when the
session cannot be trusted - but three of its details no longer describe the code.

* **It is event-driven, not a 5-second poll.** The watchdog sleeps on a netlink
  subscription to nftables events and an inotify watch on `/etc/resolv.conf`, with
  a 15-second heartbeat. A changed table reaches the killswitch in 31-48 ms
  (measured, `docs/security-assessment.md` 4.3).
* **Only Tor is healed.** A failed Tor gets one `systemctl restart`; a changed
  table or DNS overlay is treated as tampering and goes straight to the killswitch.
  Re-injecting rules into a table someone else has altered would mean guessing
  what they intended, and the table is now compared rule for rule with the one the
  session applied, so any difference is a real one.
* **The killswitch is held.** It used to be applied and the watchdog exited, which
  left nothing watching it: deleting its table released everything (#77). The
  watchdog now stays in the `killswitch` state and re-applies it whenever it is
  removed or altered, until `ttp stop`.

The state machine that implements this is described in
[ADR 0010](0010-watchdog-finite-state-machine.md).
