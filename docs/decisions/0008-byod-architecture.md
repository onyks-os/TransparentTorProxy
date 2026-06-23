<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0008: Bring Your Own Daemon (BYOD) Architecture

## Status

Accepted (v0.4.5), Updated (v0.4.6)

## Context

TTP was originally designed to manage the Tor daemon lifecycle directly via systemd service units.
However, in certain scenarios, managing the Tor daemon directly inside TTP was restrictive:
1. Inside systemd-enabled lightweight containers (like Docker or systemd-nspawn) where running a full systemd service tree might be customized or restricted.
2. When users want to route traffic through an existing, custom-configured Tor daemon already running on their system (e.g. system tor, Tor Browser daemon, or multi-instance configurations).

To support these use cases, TTP separates network routing orchestration from Tor daemon lifecycle management. Note that the host OS is still strictly required to run systemd (e.g., for cgroups v2 slice bypass execution using `systemd-run`).

## Decision

We introduced the **Bring Your Own Daemon (BYOD)** mode:
* Added the `--external-daemon` CLI option to `start` and `restart` commands.
* In BYOD mode, TTP delegates Tor startup, supervision, and lifecycle to the host or container environment.
* TTP performs **Passive Health Checks** at startup to verify that Tor is actively listening on the target ports (TCP TransPort and UDP/TCP DNSPort).
* **Tor UID Resolution Hierarchy**: Since the firewall needs to allow Tor process traffic to bypass redirection, TTP resolves Tor's UID by:
  1. Manual override (`--tor-uid` option accepting UID or username).
  2. Sockets parsing: checking `/proc/net/tcp` and `/proc/net/tcp6` for the listening socket owner UID of `transport_port`.
  3. Checking `/etc/passwd` for standard users `tor` or `debian-tor`.
* TTP bypasses all systemd service commands for the Tor service (`systemctl start/stop/status ttp-tor`) in startup and teardown phases.
* The watchdog service is disabled in BYOD mode since it relies on systemd for privilege-separated service control. If Tor crashes, the network fails closed (packets die on closed ports), preventing cleartext leaks.

## Consequences

* **Pros**:
  * TTP supports custom external Tor configurations and multi-instance Tor setups.
  * TTP can run inside Docker/container environments that use systemd.
  * Separation of concerns: TTP focuses purely on the network layer while leveraging the host's Tor instance.
* **Cons**:
  * The user is responsible for starting and monitoring the external Tor process.
  * No watchdog auto-healing is available in BYOD mode.
