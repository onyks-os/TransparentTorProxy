<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0008: Bring Your Own Daemon (BYOD) Architecture

## Status

Accepted (v0.4.5)

## Context

TTP was originally designed for systemd-based Linux systems, managing the Tor daemon lifecycle via volatile systemd service units.
However, this prevented TTP from running:
1. On systemd-less distributions (such as Alpine Linux or Void Linux).
2. Inside lightweight Docker containers where process managers are absent.
To support these environments, TTP needs to separate network routing orchestration from Tor daemon management (Separation of Concerns).

## Decision

We introduced the **Bring Your Own Daemon (BYOD)** mode:
* Added the `--external-daemon` CLI option to `start` and `restart` commands.
* In BYOD mode, TTP delegates Tor startup, supervision, and lifecycle to the host OS (e.g. OpenRC `rc-service tor start` on Alpine, or Docker Entrypoint startup).
* TTP performs **Passive Health Checks** at startup to verify that Tor is actively listening on the target ports (TCP TransPort and UDP/TCP DNSPort).
* **Tor UID Resolution Hierarchy**: Since the firewall needs to allow Tor process traffic to bypass redirection, TTP resolves Tor's UID by:
  1. Manual override (`--tor-uid` option accepting UID or username).
  2. Sockets parsing: checking `/proc/net/tcp` and `/proc/net/tcp6` for the listening socket owner UID of `transport_port`.
  3. Checking `/etc/passwd` for standard users `tor` or `debian-tor`.
* TTP bypasses all systemd service commands (`systemctl start/stop/status`) in startup and teardown phases.
* The watchdog service is disabled in BYOD mode since it depends on systemd. If Tor crashes, the network fails closed (packets die on closed ports), preventing cleartext leaks.

## Consequences

* **Pros**:
  * TTP can now run on Alpine, Void, and inside Docker containers.
  * Separation of concerns: TTP focuses purely on the network layer.
* **Cons**:
  * The user is responsible for starting and monitoring the Tor process.
  * No watchdog auto-healing is available in BYOD mode.
