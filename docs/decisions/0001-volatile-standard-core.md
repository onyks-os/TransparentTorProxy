<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0001: Volatile Standard Core (`/run/ttp`)

## Status

Accepted (v0.3.0)

## Context

During early development, TTP stored active session state, logs, and lock files on the host's physical persistent disk (e.g. `/var/run` or `/var/lib`). This introduced several issues:
1. If the system crashed or lost power, TTP left behind stale state files that would prevent subsequent startups or lead to inconsistent states.
2. Writing frequent log statements and state changes to a physical disk (especially on flash/SSD storage on embedded or low-resource hosts) was inefficient and increased wear.

## Decision

We decided to move all runtime session data, log files, ephemeral configuration (such as the generated `torrc`), and dynamic systemd service files into the `/run/` memory-backed volatile directory (`tmpfs`). 

Specifically:
* TTP session lock files are written to `/run/ttp/ttp.lock`.
* Dynamic unit files are written to `/run/systemd/system/` (e.g. `ttp-tor.service` and `ttp-watchdog.service`).
* Active session logs are written to `/run/ttp/ttp.log` and capped at 1MB.

Since `/run` is mounted on a `tmpfs` RAM disk, all files automatically evaporate upon system reboot, guaranteeing that any stale lock or service state is cleaned up naturally on a fresh start.

## Consequences

* **Pros**:
  * Predictable, crash-safe state management. No stale session locks exist after a reboot.
  * Reduced SSD/Flash write wear.
  * Faster file read/write operations.
* **Cons**:
  * System logs and state files are lost on reboot. Persistent logs must be retrieved through system journals (e.g. `journalctl`) if necessary.
  * TTP must perform a pre-flight check to verify that `/run` has sufficient free space (at least 5MB) before launching to prevent out-of-space runtime crashes.
