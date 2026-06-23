<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0002: Stateless DNS Overlay (`mount --bind`)

## Status

Accepted (v0.3.0)

## Context

To prevent DNS leaks, all DNS queries must be hijacked and routed to Tor's DNS resolver. Standard practice involves overwriting `/etc/resolv.conf` with `nameserver 127.0.0.1` and `nameserver ::1`.
However, overwriting `/etc/resolv.conf` directly:
1. Is destructive: if the process crashes or gets killed abruptly, the original host resolver configuration is lost, breaking name resolution for the host.
2. Conflicts with system resolver daemons (like `systemd-resolved` or `NetworkManager`) which aggressively overwrite `/etc/resolv.conf` on DHCP updates or link changes.

## Decision

Instead of modifying the `/etc/resolv.conf` file directly, we use a stateless kernel-level overlay via `mount --bind`.
1. We write a temporary resolv.conf containing Tor's local resolver addresses to `/run/ttp/resolv.conf`.
2. We perform a bind mount (`mount --bind /run/ttp/resolv.conf /etc/resolv.conf`).
3. To resolve conflicts, we follow the symlink if `/etc/resolv.conf` is a symbolic link and bind mount to its real target path instead.
4. During teardown, we restore DNS by lazy unmounting (`umount -l`) the bind mount.

## Consequences

* **Pros**:
  * Original `/etc/resolv.conf` remains physically unmodified on disk.
  * System resolver daemons cannot overwrite the file because the mount overlay intercepts all file operations at the kernel level.
  * If the system reboots, the mount overlay disappears naturally.
* **Cons**:
  * Unmounting requires root privileges.
  * If TTP is killed abruptly without running its cleanup phase, the overlay remains active until a manual `umount` or system reboot.
