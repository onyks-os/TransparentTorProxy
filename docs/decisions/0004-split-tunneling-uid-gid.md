<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0004: Split Tunneling by UID/GID

## Status

Accepted (v0.4.6)

## Context

In many deployments, certain local processes (e.g., system updates, local daemons, or backup utilities) need to bypass Tor routing to save bandwidth or resolve local endpoints directly on the cleartext network.
To achieve this, we need a secure way to exclude specific processes or users from Tor redirection without opening global security holes or causing DNS leaks.

## Decision

We implemented a split-tunneling architecture based on system UID/GID mapping and priority rules inside `nftables`:
1. Users specify bypassed users/groups using the CLI options `--bypass-user` and `--bypass-group`.
2. TTP resolves usernames and groupnames to numeric UIDs and GIDs at startup via Python's standard `pwd` and `grp` libraries.
3. TTP inserts top-priority rules at the beginning of the `output` chain (e.g. `meta skuid <uid> accept` and `meta skgid <gid> accept`) to allow these processes to exit directly to the WAN.
4. Local DNS queries (UDP/TCP port 53) from bypassed users are still intercepted and redirected to Tor to prevent dynamic DNS leaks.

## Consequences

* **Pros**:
  * Fine-grained control over which applications/users bypass Tor.
  * Native kernel enforcement via `nftables` matching user credentials of socket owners.
* **Cons**:
  * Care must be taken since any application run under the bypassed UID/GID will bypass the proxy and expose the host's real IP address.
  * Bypassed users/groups must exist on the system prior to starting TTP.
