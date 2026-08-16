<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0005: Tor Bridge and Pluggable Transports Support

## Status

Accepted (v0.4.7: No Auto-Install policy)

## Context

In censored networks or environments where Tor usage is monitored or blocked, standard direct connections to the Tor network fail. Users need to connect using Tor Bridges and Pluggable Transports (like `obfs4` or `snowflake`) to disguise their traffic.
To support this natively in TTP, we need to handle:

1. Validating bridge lines and bridge files.
2. Detecting and referencing censors-bypassing pluggable transport helper binaries in the volatile `torrc` config.

## Decision

We integrated native support for Tor bridges and pluggable transports:
* Added `--use-bridges`, `--bridge-file`, and `--bridge` CLI options.
* TTP parses, cleans, and validates bridge lines at startup.
* We map transports (e.g. `obfs4`, `snowflake`) to package names (`obfs4proxy`, `snowflake-client`). TTP detects if they are installed in the host's `$PATH`. If missing, TTP displays distro-specific installation guidance and official Tor documentation links, then exits gracefully with status code `0`. **TTP never auto-installs packages.**
* We dynamically write the absolute paths of pluggable transport executables inside the volatile `torrc` (e.g. `ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy`).

## Consequences

* **Pros**:
  * Seamless connection setup in censored networks when binaries are pre-installed.
  * No silent system modifications: users retain full control over what is installed.
  * Clear, distro-specific guidance when a dependency is missing.
* **Cons**:
  * Users must manually install pluggable transport helper binaries before running TTP with bridges.
  * Dynamic `torrc` generation is more complex and depends on paths of external binaries.
