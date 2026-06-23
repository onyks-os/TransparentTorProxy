<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0006: Subprocess Network Orchestration

## Status

Accepted (v0.4.6)

## Context

TTP needs to manipulate network namespaces, virtual ethernet (`veth`) interfaces, and system routing tables. Currently, this is achieved by calling external shell binaries (`iproute2` and `nftables` commands) via Python's `subprocess` module.
We evaluated migrating to a native Netlink Python library (`pyroute2`) to avoid shell execution overhead and text-based parsing of command outputs.

## Decision

We decided to keep the current `subprocess`-based network orchestration for CLI commands. The overhead (< 50ms) is negligible for user experience and CLI execution, and keeping dependencies minimal is highly beneficial for simplicity and maintainability.

However, we established strict **Trigger Conditions** under which we will evaluate a migration to `pyroute2` in the future (Target: v0.6.0+):
1. **Active Monitoring**: TTP transitions from a static CLI tool to a stateful background daemon that needs to subscribe to Netlink sockets to handle real-time kernel events (e.g. interface IP changes, network cable disconnects).
2. **Strict Performance constraints**: Future profiling tests (via `cProfile`) demonstrate that shell command execution via `subprocess` accounts for more than 20% of TTP's total boot time (excluding Tor bootstrapping).

## Consequences

* **Pros**:
  * Simpler implementation using standard tool interfaces (`ip`, `nft`).
  * Easier for external contributors to read, debug, and write tests for.
  * Avoids bringing in heavy Python dependencies (`pyroute2`) for the core runtime.
* **Cons**:
  * Minor overhead of fork/exec system calls.
  * Relies on the host system having standard `iproute2` and `nftables` binaries installed and available in `$PATH`.
