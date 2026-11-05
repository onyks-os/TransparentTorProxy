<!-- Copyright (c) 2026 onyks-os; SPDX-License-Identifier: MIT -->

# ADR 0014: Passive session monitor

## Status

Accepted by the maintainer, 2026-11-06. Implemented for 0.5.0 (unreleased).

## Context

`ttp status` gives one local snapshot; `ttp check` and `ttp check-leak` initiate
external verification. An operator watching a running session needs to see
changes without repeatedly invoking commands or mistaking an old Tor check for
continuous proof. ADR 0013 defines the underlying evidence and its expiry.

## Decision

`ttp monitor` is a root-only, interactive terminal view of repeated passive
session observations. It uses the same read-only observation path as `status`.
The default sampling interval is five seconds, configurable from two to sixty
seconds. It does not start a daemon, make Tor or DNS Internet requests, run
`check` or `check-leak`, or add DNS/firewall checks beyond those in `status`.

The view shows the current session, historical Tor verification with its age,
watchdog progress, emergency application and kernel verification, notification
delivery state, existing rejected-packet counter, and active diagnostics. A
bounded, in-memory timeline records meaningful changes seen *since opening the
view*. It is cleared on session identity change. The counter is cumulative,
and its difference from the preceding sample is explicitly not a leak count.
Elapsed age alone does not create a timeline event.

Missing or failed observations show UNKNOWN immediately, without retaining a
favorable previous snapshot. Terminal control characters in observed strings
are replaced. The command requires a terminal; scripts should use `status
--json`. Closing the view with Ctrl-C or SIGTERM does not stop TTP or alter
network policy. Monitor exit status describes command execution, not session
health.

## Consequences

The operator can see recent transitions and stale evidence while remaining at
the terminal. The view has no history before it was opened, no persistent event
store, and no alert channel once closed. It cannot prove absence of leaks or
replace the watchdog, an active Tor check, or independent packet capture.
