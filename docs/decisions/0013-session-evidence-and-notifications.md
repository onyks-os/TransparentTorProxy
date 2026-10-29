<!-- Copyright (c) 2026 onyks-os; SPDX-License-Identifier: MIT -->

# ADR 0013: Session evidence, required supervision and optional notifications

## Status

Accepted by the maintainer, 2026-10-27. Implemented for 0.5.0 (unreleased).
This record supersedes earlier proposals about degraded states and notifications;
it does not approve a privileged D-Bus controller, VPN topology or `ttp monitor`.

## Contract

Session management, supervision, notification delivery and observation are
composable responsibilities. A command must satisfy the requirements actually
selected, and must not silently replace a missing requested capability. Watchdog
and desktop notifications are optional. Notifications do not require a watchdog:
without a supervisor there is no continuous producer of fault observations.
CLI-only installations require neither a graphical session nor desktop packages.

### Evidence and emergency policy

- Distinguish Tor verification confirmed, valid negative, inconclusive and not
  performed. An inconclusive external check neither proves no Tor traffic nor
  proves isolation. Preserve the session and return code 3.
- A valid negative result from a correctly non-exempt probe requests emergency
  isolation. An exempt or incorrectly executed probe is inconclusive.
- A requested watchdog unavailable before network setup refuses startup without
  changing the network. After setup, request emergency isolation and fail loudly,
  including in quiet mode. Success is announced only after required readiness.
- Distinguish isolation requested, application result and verification against
  the expected kernel rules. Never announce isolation after a failed or unknown
  verification. Re-reading an arbitrary installed table is not a specification.
- Emergency rules block input, output and forwarding except loopback, including
  ordinary LAN and UID/cgroup exemptions. Keep emergency mode until explicit
  session termination. A watchdog restart must not reopen the network.
- systemd runs a small termination handler independent of the watchdog process.
  It attempts isolation if supervision remains required. Explicit TTP teardown
  marks stopping before stopping services, so this handler does not re-arm it.
- Reject `ttp watchdog stop` while the active session requires supervision.
  `ttp stop` remains the explicit way to terminate that contract.
- Before removing emergency protection, explain that sensitive applications
  should be closed: they may reconnect outside Tor after teardown.

### Observation and timing

Retain separate requested policy and observed state, with reasons, observation
times, session identity and service-instance identity. A PID or lock alone does
not establish liveness. Expired observations are unknown, never automatically
healthy or failed. Relevant events invalidate previous observations immediately.
Use suspend-aware monotonic age; re-observe after suspend or process replacement.
External verification is always described as a measurement at a specific time.

| Configurable budget | Default seconds |
| :--- | ---: |
| Watchdog readiness | 30 |
| Nominal progress heartbeat | 5 |
| systemd watchdog timeout | 30 |
| Periodic local integrity check (also triggered by events) | 15 |
| Total local-check budget | 10 |
| Maximum age of a recent local result | 30 |
| Total external verification budget after bootstrap | 60 |
| Notification agent readiness | 15 |
| One notification server call | 5 |
| Total delivery budget, at most 3 attempts | 15 |

Read an administrator-owned INI file `/etc/ttp/ttp.conf`, validate keys, types
and timing relationships before network changes, and freeze effective settings
for the session. Provide documented examples and a command exposing effective
values and their origins. CLI options override configuration where provided.
These deadlines bound attempts and detection, not a promise of leak-free latency.
Retain the watchdog restart delay of 3 seconds and limit of 5 starts in 60 seconds.

### Notifications

Notify only the initiating user's local graphical session. Determine identity at
startup; direct-root invocations need an explicit recipient. Do not guess when
the destination is missing or ambiguous. An unprivileged user agent delivers
events using the desktop notification protocol, through authenticated local IPC.
It has no authority to alter the firewall or session policy.

Notifications are recommended, optional and independently selectable. **A failed
notification alone does not request isolation.** Report the delivery error and
preserve any existing emergency state. CLI and journal remain available; neither
promises an unattended administrator will see an asynchronous failure.

Track pending, accepted by the notification server, unconfirmed and failed
delivery. A notification ID confirms acceptance, not display or human reading.
Timeout may mean acceptance occurred but its reply was lost. Do not block
emergency actions on delivery. A failed final stop notification never re-arms
protection after explicit teardown.

Events: completed start and stop; inconclusive verification; unavailable required
watchdog; valid negative Tor verification; verified killswitch; unconfirmed
isolation; verified recovery (which must not imply reopening a latched emergency).
Deduplicate an incident, update its notification and immediately announce a
severity increase. Request critical urgency and no expiration for emergencies,
subject to desktop support. Send concise consequences and diagnostic instructions,
not IPs, visited destinations, bridge secrets or complete logs. No notification
button changes network state.

### Diagnostic interface

Keep all concurrent errors with stable reason identifiers and structured
component, phase, operation and cause. Exit codes identify the principal result;
additional codes/reasons may be assigned without further maintainer approval.

| Code | Principal result |
| :--- | :--- |
| 0 | Requested command requirements satisfied |
| 1 | Other configuration or operation failure |
| 2 | CLI usage error |
| 3 | Inconclusive Tor verification |
| 4 | Explicit DNSSEC conflict before network changes (existing contract) |
| 5 | Required watchdog unavailable |
| 6 | Valid negative Tor verification |
| 7 | Emergency rules installed and verified |
| 8 | Required containment unconfirmed |
| 9 | Notification requirement/delivery failure |

Session-result precedence is 8, 7, 6, 5, 1, 9, 3, 0, with all contributing causes
retained. Code 4 is an initial refusal. Read-only status distinguishes successful
observation from the health of what it describes. Commands do not claim an exit
status can change after they have returned.

## Validation

Test the policy independently, then exercise CLI-visible results and artifacts.
Cover missing/stale/foreign observations, watchdog readiness and lost progress,
restart during emergency, stop-handler races, isolated kernel rules and failure
to apply/read them, and actual notification protocol acceptance/errors on a
private D-Bus. Run systemd lifecycle cases in disposable VMs/containers, never by
changing the developer host's firewall, resolver or desktop session.

## References

- [systemd service readiness and termination hooks](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [systemd heartbeat protocol](https://www.freedesktop.org/software/systemd/man/latest/sd_watchdog_enabled.html)
- [Desktop Notifications protocol](https://specifications.freedesktop.org/notification/latest/protocol.html)
- [Suspend-aware Linux clocks](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
