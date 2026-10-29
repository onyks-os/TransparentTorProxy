<!-- Copyright (c) 2026 onyks-os; SPDX-License-Identifier: MIT -->

# Supervision, observations and optional notifications

This page describes the implemented 0.5.0 contract (unreleased). It does not change
the behavior of an installed 0.4.11 package.

## Select the capabilities you need

```bash
sudo ttp start --watchdog
sudo ttp start --watchdog --notifications
sudo ttp start --notifications --no-watchdog
```

The watchdog continuously checks local session integrity. Desktop notifications
deliver events to the initiating user's graphical session. They are independent:
without a watchdog, notifications cover explicit lifecycle and verification
commands, but there is no continuous source of fault events. A terminal-only
installation can use the watchdog without any desktop software.

A requested watchdog must become ready. Failure before network configuration
refuses startup; failure after configuration requests emergency containment.
The command reports an error even with `--quiet`. Notifications are optional:
their failure is reported, but never causes containment by itself.

For a direct root invocation, provide `--notification-user USER`. TTP requires
exactly one local graphical session belonging to that recipient; it does not
guess a desktop or broadcast to unrelated logged-in users. The recipient agent
runs without firewall capabilities and talks to the user's desktop notification
server. No network action is attached to a notification button.

## Understand what has actually been observed

```bash
sudo ttp status
sudo ttp status --json
sudo ttp check
sudo ttp config
sudo ttp config --session
```

`status` collects observations without making an external IP request or changing
network policy. Its successful exit means the observation command completed,
not that the session is healthy. A recorded session, PID or cached active flag
does not prove that supervision is progressing.

Local observations include session, boot and service-instance identity. Expired
or invalidated observations are unknown. Tor verification is a measurement at a
particular time, not a continuous guarantee. A failed DNS/TLS request, timeout or
malformed response is inconclusive. A valid negative Tor result from a correctly
non-exempt probe requests containment.

Emergency reporting distinguishes requested, application result and independent
verification of the expected kernel rules. An application error never suffices
to claim isolation. A restarted watchdog preserves the emergency latch.

Desktop delivery distinguishes pending, accepted, unconfirmed and failed. A
notification identifier proves that the desktop server accepted the call; it
does not prove display or human reading. Desktop policy can suppress a popup or
ignore a non-expiring request. Closing the terminal does not create another
alert channel: CLI output and the journal remain available for inspection, but
do not guarantee that an unattended user will notice a fault.

## Terminate an emergency deliberately

Close sensitive applications before running `sudo ttp stop`: removing protection
can allow them to reconnect outside Tor. Emergency mode remains latched until
explicit termination. `ttp watchdog stop` refuses to remove supervision that the
active session requires. A failure to deliver the final stop notification never
reinstates protection after explicit teardown.

## Configuration and exit codes

Copy the documented [configuration example](https://github.com/onyks-os/TransparentTorProxy/blob/main/assets/ttp.conf.example)
to `/etc/ttp/ttp.conf` if you need different timing budgets. The file must be
root-owned and not writable by group or others. Native packages also ship the
example under `/usr/share/doc/`; source installs retain it under `/opt/ttp/assets/`. Unknown options and inconsistent
deadlines are rejected before network changes. Effective settings are frozen for
the session; editing the file affects subsequent sessions. Explicit CLI flags
override the configuration, including `--no-watchdog` and `--no-notifications`.

| Code | Meaning |
| ---: | --- |
| 0 | Requested command requirements satisfied |
| 1 | Configuration or operation error |
| 2 | CLI usage error |
| 3 | Tor verification inconclusive |
| 4 | Explicit DNSSEC conflict before startup |
| 5 | Required watchdog unavailable |
| 6 | Valid negative Tor verification |
| 7 | Emergency rules verified |
| 8 | Required containment unconfirmed |
| 9 | Notification failure |

Concurrent causes are retained. Session-result precedence is `8 > 7 > 6 > 5 > 1 > 9 > 3 > 0`; for example, verified containment after watchdog failure returns 7 and
retains the watchdog cause. A returned command's exit status cannot change when
an asynchronous failure happens later.

See [ADR 0013](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0013-session-evidence-and-notifications.md)
for timing defaults and the approved contract. The underlying mechanisms follow
[systemd readiness and watchdog semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
and the [Desktop Notifications protocol](https://specifications.freedesktop.org/notification/latest/protocol.html).

## Troubleshoot delivery separately from protection

```bash
sudo journalctl -b -u ttp-watchdog.service -u ttp-notify.service
sudo ttp status --json
```

Notifications need `loginctl`, `busctl`, a local graphical login and a notification
server implementing `org.freedesktop.Notifications` on that user's bus. A missing
recipient, ambiguous sessions, a missing server or a rejected/timed-out call is
reported with code 9 and a stable `notifications.*` reason. TTP does not install
a desktop on a terminal-only host. Use `--no-notifications` there, or inspect the
journal from your existing operational monitoring system.

`check-leak` now uses the same typed Tor check. Its optional DNS answers are
informational: a missing `dig`, a timeout or an answer containing a resolver IP
does not establish a leak. Successful HTTP verification covers that request,
not every application's traffic.

A requested watchdog that cannot start produces code 5 before network setup, or
code 7/8 after containment is attempted. All contributing reasons remain visible.
If session intent is lost or corrupt, explicit `sudo ttp stop --restore-only`
publishes restoration intent before stopping services, so the independent
termination handler cannot re-arm protection afterward.

## Reproduce the service tests safely

The CI `session-services` job builds the Debian 13 fixture and runs
`scripts/check-session-services.sh`. It creates disposable Podman containers
with no external network, read-only source mounts and separate network
namespaces. The repository and host firewall/resolver are not modified.
The fixture needs `NET_ADMIN` and `SYS_ADMIN` inside the container for nftables,
DNS bind mounts and systemd sandbox setup. Do not run
`tests/fixtures/session_services.py` directly on a workstation.

The real-service cases cover readiness, SIGSTOP and SIGKILL, independent emergency
application and kernel verification, restart latching, tamper repair, explicit
stop, and an agent with the recipient UID and no capabilities. A private D-Bus
server tests ordinary/critical expiry, replacement IDs, duplicate suppression,
server disappearance and timeout after receipt. Its dummy Tor unit deliberately
does not test Tor transport. The separate NSE and VM lifecycle suites retain
that wider network-validation role.
