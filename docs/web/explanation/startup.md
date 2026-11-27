<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# Explanation: Startup Phases and Their Failure Contract

`ttp start` does not protect the host from the moment it is invoked. It
changes the system in a fixed order, and what a failure or an interruption
leaves behind depends on how far it got. This page states that contract, phase
by phase, from the code in `ttp/commands/start.py`. It is the reference that
L01 of the [leak-testing plan](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/security/leak-testing-plan.md)
measures against.

**Status:** each failure and interruption outcome below has a unit test
(`tests/test_cli_start.py`). Where the first barrier falls, and what crosses
the wire before it, has not yet been measured from outside a VM. That is L01's
external part, which waits for the continuous capture of slice 3.

## The two halves

Startup has two halves, and they fail differently.

- **Before the session is recorded** (phases 1 to 4), a failure undoes
  everything start did and leaves the host in cleartext, deliberately. A failed
  start is not turned into a lockdown: nothing would record it, and nothing
  would tell `ttp stop` or `ttp status` that it exists.
- **After the session is recorded** (phases 5 to 7), the session exists. A
  failure no longer rolls back. It either leaves the session configured and
  says so with a nonzero exit code, or requests emergency containment, which
  holds until an explicit `ttp stop`.

No outcome that leaves the host unprotected exits `0`.

## Phases

| Phase | What changes | Traffic of an ordinary process | On failure | On SIGINT / SIGTERM |
| :--- | :--- | :--- | :--- | :--- |
| 0. Preflight | Nothing on the network. Settings, options, root and systemd, ports, DNSSEC, the session state (an orphan left by a crashed session is recovered here), a retained VPN guard, the record store | Cleartext | Exit `1`, `2`, `4` or `10`; nothing changed | Exit `1`; an orphan recovery in progress is completed by stopping what it found |
| 1. Tor | Managed mode: Tor is installed if needed and `ttp-tor` starts. Required-VPN mode: the VPN guard is installed **before** Tor starts, and is the first barrier. External daemon: only its UID is resolved | Cleartext (required-VPN: confined to the tunnel by the guard) | Exit `1` (Tor or a pluggable transport missing: exit `1` since 0.5.1) | Undone like `stop --restore-only`, exit `1`; a VPN guard is retained, exit `10` |
| 2. Rules | The `inet ttp` table, in **one** `nft` transaction: the first barrier outside required-VPN mode | Redirected to Tor or rejected from the commit on, DNS included (redirected to the DNSPort) | Own Tor stopped, table destroyed: cleartext, exit `1` | As phase 1 |
| 3. DNS | The resolver overlay on `/etc/resolv.conf`, and the systemd-resolved drop-in | As phase 2 | `apply_dns` undoes its own partial change; own Tor stopped, table destroyed: cleartext, exit `1` | As phase 1; the overlay is found on the host, so a half-applied one is removed too |
| 4. Session record | The session lock, with the fingerprint of the table the watchdog must find | As phase 2 | Own Tor stopped, table destroyed, DNS restored: cleartext, exit `1` | As phase 1 |
| 5. Notifications | The desktop agent, if selected | Contained | Session kept, exit `9` | Session stopped, exit `1` |
| 6. Watchdog | Required watchdog readiness, if selected | Contained | Emergency containment requested and latched, exit nonzero | Session stopped, exit `1`; a latched emergency is retained, exit `8` |
| 7. Verification | Nothing; Tor routing is checked from outside | Contained | Inconclusive: session kept, exit `3`. Negative: emergency containment | As phase 6 |

"Undone like `stop --restore-only`" means that start derives what to undo from
the host instead of a session record. It stops the managed Tor and closes the
connections redirected during the start while the rules still hold them. If
one cannot be closed, the rules stay and start exits `8`. Then it removes the
table and the DNS overlay. An external Tor (`--external-daemon`) is never
stopped.

## Interruptions

The signal handler does not undo anything itself. It runs between two
bytecodes of whatever start was doing, possibly while an `nft` or `systemctl`
child is still running, so a teardown there could remove the table before that
child loads it. It raises `StartInterrupted` instead. The call in flight
unwinds first (`subprocess.run` kills and reaps its child), and only then does
start undo itself. A second Ctrl-C during the undo is ignored.

Until the release after 0.5.1, an interruption in phases 1 to 4 found no session record and
undid nothing. The table, the overlay and Tor stayed in place. `ttp status`
reported `INACTIVE` and `ttp stop` reported that no session was found. Start
exited `0`, so a script that trusted it believed the host was protected.
After phase 4 the session was stopped, but start still exited `0`.

## What this contract does not claim

- **Protection before phase 2.** Applications that run while Tor starts send
  in cleartext, unless the required VPN guard is in place.
- **That a connection opened before `ttp start` is moved into Tor.** It is
  ended at its next packet; see [Architecture](architecture.md).
- **Anything about `SIGKILL` or a power loss during startup.** Nothing runs.
  A table without a session record (phases 2 to 4) stays until `ttp stop
  --restore-only`. A recorded session stays until `ttp stop`, and the next
  `ttp start` refuses to run until then. A power loss ends both, because the
  rules and the record live only in memory and `/run`.
