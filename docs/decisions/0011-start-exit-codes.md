<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# ADR 0011: Distinct Exit Code for an Unverified Session

## Status

Accepted (v0.4.9)

## Context

`ttp start` builds a session in five ordered steps: detect and start Tor (1), apply the
nftables ruleset (2), install the DNS overlay (3), write the lock file (4), and only then
wait for Tor to finish bootstrapping and confirm that traffic is actually leaving through
it (5).

That ordering is deliberate — the ruleset must exist before any packet can move, so the
kill-switch is in place before Tor is asked to do anything. Its consequence is that a Tor
failure lands in one of two very different places:

| Where it fails | Rules applied? | Resulting host state |
| :------------- | :------------- | :------------------- |
| Step 1, the `ttp-tor` unit will not start | No | Plain clearnet |
| Step 5, the unit runs but never bootstraps | Yes | Fail-closed, traffic blocked |

Until now both exited in a way a caller could not act on. Step 1 raised `typer.Exit(1)`.
Step 5 printed a yellow warning and then **fell through to the end of the function,
exiting `0`** — reporting success for a host whose network was entirely blocked.

`ttp restart` makes this sharp. It tears the current session down before calling `start`,
so `ttp restart && some_command` would proceed onto a blocked network in the step 5 case
and stop in the step 1 case, where connectivity was in fact fine. The exit code said the
opposite of the truth in both directions.

It is worth being precise about what was *not* broken: the security posture was correct in
both windows. Step 5 leaves the host fail-closed, step 1 leaves it in the known-good
pre-TTP state required by the crash-safety goal. The defect was purely in the signal — the
two outcomes were indistinguishable to anything that was not a human reading the terminal.

## Decision

We decided to give an established-but-unverified session its own exit code, and to define
the three outcomes of `ttp start` (and therefore of `ttp restart`) as a stable contract:

| Code | Meaning | Host state |
| :--- | :------ | :--------- |
| `0` | Session active, routing through Tor confirmed | Protected |
| `1` | Start failed and gave up | Restored to cleartext |
| `3` | Session active, Tor unverified | Fail-closed, traffic blocked |

The session is **not** torn down on code `3`. Tearing it down would convert a blocked
network into an unannounced cleartext one, which is the worse of the two failures; leaving
it standing keeps the kill-switch engaged and lets the operator decide. The watchdog, if it
was requested, is still started before the exit is raised — an unverified session is
precisely the one that benefits from being watched.

### Alternatives Considered

| Alternative | Why it was rejected |
| :---------- | :------------------ |
| Keep exiting `0` and rely on the printed warning | Unreadable to scripts, CI, and systemd units, which is where the confusion actually causes damage. |
| Exit `1`, same as a hard failure | Collapses "blocked" and "cleartext" into one code. Those demand opposite responses from the caller, so they cannot share a code. |
| Exit `2` | Click already uses `2` for usage errors. A script could not tell a mistyped flag from a blocked network. |
| Tear the session down and exit `1` | Turns a fail-closed host into a silently clearnet one on a transient bootstrap timeout. Directly contrary to the project's primary guarantee. |

## Consequences

* **Pros**:
  * `ttp restart && …` can no longer proceed onto a blocked network believing it succeeded.
  * The two failure windows become distinguishable without parsing terminal output.
  * The fail-closed guarantee is now *stated* by the interface, not only by the firewall.
* **Cons**:
  * Observable behaviour change. Anything treating a non-zero exit as fatal will now stop
    on an unverified session where it previously continued — which is the intent, but it
    will surface in existing scripts and CI without warning.
  * A third code is a third thing for a caller to handle.
* **Neutral / follow-up work**:
  * `docs/security-assessment.md` previously claimed a bootstrap failure was fail-closed
    "because nftables rules are already applied". That is true only of the step 5 window;
    the row has been split so both windows are described.
  * The recovery path is now covered by tests that assert *which* of the two states the
    host ends in, rather than only that the command failed.

## References

* Issue [#23](https://github.com/onyks-os/TransparentTorProxy/issues/23)
* [ADR 0003](0003-watchdog-emergency-killswitch.md) — fail-closed killswitch policy.
* `ttp/commands/start.py`, `ttp/commands/stop_restart.py`, `ttp/commands/_common.py`
