# Explanation: the session watchdog

The watchdog is an optional background service that checks, while a session is
running, that the session is still the one `ttp start` built, and contains it
when it is not. Select it with `sudo ttp start --watchdog` or `watchdog.enabled =
true` in `/etc/ttp/ttp.conf`; a [required-VPN session](../how-to/vpn.md) always
uses it. Without it, nothing watches a running session.

Since 0.5.0 a requested watchdog is a requirement, not a best effort: it must
show that it is evaluating, and a watchdog that stops, hangs or cannot evaluate
leads to containment. The contract is in
[ADR 0013](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0013-session-evidence-and-notifications.md).
The event subscriptions still live in the class described by
[ADR 0010](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0010-watchdog-finite-state-machine.md)
(`ttp/watchdog/fsm.py`), but its 0.4 state diagram (healthy, suspended, healing,
killswitch) no longer drives the loop: `ttp/watchdog/supervisor.py` does.

The timings below are the defaults. `sudo ttp config` shows the values in force,
and `sudo ttp config --session` the ones frozen into the running session.

---

## 1. How it runs

The service is a volatile systemd unit, `/run/systemd/system/ttp-watchdog.service`,
running `ttp watchdog run`:

- as the `ttp-watchdog` account when it exists, with only `CAP_NET_ADMIN` and
  `NoNewPrivileges=yes`. It can read the session lock but not write it, and it
  writes only to its own directory, `/run/ttp/watchdog`;
- as `Type=notify`: it reports **ready** only after its event subscriptions are
  in place and its first complete evaluation has finished (`readiness_timeout`,
  30 s). `ttp start` waits for that first healthy observation. A watchdog that
  does not become ready before the network is changed refuses the start; after
  that, it requests containment;
- with `WatchdogSec` (`service_timeout`, 30 s) and `SIGKILL`: it pings systemd
  between bounded steps, at least every `heartbeat_interval` (5 s), so a hung
  watchdog is killed rather than trusted;
- with `ExecStopPost=ttp watchdog terminated --session UUID`: whenever the
  process ends other than through an explicit `ttp stop`, this independent hook
  requests containment for that session;
- with `Restart=on-failure` and `Wants=ttp-tor.service`, not `Requires=`.
  Stopping Tor must not stop the process whose job is to notice that Tor stopped.

It does not poll. It sleeps in `select()` on two event sources and a timer:

| Source | Wakes it when |
| :--- | :--- |
| A netlink socket subscribed to nftables events | any nftables ruleset changes, TTP's or anyone else's |
| An inotify watch on `/etc/resolv.conf` (the path and its symlink target) | the DNS overlay is touched |
| A timer | `check_interval` (15 s) has passed since the last evaluation |

An event first marks the published observation as unknown, then triggers a full
evaluation at once. A table flushed or altered by another process reaches
containment in tens of milliseconds (31-48 ms measured; see section 4.3 of the
[security assessment](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/security-assessment.md)).
Losing an event subscription is itself a failure.

---

## 2. What it publishes

The watchdog writes its observation to `/run/ttp/watchdog`, where `ttp status`,
`ttp monitor` and `ttp check` read it. An observation belongs to one session,
boot and service instance, and expires after `observation_max_age` (30 s): an
old, foreign or unreadable observation counts as **no evidence**, never as
healthy.

| Observation | Meaning |
| :--- | :--- |
| `unknown` (`initializing`, `evaluation_pending`, `event_invalidated`) | An evaluation is pending or running. `ttp check` waits for it, for at most twice `check_timeout` plus `heartbeat_interval` (25 s). |
| `unknown` (`tor_healing`) | Tor failed and is being restarted. |
| `healthy` | The last evaluation passed every check below. |
| `emergency` | Containment is latched; see section 5. |

Each evaluation is bounded by `check_timeout` (10 s). One that does not finish in
time is a failure.

---

## 3. What is checked

Every evaluation runs the same checks, in this order. The first failure ends the
evaluation and names the component.

| Component | Check |
| :--- | :--- |
| `apparmor` | On AppArmor kernels, managed Tor is still confined in enforce mode by TTP's profile ([AppArmor](../how-to/apparmor.md)). A Tor that is not running counts as a `tor` failure, so that it can be restarted. |
| `vpn` | In a required-VPN session, the WireGuard profile, its device and TTP's VPN guard still match the frozen policy ([VPN before Tor](../how-to/vpn.md)). |
| `dns` | `/etc/resolv.conf` (or its symlink target) is still a mount point, and every `nameserver` in it is `127.0.0.1` or `::1`. |
| `dns` | If `systemd-resolved` was active at start: TTP's drop-in `/run/systemd/resolved.conf.d/ttp.conf` still exists and the service is still active. |
| `firewall` | The `inet ttp` table exists and matches, rule for rule, the fingerprint `ttp start` recorded in the lock. A chain-name check would pass a flushed table, which leaks everything. |
| `firewall` | Each bypass user and group recorded in the lock still resolves. |
| `firewall` | The DoT, DoH and un-redirected-DNS reject counters have not moved since the previous check. Those rules are only reachable when the NAT redirect has failed, so a new packet on any of them is an alarm about TTP itself ([ADR 0012](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0012-doh-dot-and-browser-leaks-are-out-of-scope.md)). |
| `tor` | Tor's control socket answers a `GETINFO`; if the socket is unavailable, `ttp-tor.service` is active. |

---

## 4. What happens on a failure

Only Tor is repaired. Everything else is treated as tampering.

| Failed component | Response |
| :--- | :--- |
| `tor` | One `systemctl restart ttp-tor.service`, bounded by `check_timeout`, then a full re-evaluation, AppArmor confinement included. If it passes, the observation returns to `healthy` and, with notifications enabled, a `recovered` notification is sent; otherwise, containment. |
| anything else | No repair is attempted: a table, overlay, profile or tunnel that changed under a running session is not something to guess back into shape. Straight to containment. |

---

## 5. Emergency containment

Containment is the same whoever requests it: the watchdog, its termination hook,
`ttp check` after a valid negative Tor answer, or `ttp start`. It runs in three
steps, in this order:

1. **Latch.** The request is recorded in a watchdog-owned record before anything
   else. Recovery never clears the latch, and it survives a watchdog restart.
2. **Apply.** `apply_emergency_killswitch()` replaces the `inet ttp` table, in
   one atomic transaction, with the ruleset below: everything is dropped in every
   direction except loopback.
3. **Verify.** The kernel ruleset is inspected independently. Applied *and*
   verified is reported as code `7`. Any doubt (the application failed, the rules
   do not match, the latch could not be written) is reported as code `8`,
   **containment unconfirmed**: an application that returned without error is
   never enough to claim isolation.

```text
table inet ttp {
    chain filter_out {
        type filter hook output priority filter; policy drop;
        oifname "lo" accept
    }
    chain filter_forward {
        type filter hook forward priority filter; policy drop;
    }
    chain filter_input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
    }
}
```

The containment is **held**, not fired and forgotten. While the latch is set, the
watchdog repeats it on every nftables event and at least every
`heartbeat_interval` (5 s): if the rules no longer verify, because the table was
removed or altered (an `accept` added to it empties it just as surely as
deleting it), they are applied again. The network stays down until the
administrator runs `sudo ttp stop`, which stops the watchdog first and then tears
the session down. `ttp restart` refuses while the emergency is latched, and
`ttp watchdog stop` refuses while the session requires supervision.

The result goes to the journal (`journalctl -u ttp-watchdog`), and
`sudo ttp status` shows requested, applied and verified separately. With
notifications enabled, the event also goes to the initiating user's desktop
through an unprivileged agent, once the rules are verified; the watchdog never
waits for the delivery. Without notifications nothing interrupts the user: a host
that suddenly has no network may be in containment, and `sudo ttp status` says
whether it is.
