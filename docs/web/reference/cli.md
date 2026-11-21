# Reference: CLI Command Line Interface

TTP provides a Typer-powered command-line interface. Every command that reads or
changes the session needs root (`sudo`): the session state in `/run/ttp` and the
log are readable only by root, because they record the interface, the bypassed
users and Tor's UID. A command run without the privileges it needs says so and
exits with `1`; it never reports an unreadable session as inactive.

---

## 1. Commands Summary

| Command | Privileges | Description |
|---|---|---|
| [`sudo ttp start`](#sudo-ttp-start) | Root | Start a transparent Tor proxy session. |
| [`sudo ttp stop`](#sudo-ttp-stop) | Root | End the session and restore the network. |
| [`sudo ttp restart`](#sudo-ttp-restart) | Root | Stop the session and start a new one with new or updated options. |
| [`sudo ttp refresh`](#sudo-ttp-refresh) | Root | Send `NEWNYM` to Tor over its control socket to get new circuits (and usually a new exit IP). |
| [`sudo ttp status`](#sudo-ttp-status) | Root (see below) | Show the recorded session from local evidence; no network request. |
| [`sudo ttp monitor`](#sudo-ttp-monitor) | Root | Watch the same evidence in a terminal, with the changes seen while it is open. |
| [`sudo ttp check`](#sudo-ttp-check) | Root | Verify now, from a non-exempt process, that traffic reaches Tor. |
| [`sudo ttp check-leak`](#sudo-ttp-check-leak) | Root | `check`, plus informational DNS observations. |
| [`sudo ttp config`](#sudo-ttp-config) | Root | Show the validated settings and where each value comes from. |
| [`sudo ttp diagnose`](#sudo-ttp-diagnose) | Root | Run a 7-layer system diagnostic and print a troubleshooting report. |
| [`sudo ttp uninstall`](#sudo-ttp-uninstall) | Root | Stop any session, remove the SELinux module and TTP's markers; the package itself is removed separately. |
| [`sudo ttp logs`](#sudo-ttp-logs) | Root | Print the volatile session log, `/run/ttp/ttp.log`. |
| [`sudo ttp bypass <CMD...>`](#sudo-ttp-bypass-command) | Root (via `sudo`) | Run a command outside Tor in a transient `systemd` scope. |
| [`sudo ttp watchdog <SUBCOMMAND>`](#sudo-ttp-watchdog-subcommand) | Root | Start, stop or inspect the session watchdog. |

Without root, `ttp status` works only when no session has run since boot
(`/run/ttp` does not exist): it then reports `INACTIVE`. After any session it
asks for `sudo` and exits with `1`.

TTP has no `--version` option: use your package manager (`rpm -q
transparent-tor-proxy`, `dpkg-query -W transparent-tor-proxy`, `pipx list`).

---

## 2. Global Options

The following flags can be passed to the top-level `ttp` application before any subcommand:

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--verbose` | `-v` | Flag | `False` | Enable verbose debug logging output. |
| `--quiet` | `-q` | Flag | `False` | Suppress all output except errors. A required watchdog's failure is reported even with `--quiet`. |
| `--log-format` | | String | `text` | Output log format (`text` or `json`). |
| `--help` | | Flag | | Display CLI help message and exit. |

---

## 3. Comprehensive Command Reference

### `sudo ttp start`

Starts the transparent Tor proxy session.

```text
Usage: ttp start [OPTIONS]
```

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--interface` | `-i` | String | Auto-detected | Network interface to configure DNS on. |
| `--bootstrap-timeout` | | Integer | `180` | Seconds to wait for Tor to bootstrap. |
| `--transport-port` | `-t` | Integer | `9041` | Port for Tor's TransPort redirect. |
| `--dns-port` | `-d` | Integer | `9054` | Port for Tor's DNSPort redirect. |
| `--allow-root` | | Flag | `False` | Let root's processes bypass Tor (increases leak risk). |
| `--no-lan-bypass` | | Flag | `False` | Route local RFC 1918 and link-local subnets through Tor instead of bypassing them. |
| `--watchdog` / `--no-watchdog` | `-w` | Flag | `watchdog.enabled` (off) | Require the session watchdog. A requested watchdog must become ready, or the start fails. |
| `--bypass-user` | | List[String] | `None` | System user(s) whose traffic bypasses Tor. Repeat the option or separate names with commas. |
| `--bypass-group` | | List[String] | `None` | System group(s) whose traffic bypasses Tor. Repeat the option or separate names with commas. |
| `--use-bridges` | | Flag | `False` | Enable Tor bridges. |
| `--bridge-file` | | Path | `None` | Text file with Tor bridge lines. Under `sudo` or `pkexec` it is read with the caller's permissions, not root's. |
| `--bridge` | | List[String] | `None` | One Tor bridge line; can be repeated. |
| `--external-daemon` | | Flag | `False` | BYOD mode: use a Tor managed by the host instead of TTP's own instance. |
| `--tor-uid` | | String | `None` | Numeric UID or user name of the host's Tor process in BYOD mode. |
| `--no-ipv6` | | Flag | `False` | Drop all outgoing IPv6 instead of routing it through Tor. |
| `--notifications` / `--no-notifications` | | Flag | `notifications.enabled` (off) | Send session events to the initiating user's desktop. Independent of the watchdog. |
| `--notification-user` | | String | `None` | Desktop recipient. Required when root runs `ttp` directly rather than through `sudo`; needs notifications enabled. |
| `--require-vpn` | | UUID | `None` | Require an active, full-tunnel NetworkManager WireGuard profile before Tor. Needs `--watchdog` and `--no-lan-bypass`, managed Tor, and no root, user or group bypass. See [VPN before Tor](../how-to/vpn.md). |

The defaults for the watchdog and notifications come from the optional
`/etc/ttp/ttp.conf`; an explicit flag overrides it. See
[`sudo ttp config`](#sudo-ttp-config).

TTP never installs packages. If Tor, or a pluggable transport that the bridges
need, is missing, `start` prints the package to install and exits with `1`
without changing the network.

---

### `sudo ttp stop`

Stops the transparent Tor proxy session and restores default system networking.
Close sensitive applications first: once protection is removed they can
reconnect outside Tor. This is also the only way out of a latched emergency.

```text
Usage: ttp stop [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--restore-only` | Flag | `False` | Force network restoration even if TTP is crashed or no session is active. Also releases a retained VPN guard. |

---

### `sudo ttp restart`

Stops the active session and starts a new one. It accepts the options of
`sudo ttp start` except `--require-vpn`.

```text
Usage: ttp restart [OPTIONS]
```

Before stopping anything it checks the DNSSEC policy and the settings, so a
refusal leaves the current session in place. It refuses:

- a required-VPN session (code `10`): a restart would leave an unprotected
  interval, so stop and start it explicitly;
- a session with a latched emergency (code `7`): end it with `sudo ttp stop`.

If the new session then fails to start, the old one is already gone and the host
is in cleartext; the exit code says so.

---

### `sudo ttp refresh`

Requests new Tor circuits by sending `NEWNYM` over Tor's control socket
(`/run/tor/ttp/control.sock`). New connections then usually leave from a different
exit.

```text
Usage: ttp refresh
```

---

### `sudo ttp status`

Reports the recorded session from local evidence only: the session phase, the
**last** Tor verification and its age, the watchdog's progress, emergency
containment and its kernel verification, notification delivery, the VPN and
AppArmor observations when they apply, active diagnostic reasons, and the
rejected-packet counter. It makes no network request and changes nothing.

```text
Usage: ttp status [--json]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--json` | Flag | `False` | Print the observations as JSON, for scripts. |

Exit code `0` means the observation completed, not that the session is healthy:
read the reported state. A recorded session, PID or cached flag does not prove
that supervision is progressing. See
[Supervision and notifications](../how-to/session-observations.md).

---

### `sudo ttp monitor`

Refreshes the same passive evidence as `status` in an interactive terminal, and
keeps a short timeline (at most six changes) of what changed while it is open. It
has no earlier history and resets for a new session. It sends no Tor or DNS
probe and changes no policy.

```text
Usage: ttp monitor [--interval SECONDS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--interval` | Float, 2–60 | `5` | Seconds between observations. |

It needs a terminal on both stdin and stdout; for scripts or redirected output,
use `sudo ttp status --json`. Ctrl-C or `SIGTERM` closes the view without ending
the session, with exit code `0`, which says nothing about session health.

---

### `sudo ttp check`

Asks `check.torproject.org`, from a process that TTP's rules do not exempt,
whether the request arrived through Tor. It retries, and uses `api.ipify.org` and
`ifconfig.me` only as fallbacks for the IP: only `check.torproject.org` may
assert that the IP is a Tor exit. It then prints the result, the TransPort and
DNSPort, the IPv6 state and the active diagnostics.

```text
Usage: ttp check
```

A failed or malformed request is **inconclusive** (code `3`), not proof of a leak.
A valid **negative** answer means traffic reached the internet outside Tor: TTP
requests emergency containment, and the code is `7` or `8`. With a required
watchdog, `check` also requests containment when supervision has no current
evidence of progress. See [exit codes](#4-cli-exit-codes).

---

### `sudo ttp check-leak`

Runs `sudo ttp check`, then, if `dig` is installed, two informational DNS
observations: an `A` lookup of `check.torproject.org` and the resolver identity
from `whoami.ipv4.akahelp.net`.

```text
Usage: ttp check-leak
```

It returns the exit code of `check`; the DNS observations do not change it. A
failed DNS observation is reported as inconclusive. A `0` confirms Tor for that
request only; it is not proof that every application is leak-free. Without an
active session it exits with `1`.

---

### `sudo ttp config`

Prints the validated settings from `/etc/ttp/ttp.conf` and the built-in defaults,
with the origin of each value. The file is optional, must be root-owned and not
writable by group or others, and unknown keys or inconsistent deadlines are
rejected before any network change.

```text
Usage: ttp config [--session]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--session` | Flag | `False` | Show the settings frozen into the running session instead. Editing the file affects only later sessions. |

See the [configuration example](https://github.com/onyks-os/TransparentTorProxy/blob/main/assets/ttp.conf.example).

---

### `sudo ttp diagnose`

Executes a 7-layer diagnostic scan (OS, Tor service, torrc, nftables, DNS, ControlPort, TTP internal state) and prints a Rich formatted report.

```text
Usage: ttp diagnose
```

---

### `sudo ttp uninstall`

Stops an active session, removes the `ttp_tor_policy` SELinux module if it is
installed, and deletes TTP's markers in `/var/lib/ttp`. It does not remove the
package or its files: use the package manager or `scripts/uninstall.sh` for that.

```text
Usage: ttp uninstall
```

---

### `sudo ttp logs`

Prints the volatile session log, `/run/ttp/ttp.log`. The file is `0600` and is
removed at reboot. Without root it says so and exits with `1`; with no log it
exits with `1` too.

```text
Usage: ttp logs
```

---

### `sudo ttp bypass <COMMAND...>`

Executes a command outside Tor, in a transient `systemd` scope in `ttp-bypass.slice` that TTP's ruleset exempts by cgroup. The command runs as the invoking `SUDO_UID` / `SUDO_GID`, wrapped in `setpriv --init-groups` so that it does not inherit root's supplementary groups. Its traffic, DNS included, leaves in cleartext.

It must be run through `sudo`: TTP needs `SUDO_UID` and `SUDO_GID` to know whom
to run the command as.

```text
Usage: ttp bypass COMMAND [ARGS...]
```

---

### `sudo ttp watchdog <SUBCOMMAND>`

Manages the session watchdog. See [Watchdog](../explanation/watchdog-fsm.md) for what it checks and how it responds.

```text
Usage: ttp watchdog [SUBCOMMAND]
```

| Subcommand | Description |
|---|---|
| `start` | Start the watchdog for the active session. Exits with `5` if it cannot be configured or does not become ready. |
| `stop` | Stop the watchdog. Refused while the active session requires supervision: end such a session with `sudo ttp stop`. |
| `status` | Show whether the watchdog unit is running, and its PID. It re-probes the unit instead of trusting the lock. |

---

## 4. CLI Exit Codes

The codes are the same for every command. When several causes apply at once, all
of them are reported and the code with the highest precedence is returned:
`8 > 7 > 6 > 10 > 5 > 1 > 9 > 3 > 0`. Codes `2` and `4` are refusals before
anything changes.

| Code | Meaning | What it says about the network |
|:---:|---|---|
| `0` | **Requirements satisfied** | For `start` and `restart`: the session is active and Tor was confirmed. For `status` and `monitor`: only that the observation completed. |
| `1` | **Error** | A configuration or operation failure: no root, unreadable session state, Tor or a required transport not installed, a setup step failed. A failed `start` restores the network, so the host is in **cleartext**. |
| `2` | **Usage error** | Unknown option, invalid value or inconsistent selection (for example `--notification-user` without notifications). Nothing changed. |
| `3` | **Tor verification inconclusive** | `start`, `restart`, `check`: the session is installed and fail-closed, but the external check could not answer (network error, timeout, malformed reply). Neither proof of a leak nor proof that Tor carries traffic. |
| `4` | **DNSSEC conflict** | An interface explicitly requires `DNSSEC=yes`. `start` is refused before any network change; `restart` keeps the existing session. See [DNSSEC policy](../how-to/dnssec.md). |
| `5` | **Required watchdog unavailable** | Before network changes, the start is refused. After them, containment is requested and its result (`7` or `8`) takes precedence. |
| `6` | **Tor verification negative** | A correctly non-exempt request reached the internet outside Tor. Containment is requested and its result (`7` or `8`) takes precedence. |
| `7` | **Emergency verified** | The emergency rules are in the kernel and were verified: everything except loopback is dropped. Latched until `sudo ttp stop`. |
| `8` | **Containment unconfirmed** | Containment was required but TTP cannot show it is in place. Treat the host as possibly leaking: close sensitive applications and run `sudo ttp stop`. |
| `9` | **Notification failure** | Notification selection, readiness or delivery failed. Never causes containment by itself; read the other causes. |
| `10` | **Required VPN unavailable, or operation refused** | The required VPN profile is missing, inactive or unsupported; or the operation would weaken VPN protection (`restart` of a VPN session, a retained VPN guard). See [VPN before Tor](../how-to/vpn.md). |

!!! warning "Scripting Tip"
    Do not infer protection from the exit code alone, and never test only for
    `$? -eq 0`: `3` and `7` mean the host is blocked, not leaking; `1` after a
    failed start means cleartext; `8` means unknown. Read `sudo ttp status --json`
    for the full set of causes. See
    [Automation & Scripts](../tutorials/automating-sessions.md).
