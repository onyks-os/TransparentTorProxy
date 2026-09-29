# Reference: CLI Command Line Interface

TTP provides a Typer-powered command-line interface. Most network-modifying commands require root privileges (`sudo`).

---

## 1. Commands Summary

| Command | Privileges | Description |
|---|---|---|
| [`sudo ttp start`](#sudo-ttp-start) | Root | Start transparent Tor proxying session with specified options. |
| [`sudo ttp stop`](#sudo-ttp-stop) | Root | Stop active proxying session and restore default system networking. |
| [`sudo ttp restart`](#sudo-ttp-restart) | Root | Restart active proxy session with new or updated options. |
| [`sudo ttp refresh`](#sudo-ttp-refresh) | Root | Send `NEWNYM` to Tor over its control socket to get new circuits (and usually a new exit IP). |
| [`ttp status`](#ttp-status) | User | Display current session state, ports, IP address, and active options. |
| [`ttp check`](#ttp-check) | User | Confirm traffic exits through Tor; show exit IP, ports, IPv6 state and latency. |
| [`ttp check-leak`](#ttp-check-leak) | User | Run automated leak tests (Tor verification, dig A, Akamai TXT resolver identity). |
| [`sudo ttp diagnose`](#sudo-ttp-diagnose) | Root | Execute 7-layer system diagnostics and output troubleshooting report. |
| [`sudo ttp uninstall`](#sudo-ttp-uninstall) | Root | Stop any session, remove the SELinux module and TTP's markers; the package itself is removed separately. |
| [`ttp logs`](#ttp-logs) | User | Display recent volatile session logs from `/run/ttp/ttp.log`. |
| [`sudo ttp bypass <CMD...>`](#sudo-ttp-bypass-command) | Root | Execute target command outside Tor proxying in a transient `systemd` scope. |
| [`sudo ttp watchdog <SUBCOMMAND>`](#sudo-ttp-watchdog-subcommand) | Root | Manage background FSM integrity watchdog daemon (`start`, `stop`, `status`). |

---

## 2. Global Options

The following flags can be passed to the top-level `ttp` application before any subcommand:

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--verbose` | `-v` | Flag | `False` | Enable verbose debug logging output. |
| `--quiet` | `-q` | Flag | `False` | Suppress all Rich console banners and non-error output. |
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
| `--bootstrap-timeout` | | Integer | `180` | Timeout in seconds to wait for Tor circuit bootstrap. |
| `--transport-port` | `-t` | Integer | `9041` | Dedicated TCP port for Tor TransPort redirection. |
| `--dns-port` | `-d` | Integer | `9054` | Dedicated UDP/TCP port for Tor DNSPort redirection. |
| `--allow-root` | | Flag | `False` | Allow root processes to bypass Tor routing (increases leak risk). |
| `--no-lan-bypass` | | Flag | `False` | Route local RFC 1918 subnets through Tor instead of bypassing. |
| `--watchdog` | `-w` | Flag | `False` | Launch background FSM integrity watchdog daemon. |
| `--bypass-user` | | List[String] | `None` | System user(s) to bypass Tor routing (can be specified multiple times). |
| `--bypass-group` | | List[String] | `None` | System group(s) to bypass Tor routing (can be specified multiple times). |
| `--use-bridges` | | Flag | `False` | Globally enable Tor bridges support. |
| `--bridge-file` | | Path | `None` | Path to a text file containing Tor bridge lines. |
| `--bridge` | | List[String] | `None` | Individual Tor bridge line (can be specified multiple times). |
| `--external-daemon` | | Flag | `False` | BYOD mode: delegate Tor process lifecycle management to host. |
| `--tor-uid` | | String | `None` | Specify numeric UID or username of host Tor process in BYOD mode. |
| `--no-ipv6` | | Flag | `False` | Enforce outbound IPv6 drop policy to prevent IPv6 leaks. |

---

### `sudo ttp stop`

Stops the transparent Tor proxy session and restores default system networking.

```text
Usage: ttp stop [OPTIONS]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--restore-only` | Flag | `False` | Force network restoration even if session lock is missing or crashed. |

---

### `sudo ttp restart`

Restarts the active proxy session. Accepts all options supported by `sudo ttp start`.

```text
Usage: ttp restart [OPTIONS]
```

---

### `sudo ttp refresh`

Requests new Tor circuits by sending `NEWNYM` over Tor's control socket
(`/run/tor/ttp/control.sock`). New connections then usually leave from a different
exit.

```text
Usage: ttp refresh
```

---

### `ttp status`

Displays the current TTP session state, active ports, public exit IP, watchdog status, and active bypass settings.

```text
Usage: ttp status
```

---

### `ttp check`

Asks `check.torproject.org` whether traffic reaches it through Tor (retrying, with
`api.ipify.org` and `ifconfig.me` as fallbacks for the IP only - only
`check.torproject.org` may assert that the IP is a Tor exit), then prints the exit IP,
the TransPort and DNSPort, the IPv6 state and the latency.

```text
Usage: ttp check
```

---

### `ttp check-leak`

Runs automated network leak detection probes (Tor exit validation, dig A lookup, Akamai TXT resolver identity).

```text
Usage: ttp check-leak
```

Exits with code `0` if no leaks are detected, or code `1` if leaks or unreachable endpoints are detected.

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

### `ttp logs`

Outputs the contents of the volatile session log file (`/run/ttp/ttp.log`).

```text
Usage: ttp logs
```

---

### `sudo ttp bypass <COMMAND...>`

Executes a command outside Tor, in a transient `systemd` scope in `ttp-bypass.slice` that TTP's ruleset exempts by cgroup. The command runs as the invoking `SUDO_UID` / `SUDO_GID`, wrapped in `setpriv --init-groups` so that it does not inherit root's supplementary groups. Its traffic, DNS included, leaves in cleartext.

```text
Usage: ttp bypass COMMAND [ARGS...]
```

---

### `sudo ttp watchdog <SUBCOMMAND>`

Manages the background integrity watchdog. See [Watchdog FSM](../explanation/watchdog-fsm.md) for what it checks and how it responds.

```text
Usage: ttp watchdog [SUBCOMMAND]
```

| Subcommand | Description |
|---|---|
| `start` | Launch background watchdog daemon process. |
| `stop` | Stop background watchdog daemon process cleanly. |
| `status` | Show whether the watchdog unit is running, and its PID. |

---

## 4. CLI Exit Codes

TTP commands exit with standard status codes for scripting and automation:

| Code | Meaning | Context |
|:---:|---|---|
| `0` | **Success** | Command completed successfully, or system already in target state. For `start` and `restart`, the session is active and Tor routing was confirmed. |
| `1` | **Error / Failure** | Preflight check failure, missing root privileges, or system error. For `start` and `restart`, no session is running and the network is in cleartext. |
| `2` | **Usage error** | Reserved by the CLI framework: unknown option or invalid argument value. |
| `3` | **Unverified session** | `start` / `restart` only. The session is active and fail-closed, but Tor routing could not be verified. Traffic that is not explicitly bypassed is blocked. |

!!! warning "Scripting Tip"
    Do not read "non-zero" as "unprotected", or `0` as the only safe outcome.
    `3` means the kill-switch is holding and nothing is leaking — the session is
    simply not carrying traffic. `1` is the one that means the host is back on
    clearnet. Pass `-v` for structured error diagnostics.
