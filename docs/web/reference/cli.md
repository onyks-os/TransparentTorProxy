# Reference: CLI Command Line Interface

TTP provides a Typer-powered command-line interface. Most network-modifying commands require root privileges (`sudo`).

---

## 1. Commands Summary

| Command | Privileges | Description |
|---|---|---|
| [`sudo ttp start`](#sudo-ttp-start) | Root | Start transparent Tor proxying session with specified options. |
| [`sudo ttp stop`](#sudo-ttp-stop) | Root | Stop active proxying session and restore default system networking. |
| [`sudo ttp restart`](#sudo-ttp-restart) | Root | Restart active proxy session with new or updated options. |
| [`sudo ttp refresh`](#sudo-ttp-refresh) | Root | Send `NEWNYM` signal to Tor ControlPort to acquire a new exit IP circuit. |
| [`ttp status`](#ttp-status) | User | Display current session state, ports, IP address, and active options. |
| [`ttp check`](#ttp-check) | User | Verify SOCKS/DNSPort reachability, circuit status, and exit IP. |
| [`ttp check-leak`](#ttp-check-leak) | User | Run automated leak tests (Tor verification, dig A, Akamai TXT resolver identity). |
| [`sudo ttp diagnose`](#sudo-ttp-diagnose) | Root | Execute 7-layer system diagnostics and output troubleshooting report. |
| [`sudo ttp purge`](#sudo-ttp-purge) | Root | Remove volatile locks, stale nftables tables, `/etc/resolv.conf` mounts, and SELinux modules. |
| [`sudo ttp uninstall`](#sudo-ttp-uninstall) | Root | Alias for `purge`; cleanly uninstalls runtime modules and sentinels. |
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

Requests a new Tor exit IP circuit by issuing a `NEWNYM` signal via ControlPort.

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

Verifies SOCKS/DNSPort connectivity, Tor circuit status, public exit IP, and API latency.

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

### `sudo ttp purge`

Removes temporary `/run/ttp` state, stale lock files, leftover `nftables` tables, DNS bind mounts, and SELinux policy modules (`ttp-tor.cil`).

```text
Usage: ttp purge
```

---

### `sudo ttp uninstall`

Alias for `purge`; cleanly removes temporary runtime modules, locks, and sentinels.

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

Executes a target command bypassing `nftables` redirection inside a transient `systemd` scope (`ttp-bypass.slice`), dropping privileges to the invoking `SUDO_UID` / `SUDO_GID`.

```text
Usage: ttp bypass COMMAND [ARGS...]
```

---

### `sudo ttp watchdog <SUBCOMMAND>`

Manages the background Finite State Machine watchdog daemon.

```text
Usage: ttp watchdog [SUBCOMMAND]
```

| Subcommand | Description |
|---|---|
| `start` | Launch background watchdog daemon process. |
| `stop` | Stop background watchdog daemon process cleanly. |
| `status` | View background watchdog process status and PID. |

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
