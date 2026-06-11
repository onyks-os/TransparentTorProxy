# TTP – External Interfaces Reference

This document describes all external interfaces exposed by Transparent Tor Proxy (TTP): the command-line interface, integration points with the Tor daemon, and integration with Linux kernel subsystems.

> **Audience:** contributors, security auditors, and packagers who need to understand how TTP interacts with the outside world.

---

## Table of Contents

1. [Command Line Interface (CLI)](#1-command-line-interface-cli)
2. [Tor Integration](#2-tor-integration)
3. [System Integration](#3-system-integration)
4. [External Network Endpoints](#4-external-network-endpoints)

---

## 1. Command Line Interface (CLI)

TTP exposes a single binary entry point `ttp`, implemented via [Typer](https://typer.tiangolo.com/) in `ttp/cli.py`.

### 1.1 Invocation

```
ttp [COMMAND] [OPTIONS]
```

Most commands require root privileges (`sudo`). Exceptions are noted in the table below.

### 1.2 Command Reference

| Command               | Requires Root | Description                                                                                                                                                  |
| :-------------------- | :-----------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ttp start`           |       ✅       | Activates the transparent Tor proxy: installs Tor if missing, applies nftables rules, mounts DNS overlay, waits for Tor bootstrap, and verifies the exit IP. |
| `ttp stop`            |       ✅       | Graceful teardown: sends `SHUTDOWN` to Tor, removes nftables rules, unmounts DNS overlay, and deletes the session lock file.                                 |
| `ttp restart`         |       ✅       | Shortcut for `ttp stop` followed by `ttp start`. Accepts all `start` options.                                                                                |
| `ttp refresh`         |       ✅       | Requests a new Tor circuit via `NEWNYM` signal. All active streams are rotated for a new exit IP.                                                            |
| `ttp status`          |       ❌       | Displays current session state from the lock file: status, exit IP, session start time, and PID.                                                             |
| `ttp check`           |       ❌       | Live network check: verifies the real-world Tor routing state, current IP, `IsTor` flag, and latency to `torproject.org`.                                    |
| `ttp check-leak`      |       ❌       | Runs DNS and IP leak detection tests. Use `-v`/`--verbose` for raw output.                                                                                   |
| `ttp logs`            |       ✅       | Streams real-time content from the volatile log at `/run/ttp/ttp.log`.                                                                                       |
| `ttp diagnose`        |       ✅       | Collects full system diagnostics: OS info, Tor service status, active torrc, nftables ruleset, and DNS state.                                                |
| `ttp uninstall`       |       ✅       | Removes TTP system-wide (only applicable to source installs via `scripts/install.sh`).                                                                       |
| `ttp watchdog start`  |       ✅       | Manually starts the background session integrity watchdog as a volatile systemd service.                                                                     |
| `ttp watchdog stop`   |       ✅       | Manually stops the watchdog service.                                                                                                                         |
| `ttp watchdog status` |       ❌       | Shows the current state of the watchdog daemon (active/inactive, PID).                                                                                       |
| `ttp watchdog run`    |       ✅       | **Internal command.** Runs the continuous integrity monitoring loop (invoked by the watchdog service unit).                                                  |

### 1.3 `ttp start` Options

| Option                | Type  | Default     | Description                                                                                   |
| :-------------------- | :---- | :---------- | :-------------------------------------------------------------------------------------------- |
| `--interface`, `-i`   | `str` | Auto-detect | Network interface for DNS overlay (e.g. `eth0`, `wlan0`).                                     |
| `--bootstrap-timeout` | `int` | `180`       | Seconds to wait for Tor to reach 100% bootstrap before aborting.                              |
| `--allow-root`        | flag  | off         | Exempt root (`uid 0`) processes from Tor routing (allows direct internet for system updates). |
| `--no-lan-bypass`     | flag  | off         | Disable LAN bypass: all RFC 1918 and link-local traffic is also routed through Tor.           |
| `--watchdog`, `-w`    | flag  | off         | Start the background session integrity watchdog daemon after activation.                      |
| `--bypass-user`       | `str` | —           | Comma-separated list of system users whose traffic bypasses Tor (split tunneling).            |
| `--bypass-group`      | `str` | —           | Comma-separated list of system groups whose traffic bypasses Tor (split tunneling).           |

### 1.4 Exit Codes

| Code | Meaning                                        |
| :--- | :--------------------------------------------- |
| `0`  | Success                                        |
| `1`  | Generic error (printed to stderr)              |
| `2`  | Invoked without root privileges where required |

---

## 2. Tor Integration

TTP manages a **dedicated, isolated Tor instance** via a volatile systemd service (`ttp-tor.service`). It does **not** interact with or modify any pre-existing system `tor.service`.

### 2.1 Managed Tor Ports

| Port            | Protocol    | Role                                                                                                      | Default                     | Configurable                      |
| :-------------- | :---------- | :-------------------------------------------------------------------------------------------------------- | :-------------------------- | :-------------------------------- |
| `TransPort`     | TCP         | Transparent proxy: receives redirected application traffic from nftables                                  | `9041`                      | Via `--transport-port` (internal) |
| `DNSPort`       | UDP         | Tor's internal DNS resolver: receives DNS queries redirected from port 53                                 | `9054`                      | Via `--dns-port` (internal)       |
| `ControlSocket` | Unix socket | Authenticated control interface used by `stem` for bootstrap monitoring, `NEWNYM`, and `SHUTDOWN` signals | `/run/tor/ttp/control.sock` | No                                |

> **Note:** Ports `9041` and `9054` are intentionally non-standard to avoid conflicts with existing Tor service instances that may use the default ports `9040` and `5353`.

### 2.2 Tor Control Protocol

TTP communicates with the Tor daemon via the **Tor Control Protocol** (see [Tor control spec](https://spec.torproject.org/control-spec)) using the Python [`stem`](https://stem.torproject.org/) library.

| Operation         | Signal/Command                     | Trigger            |
| :---------------- | :--------------------------------- | :----------------- |
| Authenticate      | `COOKIE` auth via `CookieAuthFile` | At session start   |
| Monitor bootstrap | `GETINFO status/bootstrap-phase`   | During `ttp start` |
| Rotate circuits   | `SIGNAL NEWNYM`                    | `ttp refresh`      |
| Graceful shutdown | `SIGNAL SHUTDOWN`                  | `ttp stop`         |

### 2.3 Generated `torrc` Configuration

TTP generates a **volatile** `torrc` at `/run/tor/ttp/torrc` on each start. Key directives:

| Directive                | Value                                        | Purpose                                             |
| :----------------------- | :------------------------------------------- | :-------------------------------------------------- |
| `VirtualAddrNetworkIPv4` | `10.192.0.0/10`                              | Address range for `AutomapHostsOnResolve`           |
| `AutomapHostsOnResolve`  | `1`                                          | Maps `.onion` and `.exit` to virtual IPs            |
| `SocksPort`              | `0`                                          | SOCKS proxy disabled (transparent-only mode)        |
| `CookieAuthentication`   | `1`                                          | Enables cookie-based control auth                   |
| `DataDirectory`          | `/var/lib/tor/ttp/`                          | **Persistent** entry guard cache (survives reboots) |
| `MapAddress`             | `use-application-dns.net 0.0.0.0` (+ others) | DoH canary domain mitigation                        |

### 2.4 Pluggable Transports (Optional)

When bridges are configured, TTP supports pluggable transports via external helper binaries:

| Transport             | Binary             | Package (Debian)   | Package (Fedora)   |
| :-------------------- | :----------------- | :----------------- | :----------------- |
| `obfs4` / `meek_lite` | `obfs4proxy`       | `obfs4proxy`       | `obfs4`            |
| `snowflake`           | `snowflake-client` | `snowflake-client` | `snowflake-client` |

Missing binaries are auto-installed via the detected system package manager.

---

## 3. System Integration

TTP interacts directly with several Linux kernel subsystems and system services.

### 3.1 nftables Firewall

TTP creates a dedicated, isolated nftables table that does not interfere with any pre-existing firewall rules.

| Attribute              | Value                                                           |
| :--------------------- | :-------------------------------------------------------------- |
| **Table name**         | `inet ttp`                                                      |
| **Application method** | Atomic load via `nft -f <rules_file>` (all-or-nothing)          |
| **Cleanup method**     | `nft destroy table inet ttp` (atomic, no rule-by-rule deletion) |

**Chains within `inet ttp`:**

| Chain        | Hook         | Type     | Purpose                                                   |
| :----------- | :----------- | :------- | :-------------------------------------------------------- |
| `prerouting` | `prerouting` | `nat`    | Intercepts traffic arriving on the machine (gateway mode) |
| `output`     | `output`     | `nat`    | Redirects local TCP and DNS to Tor ports                  |
| `filter_out` | `output`     | `filter` | Kill-switch: drops/rejects traffic that bypasses Tor      |

**Rule execution order within `filter_out`:**

1. Exempt Tor process user (prevent routing loops)
2. Exempt bypass users/groups (split tunneling — `meta skuid`/`meta skgid`)
3. Exempt root processes (if `--allow-root` is set)
4. LAN bypass: accept RFC 1918 + IPv6 link-local/unique-local traffic (optional, `--no-lan-bypass` disables)
5. Accept loopback interface (`lo` - IPv4 and IPv6)
6. Block DNS-over-TLS (reject `tcp dport 853`)
7. Block well-known DNS-over-HTTPS (DoH) IPs on port 443 (IPv4 and IPv6)
8. Drop unrouted IPv6 traffic (only if IPv6 loopback is not supported by the system)
9. **Kill-Switch**: reject all remaining traffic (forces fallback of redirected TCP/DNS or blocks unauthorized bypasses)

### 3.2 DNS Subsystem

TTP uses a **stateless `mount --bind` overlay** to redirect DNS without modifying files on disk.

| Attribute          | Value                                                                                    |
| :----------------- | :--------------------------------------------------------------------------------------- |
| **Overlay source** | `/run/ttp/resolv.conf` (volatile, on tmpfs)                                              |
| **Overlay target** | Real path of `/etc/resolv.conf` (resolved through symlinks)                              |
| **Content**        | `nameserver 127.0.0.1` pointing to Tor's `DNSPort`                                       |
| **Mount type**     | `mount --bind` (bind mount)                                                              |
| **Teardown**       | `umount -l` (lazy unmount — safe even if file is open)                                   |
| **Idempotency**    | Stale mounts from previous unclean exits are cleaned from `/proc/mounts` before applying |

### 3.3 systemd Integration

TTP manages two volatile systemd service units, written to `/run/systemd/system/` (evaporate on reboot):

| Unit                   | Path                                       | Purpose                                                                                  |
| :--------------------- | :----------------------------------------- | :--------------------------------------------------------------------------------------- |
| `ttp-tor.service`      | `/run/systemd/system/ttp-tor.service`      | Dedicated Tor instance. Runs with a custom volatile `torrc`, no sandboxing restrictions. |
| `ttp-watchdog.service` | `/run/systemd/system/ttp-watchdog.service` | Session integrity watchdog. Invokes `ttp watchdog run` every 15 seconds.                 |

Both units are registered via `systemctl daemon-reload` and removed on `ttp stop`.

### 3.4 Filesystem — Volatile Runtime Paths

All TTP runtime state is stored in tmpfs paths that **disappear on reboot**, leaving no forensic traces.

| Path                                       | Contents                                                     | Cleared On           |
| :----------------------------------------- | :----------------------------------------------------------- | :------------------- |
| `/run/ttp/`                                | Session root directory                                       | Reboot or `ttp stop` |
| `/run/ttp/ttp.lock`                        | JSON session lock: PID, timestamps, interface, bypass config | `ttp stop`           |
| `/run/ttp/ttp.log`                         | Rolling log (1 MB limit)                                     | Reboot               |
| `/run/ttp/resolv.conf`                     | DNS resolver file for bind-mount overlay                     | Reboot               |
| `/run/tor/ttp/torrc`                       | Generated Tor configuration                                  | Reboot               |
| `/run/tor/ttp/control.sock`                | Tor control Unix socket                                      | Tor shutdown         |
| `/run/tor/ttp/auth_cookie`                 | Cookie for Tor control authentication                        | Tor shutdown         |
| `/run/systemd/system/ttp-tor.service`      | Volatile Tor service unit                                    | Reboot               |
| `/run/systemd/system/ttp-watchdog.service` | Volatile watchdog service unit                               | Reboot               |

**Persistent path (survives reboots):**

| Path                | Contents                                           | Purpose                                                 |
| :------------------ | :------------------------------------------------- | :------------------------------------------------------ |
| `/var/lib/tor/ttp/` | Tor `DataDirectory`: entry guards, consensus cache | Reduces bootstrap time from ~30s to ~3s across sessions |

---

## 4. External Network Endpoints

TTP contacts the following external URLs exclusively for session verification and diagnostics. No telemetry or tracking data is ever sent.

| URL                                   | Trigger                  | Purpose                                          |
| :------------------------------------ | :----------------------- | :----------------------------------------------- |
| `https://check.torproject.org/api/ip` | `ttp start`, `ttp check` | Primary Tor exit IP verification + `IsTor` flag  |
| `https://api.ipify.org`               | `ttp start` (fallback)   | Backup IP check if torproject.org is unreachable |
| `https://ifconfig.me/ip`              | `ttp start` (fallback)   | Second backup IP check                           |
| `https://torproject.org`              | `ttp check`              | Latency measurement to the Tor network           |
| `https://api4.my-ip.io/ip`            | `ttp check-leak`         | IPv4 leak detection                              |
| `https://api6.my-ip.io/ip`            | `ttp check-leak`         | IPv6 leak detection                              |

All connections to these endpoints are routed through Tor itself (verifying correct operation). They are never contacted via the clearnet directly.
