<h1 align="center">
  TTP - Transparent Tor Proxy
</h1>

<h4 align="center">A Linux CLI tool that transparently routes <b>all system traffic</b> through the Tor network using nftables.</h4>

<p align="center">
  <a href="https://github.com/sponsors/onyks-os"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ff69b4?style=for-the-badge&logo=githubsponsors" alt="Sponsor"></a>
  <img src="https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=for-the-badge&logo=python" alt="Python">
  <a href="https://github.com/onyks-os/TransparentTorProxy/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/onyks-os/TransparentTorProxy/ci.yml?style=for-the-badge&logo=github" alt="CI Status"></a>
  <a href="https://pypi.org/project/transparent-tor-proxy/"><img src="https://img.shields.io/pypi/dm/transparent-tor-proxy?style=for-the-badge&logo=pypi" alt="PyPI - Downloads"></a>
  <a href="https://www.bestpractices.dev/projects/13164"><img src="https://img.shields.io/cii/level/13164?style=for-the-badge&label=OpenSSF%20Best%20Practices" alt="OpenSSF Best Practices"></a>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#requirements">Requirements</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#obtain-feedback--contributions">Contribute</a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/onyks-os/TransparentTorProxy/main/assets/gif/demo_2.0.gif" alt="TTP Demo">
</p>

---

No per-application setup needed - just `sudo ttp start` and **every connection** goes through Tor.

> [!CAUTION]
> TTP is a tool designed to aid privacy by routing traffic through Tor. However, no tool can guarantee 100% anonymity. Your safety also depends on your behavior (e.g., using a regular browser vs. Tor Browser, signing into accounts, etc.). Always use TTP as part of a multi-layered security strategy.

> [!WARNING]
> **If you are a whistleblower or are engaging in high-risk activities, DO NOT use TTP.** Instead, use officially audited and reliable tools like [TailsOS](https://tails.net/) or the [Tor Browser](https://www.torproject.org/) directly. The authors and contributors of TTP assume no responsibility for your safety or the consequences of using this software.

## Features

* **Volatile Core Architecture**: Entire session state, lockfiles, and logs are stored exclusively in `tmpfs` (`/run/ttp/` and `/run/tor/ttp/`), ensuring no forensic traces are written to physical disk and automatically vanishing on reboot.
* **Stateless DNS Overlay**: Transparently redirects DNS requests using a kernel-level `mount --bind` overlay on `/etc/resolv.conf` without modifying the original configuration file on disk, with automatic stale mount cleanup for absolute idempotency.
* **Proactive Watchdog & Killswitch**: Active background session integrity daemon monitoring Tor status, nftables table/chain presence, and DNS overlay mount. Triggers a single-strike auto-healing repair or a hard network lockout (emergency drop-all killswitch) under persistent failure.
* **LAN Bypass & Split Tunneling**: Excludes local subnets (RFC 1918 & Link-Local) dynamically from Tor routing to maintain access to local resources (printers, NAS). Supports user- or group-specific exceptions (`--bypass-user` / `--bypass-group`) via `nftables` uid/gid checks.
* **Native Dual-Stack IPv6 Redirection**: Dynamically detects IPv6 loopback availability, building dual-stack nftables redirect chains or dropping all outgoing IPv6 traffic (IPv6 leak prevention) if unsupported.
* **DoH/DoT Leak Mitigation**: Actively blocks outbound DoT (port 853) and well-known DoH resolver IPs (port 443) to force system fallback to Tor DNS, utilizing canary domains in `torrc` to disable browser-level DoH where supported.
* **Native Tor Service Management**: Tor is managed via a dedicated volatile `ttp-tor.service` systemd unit running on non-standard ports, coexisting seamlessly with any standard system `tor.service` without address conflicts.

## Requirements

* **Linux with systemd** *(tested on Debian, Ubuntu, Fedora, Arch)*
* **Python 3.10+**
* **nftables** *(pre-installed on most modern distros)*
* **Root privileges** *(required for firewall and DNS modifications)*

## Installation

Choose the method that best fits your needs. **Native packages are strongly recommended** for system stability, security, and clean uninstallation.

### 1. Native Packages (Recommended)

Installing via native packages ensures that all system dependencies (`tor`, `nftables`) and kernel-level optimizations (SELinux) are managed by your OS package manager.

* **Debian / Ubuntu**: `sudo apt install ./packaging/transparent-tor-proxy_0.4.0_all.deb`
* **Fedora / RHEL**: `sudo dnf install ./packaging/transparent-tor-proxy-0.4.0-1.fc43.noarch.rpm`
* **Arch Linux**: `cd packaging && makepkg -si`

For instructions on how to verify the integrity and authenticity of the release assets, see the [Release Verification Guide](docs/verification.md).

---

### 2. Manual Source Install (Developer/Universal)

If you are a developer or want to install from the repository:

```bash
git clone https://github.com/onyks-os/TransparentTorProxy.git
cd TransparentTorProxy
sudo ./scripts/install.sh
```

> [!TIP]
> **Why use `./install.sh`?**  
> Unlike standard Python installers, this script is **"intelligent"**. On Red Hat-based systems, it detects if SELinux is in *Enforcing* mode and dynamically compiles a custom policy module (from `ttp_tor_policy.te`) to allow Tor to bind to the non-standard ports required by TTP (9041, 9054). This kernel-level optimization cannot be performed by `pip`.

---

### 3. Fallback: pipx / pip (PEP 668)

> [!WARNING]
> **Note on Linux Distributions (PEP 668)**  
> Recent versions of Ubuntu/Debian prevent global `pip install` to protect system stability. Using these methods will bypass TTP's kernel-level optimizations (SELinux) and won't handle system dependencies automatically.

#### **Option A: pipx (Recommended Fallback)**

`pipx` installs TTP in an isolated environment but makes the command available globally.

```bash
pipx install transparent-tor-proxy
```

#### **Option B: Standard pip with venv**

If you prefer standard `pip`, use a virtual environment to avoid the `externally-managed-environment` error.

```bash
# 1. Create the environment
python3 -m venv ~/.local/share/ttp-venv

# 2. Install the package
~/.local/share/ttp-venv/bin/pip install transparent-tor-proxy

# 3. Create a symbolic link to use 'ttp' everywhere
sudo ln -s ~/.local/share/ttp-venv/bin/ttp /usr/local/bin/ttp
```

> [!CAUTION]
> **Uninstallation Warning**: Running `pipx uninstall` or deleting the venv only removes the Python code. If TTP is active, your firewall and DNS will remain hijacked. Always use `ttp stop` before uninstalling via pip, or use `./scripts/uninstall.sh` if you installed via the source script.

> [!NOTE]  
> After installation, the `ttp` command is available system-wide.

## Usage

> [!IMPORTANT]
> All commands require `sudo`. Except `ttp status`, `ttp check`, `ttp check-leak`, `ttp watchdog status`, and `ttp --help`.

### Start the proxy

```bash
sudo ttp start [--interface <iface>] [--bootstrap-timeout <seconds>] [--allow-root] [--no-lan-bypass] [--watchdog] [--bypass-user <users>] [--bypass-group <groups>] [--use-bridges] [--bridge-file <path>] [--bridge <line>]
```

> [!TIP]
> Use `--bootstrap-timeout` (default: 180s) if you are on a slow network or Tor takes a long time to connect.

```text
[TTP] Detecting Tor... found (v0.4.9.6), managed via system service (user: debian-tor).
[TTP] Initializing volatile runtime in /run/ttp...
[TTP] Restarting TTP Tor service...
[TTP] Stateless nftables rules applied (Table: inet ttp).
[TTP] DNS set via overlay on interface ens3.
[TTP] Waiting for Tor to bootstrap...
[TTP] Tor is 100% bootstrapped.
[TTP] Verifying Tor routing...
[TTP] Session active. Exit IP: 109.70.100.11
[TTP] Use 'ttp stop' to terminate. 'ttp refresh' to change IP.
```

### Stop the proxy

```bash
sudo ttp stop [--restore-only]
```

> [!IMPORTANT]
> The `--restore-only` flag is a recovery tool. If TTP crashed or its lock file was lost, this flag forces the restoration of firewall rules and DNS settings without checking for an active session.

```text
[TTP] Removing nftables rules...
[TTP] Restoring DNS...
[TTP] Network restored. Traffic in cleartext.
```

### Change exit IP

```bash
sudo ttp refresh
```

*Sends `NEWNYM` to Tor via the control interface - all active circuits are rotated and you get a new exit IP.*

### Check status

```bash
sudo ttp status
```

```text
[TTP] Status: ACTIVE
[TTP] Exit IP: 185.181.61.201
[TTP] Session started: 2026-04-19T01:07:33.384801+00:00
[TTP] Process PID: 3392
```

### Restart the session

```bash
sudo ttp restart [--interface <iface>] [--bootstrap-timeout <seconds>] [--allow-root] [--no-lan-bypass] [--watchdog] [--bypass-user <users>] [--bypass-group <groups>] [--use-bridges] [--bridge-file <path>] [--bridge <line>]
```

*Shortcut for `ttp stop` followed by `ttp start`. Convenient for applying new settings or clearing network glitches.*

### Network Diagnostics (Fast)

```bash
ttp check
```

*A dedicated command to verify the real-world state of the Tor connection. Shows current IP, IsTor status, latency to torproject.org, and local controller stability. Unlike `status` which shows TTP's internal state, `check` verifies the network.*

### Leak Detection

```bash
ttp check-leak [-v]
```

*Performs a series of DNS and IP leak tests. Use `-v` or `--verbose` to see the full raw output of the tests.*

### Debugging Logs

```bash
sudo ttp logs
```

*Streams real-time logs from the volatile log file at `/run/ttp/ttp.log`.*

### Manage session watchdog

```bash
# Start background session watchdog manually
sudo ttp watchdog start

# Stop background session watchdog manually
sudo ttp watchdog stop

# Show background session watchdog status
ttp watchdog status
```

### Advanced Security Profiles

Depending on your security model and task, we recommend the following setups:

#### 1. Daily Privacy Profile (Standard)
* **Goal**: Anonymize general browsing, bypass geographic restrictions, or hide ISP snooping with minimal overhead.
* **Command**:
  ```bash
  sudo ttp start
  ```
* **Why**: Runs without background active processes (no watchdog overhead), utilizing extremely efficient `nftables` redirect rules and local bypass for smooth home/work LAN printer/NAS sharing.

#### 2. Maximum Security Profile (High-Risk)
* **Goal**: Whistleblowing, high-risk activity, total protection against accidental cleartext leaks or network state changes.
* **Command**:
  ```bash
  sudo ttp start --watchdog --no-lan-bypass
  ```
* **Why**: Starts the continuous background **Watchdog** daemon to monitor state integrity every 15s. Disables LAN bypass to prevent side-channel leaks to local LAN devices. If any component (DNS overlay, nftables, or Tor daemon) is tampered with or fails, the system instantly isolates the network completely (Emergency Killswitch) and notifies you.

#### 3. Administrative / Maintenance Profile
* **Goal**: Perform local updates (e.g., `apt update`, `dnf upgrade`) or maintenance that requires high bandwidth or direct native route while Tor is active, or speed up initial bootstrapping.
* **Command**:
  ```bash
  sudo ttp start --allow-root
  ```
* **Why**: Routes all default user/system processes through Tor, but exempts system root processes (`uid 0`) allowing them to communicate directly in cleartext for updates or troubleshooting. (Use with caution: increases risk of tool/script leaks if run under sudo).

#### 4. Split Tunneling Profile
* **Goal**: Route all network traffic through Tor except for specific system users or groups (e.g. running a local media server, backups, or gaming in cleartext).
* **Command**:
  ```bash
  sudo ttp start --bypass-user debian-tor,mediauser --bypass-group sysadmin
  ```
* **Why**: Uses `nftables` exceptions to allow the matching local user IDs or group IDs to communicate directly to the cleartext internet, bypassing redirection and the watchdog killswitch.

#### 5. Censorship Circumvention Profile (Tor Bridges)
* **Goal**: Connect to the Tor network in censored environments where standard Tor entry nodes are blocked.
* **Command**:
  ```bash
  sudo ttp start --use-bridges --bridge-file /path/to/my_bridges.txt
  # OR specify individual bridges directly:
  sudo ttp start --bridge "obfs4 192.0.2.1:1234 ..." --bridge "snowflake 192.0.2.2:4321 ..."
  ```
* **Why**: Configures Tor to connect via bridges. If pluggable transports like `obfs4proxy` or `snowflake-client` are needed, TTP automatically checks their presence and installs them using the system package manager.

## Manual Leak Verification

To confirm that the tunnel is working correctly and no leaks are present:

1. **Verify Tor Exit IP:**

   ```bash
   curl -s https://check.torproject.org/api/ip
   ```

2. **Verify DNS Routing:**

   ```bash
   # Should return a valid IP via Tor's DNSPort
   dig +short A check.torproject.org
   ```

3. **DNS Leak Test (Terminal):**

   ```bash
   # This TXT query SHOULD return an EMPTY output
   dig +short TXT whoami.ipv4.akahelp.net
   ```

   *Note: An empty output is the **expected** behavior under Tor. Tor's transparent resolver does not support TXT records; if this command returns your real ISP's IP, you have a DNS leak.*

4. **Web-based Verification:**
   Always perform additional tests on [dnsleaktest.com](https://www.dnsleaktest.com) and [ipleak.net](https://ipleak.net).

### Full Uninstallation

To remove TTP completely from the system:

```bash
sudo ./scripts/uninstall.sh
```

## How It Works

1. **Detection & System Auditing** - Checks if Tor is installed and identifies the appropriate user to run the process. It automatically checks for active `firewalld` configurations to warn users of possible firewall rule conflicts.
2. **Package Management & SELinux Optimization** - If Tor is missing, detects the system's package manager (`apt-get`, `pacman`, `dnf`, `zypper`) and installs it automatically. On Fedora/RHEL-family systems in Enforcing mode, it automatically compiles a custom SELinux policy module from the source (`ttp_tor_policy.te`) using `checkpolicy` and `semodule_package` so that Tor can bind to the non-standard ports.
3. **Pre-flight Safety Check** - Verifies that the host system has sufficient free space (minimum 5MB) on the RAM-backed volatile directory (`tmpfs`) to prevent out-of-memory crashes mid-setup.
4. **Tor Instance Lifecycle** - Generates a sanitized, dynamic `torrc` config at `/run/tor/ttp/torrc` and registers a volatile `ttp-tor.service` systemd unit in `/run/systemd/system/`. Uses `/var/lib/tor/ttp/` as a persistent `DataDirectory` to preserve entry guards and cache, enabling quick bootstrap (~3 seconds). During teardown, TTP sends a cryptographic `SHUTDOWN` signal to Tor before removing the firewall to avoid leaking cleartext TCP `RST` packets on system shutdown.
5. **Atomic Firewall Redirection** - Generates and loads `nftables` rules into a dedicated `inet ttp` table atomically using `nft -f` to prevent dangerous intermediate states.
   * **Multi-Chain Protection**:
     * `prerouting`: Intercepts traffic if TTP is used as a gateway.
     * `output` (NAT): Redirects local TCP/DNS to Tor's ports.
     * `filter_out` (Filter): Serves as a hard **Kill-Switch**.
   * **Execution Sequence**:
     1. **Exclude Tor User**: Prevent routing loops for the Tor daemon process.
     2. **Exclude Split Tunneling**: Exempt user- or group-specific traffic (`meta skuid` / `meta skgid`) to bypass Tor when requested.
     3. **Exclude System Maintenance**: Exempt root processes (`uid 0`) if `--allow-root` is set.
     4. **Intercept DNS**: Redirect UDP/TCP port 53 traffic to Tor's `DNSPort`.
     5. **Bypass LAN**: Accept local subnet traffic (RFC 1918 & Link-Local) unless `--no-lan-bypass` is active.
     6. **Accept Loopback**: Allow local `lo` traffic.
     7. **Redirect TCP**: Redirect all TCP traffic to Tor's `TransPort`.
     8. **DoH/DoT Mitigation**: Block port 853 (DoT) and well-known DoH resolver IPs on port 443.
     9. **Drop Unrouted IPv6**: Block outbound IPv6 traffic if the host lacks IPv6 loopback routing.
     10. **Brutal Reject (Kill-Switch)**: Reject all remaining traffic bypassing Tor redirection (e.g. pre-existing connections).
6. **DNS Bind-Mount Overlay** - Bind-mounts a volatile resolver file from `/run/ttp/resolv.conf` over the target `/etc/resolv.conf` to force local resolution. Stale mounts from unclean runs are automatically detected in `/proc/mounts` and swept before applying new overlays.
7. **Control socket communication** - Monitors progress via Tor ControlPort Unix socket `/run/tor/ttp/control.sock` using `stem` until it reaches 100% bootstrap.
8. **Exit IP Verification** - Validates successful Tor routing via three redundant endpoints (`check.torproject.org` API, fallback `api.ipify.org`, and `ifconfig.me`).
9. **Volatile State Retention** - Writes the session lock at `/run/ttp/ttp.lock` and limits volatile logs in `/run/ttp/ttp.log` to a strict 1MB to prevent system memory exhaustion on RAM disk.
10. **Session Watchdog Daemon** - Launches a volatile background service (`ttp-watchdog.service`) running checks every 15s. Verifies the DNS bind-mount, firewall table integrity, and Tor socket. Attempts a single-strike auto-healing repair before invoking `apply_emergency_killswitch()` (blocking all interfaces except `lo`) and broadcasting system alerts (`wall` and `notify-send`).

## Crash Recovery

TTP is designed to always restore your network, even in edge cases:

| Scenario                 | What happens                                                                                             |
| :----------------------- | :------------------------------------------------------------------------------------------------------- |
| `ttp stop`               | **Normal cleanup**: graceful Tor shutdown, firewall restored, DNS restored, lock deleted                 |
| Ctrl+C / `kill`          | Signal handler catches `SIGINT`/`SIGTERM` and runs normal cleanup before exit                            |
| `kill -9` / Power Outage | Next `ttp start` detects the orphaned lock file, clears any stale mount stacks, and auto-restores        |
| Manual emergency         | Run `sudo ./scripts/restore-network.sh` to flush all nftables rules, reset DNS, and delete the lock file |

## Known Behavior & Limitations

> [!WARNING]
>
> * **Tor Browser**: Applications using an explicit SOCKS5 proxy will create a double Tor hop. Use a regular browser instead while TTP is active.
> * **DNS-over-HTTPS (DoH)**: Normal browsers (Firefox, Chrome, Brave, Edge) may use DoH, bypassing system DNS. TTP mitigates this by blocking well-known DoH resolver IPs (forcing fallback to Tor DNS) and routing unlisted DoH traffic through Tor (which can, however, partially compromise anonymity). For maximum security, disable **DoH / "Secure DNS"** in your browser settings.
> * **IPv6**: Fully supported when available. TTP dynamically detects IPv6 loopback and routes IPv6 traffic through Tor. If the host lacks IPv6 loopback support, TTP drops all outgoing IPv6 traffic to prevent leaks.
> * **Exit IP variation**: Different connections may show different exit IPs due to Tor stream isolation.

For a full breakdown of residual risks, architectural trust boundaries, and the STRIDE threat model, see:

**[`docs/security-assessment.md`](docs/security-assessment.md)**

## Development & Testing

TTP uses a **Makefile** to automate and standardize the testing pipeline. This ensures that every change is verified against unit and integration tests before being committed.

### The "Pre-Push" Rule
>
> [!IMPORTANT]
> **Always run `make verify` before pushing code.** If this command fails, the code is NOT ready for production.

### Essential Commands

| Command                   | Goal                                                                      |
| :------------------------ | :------------------------------------------------------------------------ |
| `make test`               | Runs fast **Unit Tests** locally (no root needed, fully mocked).          |
| `make integration-debian` | Runs full system tests inside a privileged **Docker** container (Debian). |
| `make integration-all`    | Runs integration tests for all supported distros (Debian, Fedora, Arch).  |
| `make verify`             | Runs Unit Tests + All Integration Tests.                                  |
| `make build`              | Generates native `.deb` and `.rpm` packages.                              |
| `make clean`              | Removes all build artifacts, caches, and temp files.                      |

### Advanced: Real-World VM Testing

While Docker integration tests are fast and atomic, they don't capture 100% of the kernel/systemd nuances. For critical changes, it is **highly recommended** to test in a real QEMU VM:

```bash
# Start a specific VM (e.g., arch)
./scripts/vm/start.sh arch

# Sync current code to the VM
./scripts/vm/send.sh

# Snapshot management for easy rollbacks
./scripts/vm/snapshot.sh arch save before-risky-test
```

### Diagnostics

If something goes wrong, run the diagnostic command:

```bash
sudo ttp diagnose
```

## Project Structure

```text
├── pyproject.toml          # Package metadata and dependencies
├── README.md
├── CONTRIBUTING.md         # Contribution guidelines
├── SECURITY.md             # Security policy
├── scripts/                # Installation and VM management scripts
├──   ├── install.sh          # System-wide installer
├──   ├── uninstall.sh        # System-wide uninstaller
├──   ├── restore-network.sh  # Emergency network recovery script
├──   ├── verify.sh           # CI/CD verification script
├──   └── vm/                 # QEMU VM management scripts
├──   └── vms/                # .iso and .qcow2 files
├── assets/                 # Branding and demo assets
├──   ├── favicon/            # Project favicons and webmanifest
├──   └── gif/                # Demo animations
├── packaging/              # Build scripts for .deb, .rpm, and Arch packages
├──   ├── build_deb.sh
├──   ├── build_rpm.sh
├──   ├── release.sh          # Package release/publish script
├──   ├── ttp.spec
├──   ├── PKGBUILD
├──   └── ttp.service
├── ttp/                    # Source code
├──   ├── resources/          # Internal package resources (SELinux policies, etc.)
├──   ├── cli.py              # Typer entry point
├──   ├── exceptions.py       # Custom exception hierarchy
├──   ├── tor_detect.py       # Tor detection logic
├──   ├── tor_install.py      # Auto-install & configuration
├──   ├── firewall.py         # Atomic nftables management
├──   ├── dns.py              # DNS leak prevention
├──   ├── state.py            # Lock file and crash recovery
├──   ├── tor_control.py      # Tor daemon interaction and API
├──   ├── watchdog.py         # Session integrity watchdog and auto-healing
├──   └── system_info.py      # System diagnostic gathering
├── tests/                  # Unit tests (mocked) and test_watchdog.py
└── docs/
    ├── architecture.md     # Technical Architecture & Design
    ├── interfaces.md       # External interfaces reference (CLI, Tor, system)
    └── security-assessment.md  # STRIDE threat model & risk assessment
```

## Call for Contributors

We are actively looking for developers to join the TTP project! Whether you are a student looking to learn or a seasoned professional, your help is welcome.

**We are particularly seeking Senior Developers** with expertise in:

* **Linux Networking** (nftables, routing tables, network namespaces).
* **Tor Internals** (daemon configuration, Stem library, circuit management).
* **System-level Python** (asynchronous I/O, process management, security best practices).

If you want to contribute to making transparent proxying safer and more robust, please check out our [Contributing Guidelines](CONTRIBUTING.md) or dive right into the [Issues](https://github.com/onyks-os/TransparentTorProxy/issues).

## Obtain, Feedback & Contributions

- **Obtain**: TTP is available on [PyPI](https://pypi.org/project/transparent-tor-proxy/) and can also be downloaded from the [GitHub Releases](https://github.com/onyks-os/TransparentTorProxy/releases) page. For installation methods, see the [Installation](#installation) section.
- **Feedback**: Report bugs, suggest enhancements, or request features by opening a ticket on the [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues) tracker.
- **Contribute**: Contributions are always welcome! Review our [Contributing Guidelines](CONTRIBUTING.md) to learn how to submit code, follow coding standards, and run tests.
- **Security**: Please review our [Security Policy](SECURITY.md) before reporting any vulnerabilities or security concerns.

## Support

For version support status, EOL information, and support channels, please refer to the [Support Policy](SUPPORT.md).

This project is maintained in my free time, and donations are highly appreciated.

<div align="center">

Also, if you find **TTP** useful, please consider giving it a **Star**!  
It helps others discover the tool and motivates further development.

[![GitHub stars](https://img.shields.io/github/stars/onyks-os/TransparentTorProxy?style=social)](https://github.com/onyks-os/TransparentTorProxy)

</div>

## License

MIT. See [LICENSE](LICENSE) for more information.
