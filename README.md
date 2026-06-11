<p align="center">
  <img src="https://raw.githubusercontent.com/onyks-os/TransparentTorProxy/main/assets/icon.png" width="200" alt="TTP Logo">
</p>

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
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#call-for-contributors">Contribute</a> •
  <a href="#requirements">Requirements</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How It Works</a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/onyks-os/TransparentTorProxy/main/assets/gif/demo.gif" alt="TTP Demo">
</p>

---

No per-application setup needed - just `sudo ttp start` and **every connection** goes through Tor.

> [!CAUTION]
> TTP is a tool designed to aid privacy by routing traffic through Tor. However, no tool can guarantee 100% anonymity. Your safety also depends on your behavior (e.g., using a regular browser vs. Tor Browser, signing into accounts, etc.). Always use TTP as part of a multi-layered security strategy.

> [!WARNING]
> **If you are a whistleblower or are engaging in high-risk activities, DO NOT use TTP.** Instead, use officially audited and reliable tools like [TailsOS](https://tails.net/) or the [Tor Browser](https://www.torproject.org/) directly. The authors and contributors of TTP assume no responsibility for your safety or the consequences of using this software.

## Call for Contributors

We are actively looking for developers to join the TTP project! Whether you are a student looking to learn or a seasoned professional, your help is welcome.

**We are particularly seeking Senior Developers** with expertise in:

* **Linux Networking** (nftables, routing tables, network namespaces).
* **Tor Internals** (daemon configuration, Stem library, circuit management).
* **System-level Python** (asynchronous I/O, process management, security best practices).

If you want to contribute to making transparent proxying safer and more robust, please check out our [Contributing Guidelines](CONTRIBUTING.md) or dive right into the [Issues](https://github.com/onyks-os/TransparentTorProxy/issues).

## Features

* **Watchdog Daemon & Emergency Killswitch** - Background session daemon monitoring system integrity (Tor status, nftables table/chain presence, and DNS overlay mount) every 15s. Performs auto-healing or triggers total network lockout (killswitch) under persistent failure.
* **LAN Bypass** - Excludes local subnets (RFC 1918 & Link-Local) dynamically from routing to allow direct access to local devices (NAS, printers).
* **DNS Leak DoH/DoT Mitigation** - Blocks outgoing DoT on port 853, blocks well-known DoH resolvers at the firewall level, routes unlisted DoH traffic through Tor, and uses canary domains in `torrc` to disable browser-level DoH where supported.
* **Selective Root Routing** - Routes all root and `sudo` command traffic through Tor by default, with `--allow-root` to bypass if needed.
* **Volatile Standard Core** - Fully volatile runtime. All session data, locks, and temporary configs are stored in `tmpfs` (/run/ttp), wiped automatically on reboot.
* **Pre-flight Safety Check** - Verifies sufficient `tmpfs` space before execution to prevent out-of-memory crashes mid-setup.
* **DNS leak prevention** - Stateless `mount --bind` overlay strategy for `/etc/resolv.conf`, with automatic stale mount cleanup for absolute idempotency.
* **Native IPv6 Support & Redirection** - Dynamic IPv6 loopback detection, dual-stack or IPv4-only configuration based on system availability, and comprehensive IPv6 nftables redirection and leak prevention.
* **Graceful Teardown** - On stop, TTP sends a cryptographic `SHUTDOWN` signal to Tor, ensuring all circuits are closed cleanly before the firewall rules are removed to prevent cleartext `RST` packet leaks.
* **Native Tor Service Management** - Tor is managed via a dedicated volatile `ttp-tor.service` unit, ensuring zero interference with the system's own Tor service and no sandboxing issues.
* **Atomic firewall rules** - `nftables` rules are loaded with `nft -f` (all-or-nothing), avoiding dangerous intermediate states.
* **IP rotation** - `ttp refresh` requests a new Tor circuit for a fresh exit IP.
* **Volatile Logging** - Logs stored in `/run/ttp/ttp.log` (1MB limit) to ensure no forensic traces remain on disk.
* **Persistent Entry Guards** - `DataDirectory /var/lib/tor/ttp/` preserves Entry Guards across runs for fast bootstrap (~3 seconds).
* **Firewalld detection** - Warns Fedora/RHEL users if `firewalld` is active to prevent rule conflicts.
* **SELinux optimization** - Compiles a custom SELinux policy from source (`.te`) on Fedora/RHEL to allow Tor to bind to necessary ports. No opaque binaries shipped.
* **Multi-distro** - auto-detects `apt-get`, `pacman`, `dnf`, and `zypper` for Tor installation. Handles Debian multi-instance services (`tor@default`), Fedora (`toranon` user), and more.
* **Auto-configuration** - validates and sanitizes `torrc` before starting, removing invalid settings and appending missing options.

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
> Unlike standard Python installers, this script is **"intelligent"**. On Red Hat-based systems, it detects if SELinux is in *Enforcing* mode and dynamically compiles a custom policy module (from `ttp_tor_policy.te`) to allow Tor to bind to the non-standard ports required by TTP (9040, 9053). This kernel-level optimization cannot be performed by `pip`.

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

### Recommended Modes (Operational Security Profiles)

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

### Start the proxy

```bash
sudo ttp start [--interface <iface>] [--bootstrap-timeout <seconds>] [--allow-root] [--no-lan-bypass] [--watchdog]
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
sudo ttp restart [--interface <iface>] [--bootstrap-timeout <seconds>] [--allow-root] [--no-lan-bypass] [--watchdog]
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

## Manual Leak Verification

To confirm that the tunnel is working correctly and no leaks are present:

1. **Verify Tor Exit IP:**

   ```bash
   curl -s https://check.torproject.org/api/ip
   ```

1. **Verify DNS Routing:**

   ```bash
   # Should return a valid IP via Tor's DNSPort
   dig +short A check.torproject.org
   ```

1. **DNS Leak Test (Terminal):**

   ```bash
   # This TXT query SHOULD return an EMPTY output
   dig +short TXT whoami.ipv4.akahelp.net
   ```

   *Note: An empty output is the **expected** behavior under Tor. Tor's transparent resolver does not support TXT records; if this command returns your real ISP's IP, you have a DNS leak.*

1. **Web-based Verification:**
   Always perform additional tests on [dnsleaktest.com](https://www.dnsleaktest.com) and [ipleak.net](https://ipleak.net).

### Full Uninstallation

To remove TTP completely from the system:

```bash
sudo ./scripts/uninstall.sh
```

## How It Works

1. **Detection** - checks if Tor is installed and identifies the appropriate user to run the process.
2. **Installation** - if Tor is missing, detects the system's package manager and installs it automatically.
3. **Configuration** - generates a dynamic, volatile `torrc` in `/run/tor/ttp/torrc` and installs it as the system config.
4. **Tor Management** - creates a dedicated volatile `ttp-tor.service` systemd unit and starts Tor with the optimized config.
5. **Firewall** - generates `nftables` rules in a dedicated `inet ttp` table:
      * **Stateless approach** - no system backups needed; cleanup is an atomic `nft destroy table`.
      * **Multi-Chain Protection**:
          * `prerouting`: Intercepts traffic if TTP is used as a gateway.
          * `output` (NAT): Redirects local TCP/DNS to Tor's ports.
          * `filter_out` (Filter): Acts as a **Kill-Switch**.
      * **Execution Sequence**:
          1. **Exclude Tor user** (prevents routing loops).
          2. **Exclude split-tunneling users/groups** (if configured).
          3. **Route root processes** (routed by default, unless `--allow-root` is passed).
          4. **Intercept DNS** (UDP/TCP `:53`) and redirect to Tor's DNSPort (IPv4/IPv6).
          5. **Bypass local LAN traffic** (unless `--no-lan-bypass` is passed) (IPv4/IPv6).
          6. **Accept loopback** and local traffic (IPv4/IPv6).
          7. **Redirect all TCP** to Tor's TransPort (IPv4/IPv6).
          8. **Block DoT** (port 853) and well-known **DoH** IP resolvers (port 443) to force fallback to Tor DNS.
          9. **Drop unrouted IPv6** (only if IPv6 loopback is not supported by the system).
          10. **Kill-Switch (Reject)**: Terminate any cleartext traffic that bypassed redirection (e.g., pre-existing connections).
6. **DNS** - redirects DNS resolution using a `mount --bind` overlay on `/etc/resolv.conf`.
7. **Bootstrap** - waits for Tor to reach 100% bootstrap via the control interface.
8. **Verification** - confirms traffic is routed through Tor via multiple endpoints (`check.torproject.org`, `ipify`, `ifconfig.me`).
9. **State** - writes a JSON lock file at `/run/ttp/ttp.lock` (volatile) for recovery.
10. **Watchdog** - if `--watchdog` / `-w` is active (or started manually), starts a volatile daemon systemd service (`ttp-watchdog.service`) that verifies Tor, nftables, and DNS overlay mount integrity. If integrity checks fail persistently (two consecutive strikes), it invokes `apply_emergency_killswitch()` to dynamically isolate the network and alert the user via `wall` and desktop notifications.

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
│   ├── install.sh          # System-wide installer
│   ├── uninstall.sh        # System-wide uninstaller
│   ├── restore-network.sh  # Emergency network recovery script
│   ├── verify.sh           # CI/CD verification script
│   └── vm/                 # QEMU VM management scripts
│   └── vms/                # .iso and .qcow2 files
├── assets/                 # Branding and demo assets
│   ├── favicon/            # Project favicons and webmanifest
│   └── gif/                # Demo animations
├── packaging/              # Build scripts for .deb, .rpm, and Arch packages
│   ├── build_deb.sh
│   ├── build_rpm.sh
│   ├── release.sh          # Package release/publish script
│   ├── ttp.spec
│   ├── PKGBUILD
│   └── ttp.service
├── ttp/                    # Source code
│   ├── resources/          # Internal package resources (SELinux policies, etc.)
│   ├── cli.py              # Typer entry point
│   ├── exceptions.py       # Custom exception hierarchy
│   ├── tor_detect.py       # Tor detection logic
│   ├── tor_install.py      # Auto-install & configuration
│   ├── firewall.py         # Atomic nftables management
│   ├── dns.py              # DNS leak prevention
│   ├── state.py            # Lock file and crash recovery
│   ├── tor_control.py      # Tor daemon interaction and API
│   ├── watchdog.py         # Session integrity watchdog and auto-healing
│   └── system_info.py      # System diagnostic gathering
├── tests/                  # Unit tests (mocked) and test_watchdog.py
└── docs/
    ├── architecture.md     # Technical Architecture & Design
    ├── interfaces.md       # External interfaces reference (CLI, Tor, system)
    └── security-assessment.md  # STRIDE threat model & risk assessment
```

## Contributing & Security

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

* Check out our [Contributing Guidelines](CONTRIBUTING.md) to get started.
* Please review our [Security Policy](SECURITY.md) before reporting vulnerabilities.

## Support

This project is maintained in my free time, and donations are highly appreciated.

<div align="center">

Also, if you find **TTP** useful, please consider giving it a **Star**!  
It helps others discover the tool and motivates further development.

[![GitHub stars](https://img.shields.io/github/stars/onyks-os/TransparentTorProxy?style=social)](https://github.com/onyks-os/TransparentTorProxy)

</div>

## License

MIT. See [LICENSE](LICENSE) for more information.
