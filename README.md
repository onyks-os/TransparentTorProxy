<h1 align="center">
  <br>
  🛡️ TTP — Transparent Tor Proxy
  <br>
</h1>

<h4 align="center">A Linux CLI tool that transparently routes <b>all system traffic</b> through the Tor network using nftables.</h4>

<p align="center">
  <img src="https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=for-the-badge&logo=python" alt="Python">
  <img src="https://github.com/onyks-os/TransparentTorProxy/actions/workflows/ci.yml/badge.svg" alt="CI Status">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-requirements">Requirements</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-how-it-works">How It Works</a>
</p>

---

<p align="center">
  <img src="./assets/gif/demo.gif" alt="TTP Demo">
</p>

---

No per-application setup needed — just `sudo ttp start` and **every connection** goes through Tor.

> [!CAUTION]
> TTP is a tool designed to aid privacy by routing traffic through Tor. However, no tool can guarantee 100% anonymity. Your safety also depends on your behavior (e.g., using a regular browser vs. Tor Browser, signing into accounts, etc.). Always use TTP as part of a multi-layered security strategy.

> [!WARNING]
> **If you are a whistleblower or are engaging in high-risk activities, DO NOT use TTP.** Instead, use officially audited and reliable tools like [TailsOS](https://tails.net/) or the [Tor Browser](https://www.torproject.org/) directly. The authors and contributors of TTP assume no responsibility for your safety or the consequences of using this software.

## ✨ Features

* 🌐 **System-wide transparent proxy** — all TCP traffic is redirected to Tor's TransPort, all DNS queries go through Tor's DNSPort.
* 🛡️ **DNS leak prevention** — dual-mode DNS management (`resolvectl` / `resolv.conf` fallback) with symlink-aware detection.
* 🚫 **IPv6 leak prevention** — all outgoing IPv6 is blocked to avoid ISP-level leaks.
* 🔄 **Crash-safe** — a lock file tracks session state; even after `kill -9` or a power outage, the next run detects the orphaned session and restores the network.
* ⚡ **Atomic firewall rules** — `nftables` rules are loaded with `nft -f` (all-or-nothing), avoiding dangerous intermediate states.
* 🎭 **IP rotation** — `ttp refresh` requests a new Tor circuit for a fresh exit IP.
* 🛡️ **SELinux optimization** — Compiles a custom SELinux policy from source (`.te`) on Fedora/RHEL to allow Tor to bind to necessary ports. No opaque binaries shipped.
* 🐧 **Multi-distro** — auto-detects `apt-get`, `pacman`, `dnf`, and `zypper` for Tor installation. Handles Debian multi-instance services (`tor@default`), Fedora (`toranon` user), and more.
* 🛠️ **Auto-configuration** — validates and sanitizes `torrc` before starting, removing invalid settings and appending missing options.

## ⚙️ Requirements

* **Linux** with systemd *(tested on Debian 12+, Ubuntu 22.04+, Fedora 40+, Arch Linux)*
* **Python 3.10+**
* **nftables** *(pre-installed on most modern distros)*
* **Root privileges** *(required for firewall and DNS modifications)*

## 🚀 Installation

Choose the method that best fits your distribution. Native packages are recommended for system stability and better integration.

### 📦 Native Packages (Recommended)

#### **Debian / Ubuntu / Kali / Mint**

Install the pre-built `.deb` package. This automatically handles dependencies like `tor` and `nftables`.

```bash
sudo apt update
sudo apt install ./packaging/ttp_0.1.0_all.deb
```

#### **Fedora / RHEL / AlmaLinux**

Install the native `.rpm`. This package also pre-configures **SELinux** policies for you.

```bash
sudo dnf install ./packaging/ttp-0.1.0-1.fc43.noarch.rpm
```

#### **Arch Linux**

Use the provided `PKGBUILD` to build and install the package via `makepkg`.

```bash
cd packaging && makepkg -si
```

---

### 🛠️ Source Installation (Universal)

If you prefer to install from source or are on a different distribution:

```bash
git clone https://github.com/onyks-os/TransparentTorProxy.git
cd TransparentTorProxy

# For system-wide deployment (creates venv in /opt/ttp)
sudo ./install.sh
```

> [!NOTE]  
> After installation, the `ttp` command is available system-wide.

## 💻 Usage

> [!IMPORTANT]
> All commands require `sudo`. Except `ttp status` and `ttp --help`.

### Start the proxy

```bash
sudo ttp start
```

```text
[TTP] Detecting Tor... found (v0.4.9.6), service active (user: debian-tor).
[TTP] Stateless nftables rules applied (Table: inet ttp).
[TTP] DNS set via resolvectl on interface ens3.
[TTP] Waiting for Tor to bootstrap...
[TTP] Tor is 100% bootstrapped.
[TTP] Verifying Tor routing...
[TTP] ✅ Session active. Exit IP: 109.70.100.11
[TTP] Use 'ttp stop' to terminate. 'ttp refresh' to change IP.
```

### Stop the proxy

```bash
sudo ttp stop
```

```text
[TTP] Removing nftables rules...
[TTP] Restoring DNS...
[TTP] 🔴 Session terminated. Traffic in cleartext.
```

### Change exit IP

```bash
sudo ttp refresh
```

*Sends `NEWNYM` to Tor via the control interface — all active circuits are rotated and you get a new exit IP.*

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

## 🔍 Manual Leak Verification

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
sudo ./uninstall.sh
```

## 🧠 How It Works

1. **Detection** — checks if Tor is installed, which systemd service runs the daemon, and dynamically detects the Tor user.
2. **Installation** — if Tor is missing, detects the system's package manager and installs it automatically.
3. **Configuration** — sanitizes `torrc`, validates with `tor --verify-config`, restarts the correct service.
4. **Firewall** — generates `nftables` rules in a dedicated `inet ttp` table:
      * **Stateless approach** — no system backups needed; cleanup is an atomic `nft destroy table`.
      * **Multi-Chain Protection**:
          * `prerouting`: Intercepts traffic if TTP is used as a gateway.
          * `output` (NAT): Redirects local TCP/DNS to Tor's ports.
          * `filter_out` (Filter): Acts as a **Kill-Switch**.
      * **Execution Sequence**:
          1. **Exclude Tor user** (prevents routing loops).
          2. **Exclude root processes** (system stability).
          3. **Intercept DNS** (UDP `:53`) and redirect to Tor's DNSPort.
          4. **Accept loopback** and local traffic (required for redirected packets).
          5. **Redirect all TCP** to Tor's TransPort (`:9040`).
          6. **Drop all IPv6** output to prevent leaks.
          7. **Kill-Switch (Reject)**: Terminate any cleartext traffic that bypassed redirection (e.g., pre-existing connections).
5. **DNS** — redirects DNS resolution to `127.0.0.1` via `resolvectl` or `/etc/resolv.conf`.
6. **Bootstrap** — waits for Tor to reach 100% bootstrap via the control interface.
7. **Verification** — confirms traffic is routed through Tor via multiple endpoints (`check.torproject.org`, `ipify`, `ifconfig.me`) for resilience.
8. **State** — writes a JSON lock file at `/var/lib/ttp/ttp.lock` for crash recovery.

## 🚑 Crash Recovery

TTP is designed to always restore your network, even in edge cases:

| Scenario | What happens |
| :--- | :--- |
| `ttp stop` | **Normal cleanup**: firewall restored, DNS restored, lock deleted |
| Ctrl+C / `kill` | Signal handler catches `SIGINT`/`SIGTERM` and runs cleanup before exit |
| `kill -9` / Power Outage | Next `ttp start` detects the orphaned lock file and auto-restores the network |
| Manual emergency | Run `sudo ./restore-network.sh` to flush all nftables rules, reset DNS, and delete the lock file |

## ⚠️ Known Behavior

> [!WARNING]
>
> * **Tor Browser**: Applications using an explicit SOCKS5 proxy will create a double Tor hop. Use a regular browser instead while TTP is active.
> * **Chromium-based Browsers (DoH Leak)**: Chrome, Brave, and Edge might use **DNS-over-HTTPS (DoH)**, which bypasses system DNS settings. To prevent leaks:
>   1. Disable **"Secure DNS"** in browser settings.
>   2. **Ideally**, avoid Chromium-based browsers entirely while using TTP; use **Firefox** instead (ensuring its own "DNS over HTTPS" setting is also disabled).
> This still **DOES NOT** ensure the absence of leaks.
> * **IPv6**: All IPv6 traffic is blocked to prevent leaks. Future versions may support IPv6 through Tor.
> * **Exit IP variation**: Different connections may show different exit IPs due to Tor stream isolation. After `ttp refresh`, all connections get new circuits.

## 🛠️ Development

### Running tests

```bash
pip install -e .
pytest tests/ -v
```

*(unit tests run without root on any system, fully mocked).*

### VM testing

Real integration tests should be run in a QEMU VM with snapshots:

```bash
# Start a specific VM (default is debian)
./vm-helpers/start.sh arch

# Save a snapshot before testing (vm_type command name)
./vm-helpers/snapshot.sh arch save pre-test

# Sync code to VM (auto-detects the active one)
./vm-helpers/send.sh

# SSH into the VM and test (port 2223 for Arch)
ssh -p 2223 arch@localhost
cd ~/ttp && pip install -e . && sudo ttp start

# Restore if network breaks
./vm-helpers/snapshot.sh arch load pre-test
```

### Diagnostics

If something goes wrong, run the diagnostic command:

```bash
sudo ttp diagnose
```

## 🗂️ Project Structure

```text
├── pyproject.toml          # Package metadata and dependencies
├── README.md
├── CONTRIBUTING.md         # Contribution guidelines
├── SECURITY.md             # Security policy
├── install.sh              # System-wide installer
├── uninstall.sh            # System-wide uninstaller
├── restore-network.sh      # Emergency network recovery script
├── assets/                 # Branding and system policies
│   ├── gif/                # Demo animations
│   └── selinux/            # SELinux policy source (.te only)
├── packaging/              # Build scripts for .deb, .rpm, and Arch packages
│   ├── build_deb.sh
│   ├── build_rpm.sh
│   ├── ttp.spec
│   ├── PKGBUILD
│   └── ttp.service
├── vm-helpers/             # QEMU VM management scripts
├── ttp/                    # Source code
│   ├── cli.py              # Typer entry point
│   ├── exceptions.py       # Custom exception hierarchy
│   ├── tor_detect.py       # Tor detection logic
│   ├── tor_install.py      # Auto-install & configuration
│   ├── firewall.py         # Atomic nftables management
│   ├── dns.py              # DNS leak prevention
│   ├── state.py            # Lock file and crash recovery
│   ├── tor_control.py      # Tor daemon interaction and API
│   └── system_info.py      # System diagnostic gathering
├── tests/                  # Unit tests (mocked)
└── docs/
    └── TDD.md              # Technical Design Document
```

## 🤝 Contributing & Security

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

* Check out our [Contributing Guidelines](CONTRIBUTING.md) to get started.
* Please review our [Security Policy](SECURITY.md) before reporting vulnerabilities.

## 📄 License

MIT. See [LICENSE](LICENSE) for more information.
