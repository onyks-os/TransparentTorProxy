<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

<h1 align="center">
  TTP - Transparent Tor Proxy
</h1>

<h4 align="center">A Linux CLI tool that transparently routes <b>all system traffic</b> through the Tor network using nftables.</h4>

<p align="center">
  <a href="https://github.com/sponsors/onyks-os"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ff69b4?style=for-the-badge&logo=githubsponsors" alt="Sponsor"></a>
  <img src="https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=for-the-badge&logo=python" alt="Python">
  <a href="https://github.com/onyks-os/TransparentTorProxy/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/onyks-os/TransparentTorProxy/ci.yml?style=for-the-badge&logo=github" alt="CI Status"></a>
  <a href="https://onyks-os.github.io/ttp/"><img src="https://img.shields.io/badge/docs-mkdocs-526CFE?style=for-the-badge&logo=materialformkdocs&logoColor=white" alt="Documentation"></a>
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
  <a href="#verification">Verification</a> •
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
>
> [!WARNING]
> **If you are a whistleblower or are engaging in high-risk activities, DO NOT use TTP.** Instead, use officially audited and reliable tools like [TailsOS](https://tails.net/) or the [Tor Browser](https://www.torproject.org/) directly. The authors and contributors of TTP assume no responsibility for your safety or the consequences of using this software.

## Why TTP?

Legacy transparent proxy scripts (TorGhost, Anonsurf) overwrite configuration
files and build iptables rulesets that fail *open*: when they break, traffic
leaves in cleartext. TTP is built the other way round - it fails closed, and
keeps nothing on disk.

| | |
| :--- | :--- |
| **Fail-closed by construction** | An isolated `inet ttp` nftables table with a catch-all reject and `policy drop` on forwarding. On a crash, a watchdog trigger or an unclean exit, traffic is either routed through Tor or blocked - never released. |
| **Nothing persists** | Session state, torrc, lock file and logs live only in `tmpfs` (`/run/ttp/`, `/run/tor/ttp/`). A reboot leaves no residue and no stale lock. |
| **No per-application setup** | TCP and DNS are intercepted at the network layer. No SOCKS5 settings, no proxy environment variables, no application support required. |
| **DNS without rewriting your system** | A `mount --bind` overlay on `/etc/resolv.conf` rather than an edit, plus a volatile drop-in that neutralises `systemd-resolved`, backed by a kernel-level drop on any non-loopback resolver traffic. |
| **The leak claim is measured** | Every containment rule is tested in an isolated network namespace against the real generated ruleset, and each test first proves it can *see* a leak before asserting there is none. See [Verification](#verification). |

## Features

* **Continuous integrity protection** - a watchdog governed by a formal FSM
  (`transitions`) monitors Tor, the nftables chains and the DNS overlay via a
  double inotify watch that catches symlink-target swapping. It repairs once,
  then applies an emergency killswitch.
* **Split tunnelling** - exempt users or groups (`--bypass-user`,
  `--bypass-group`) with native nftables UID/GID matching, or run a single
  command outside Tor with `ttp bypass <cmd>` via a cgroups v2 slice.
* **LAN preserved** - RFC 1918 and link-local subnets stay reachable, so your
  printer and NAS keep working.
* **Dual-stack, or no stack** - IPv6 is routed through Tor when loopback
  routing is available, and dropped outright when it is not. There is no third
  option where it leaks.
* **DoT and DoH blocked** - port 853 rejected, known public DoH resolvers
  rejected on 443 (TCP and QUIC), and browser canary domains poisoned in
  `torrc`.
* **Coexists with your system Tor** - runs its own volatile `ttp-tor.service`
  on non-standard ports, leaving an existing Tor instance untouched.
* **Bridges** - obfs4 and snowflake, with BYOD (bring your own daemon) mode.

## Requirements

* **Linux with systemd**
* **Python 3.10+**
* **nftables** (pre-installed on most modern distros)
* **Root privileges** (required for firewall and DNS modifications)

## Installation

Choose the method that best fits your needs. **Native packages are strongly recommended** for system stability, security, and clean uninstallation.

### 1. Native Packages (Recommended)

Installing via native packages ensures that all system dependencies (`tor`, `nftables`) and kernel-level optimizations (SELinux) are managed by your OS package manager.

Download the `.deb` or `.rpm` for the version you want from the [latest release](https://github.com/onyks-os/TransparentTorProxy/releases/latest) - the packages are release assets and are not checked into the repository - then install it:

* **Debian / Ubuntu**: `sudo apt install ./transparent-tor-proxy_0.4.8_all.deb`
* **Fedora / RHEL**: `sudo dnf install ./transparent-tor-proxy-0.4.8-1.noarch.rpm`
* **Arch Linux**: build from the repository with `cd packaging && makepkg -si`

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

### 3. Alternative Installation Methods (Fallback)

For installing TTP via Python-specific package managers (`pipx` or `pip` with virtual environments), see the [Alternative Installation Methods Reference](docs/install-alternatives.md).

## Usage

TTP is designed to be simple and lightweight. For the complete list of CLI commands, options, exit codes, and technical specifications, refer to the [External Interfaces Reference](docs/interfaces.md).

### Quick Start

Most network-modifying commands require root privileges (`sudo`):

* **Start the proxy**:

  ```bash
  sudo ttp start
  ```

* **Stop the proxy**:

  ```bash
  sudo ttp stop
  ```

* **Check current session status**:

  ```bash
  ttp status
  ```

* **Verify Tor routing and latency**:

  ```bash
  ttp check
  ```

* **Request a new exit IP (rotate circuits)**:

  ```bash
  sudo ttp refresh
  ```

For more advanced setups and circumvention profiles, see the [Advanced Security & Usage Profiles Reference](docs/profiles.md) or consult the [External Interfaces Reference](docs/interfaces.md).

## Checking Your Session

<details>
<summary>Click to expand manual verification steps</summary>

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

</details>

### Full Uninstallation

To remove TTP completely from the system:

```bash
sudo ./scripts/uninstall.sh
```

## How It Works

TTP transparently routes all network traffic by orchestrating standard Linux kernel subsystems, system utilities, and Tor's control interfaces:

```mermaid
flowchart LR
    App["Application"] --> Local["Local Network"]
    Local --> DNS["systemd-resolved (Intercepted)"]
    DNS --> NFT["nftables (inet ttp table)"]
    NFT --> Tor["Tor Daemon"]
    Tor --> Internet["Internet"]
```

1. **Atomic Firewall Redirection**: Generates and loads an isolated `inet ttp` nftables ruleset atomically to intercept TCP and DNS traffic, redirecting them to Tor while preventing IPv6 and DoT/DoH leaks.
2. **DNS Bind-Mount Overlay**: Overlays `/etc/resolv.conf` with a volatile RAM-backed configuration via a kernel-level bind-mount to ensure DNS calls are resolved by Tor.
3. **Tor Daemon Integration**: Configures, runs, and monitors an isolated Tor instance via volatile systemd services on non-standard ports to prevent port conflicts.
4. **Session Watchdog**: Runs an active background monitor that verifies configuration integrity and executes a fail-closed emergency killswitch upon security breach or system modification.

For a detailed walkthrough of the execution flows, system hooks, security boundaries, and modular components, please refer to the:

**[Technical Architecture & Design Guide](docs/architecture.md)**

## Crash Recovery

TTP is designed to always restore your network, even in edge cases:

| Scenario                 | What happens                                                                                                                                                                                                                              |
| :----------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ttp stop`               | **Zero-leak cleanup**: applies teardown lockdown, gracefully shuts down Tor, executes active socket slaughter, waits 1.5s, flushes connection tracking, restores firewall and DNS (via table flush and delete), and deletes the lock file |
| Ctrl+C / `kill`          | Signal handler catches `SIGINT`/`SIGTERM` and runs normal cleanup before exit                                                                                                                                                             |
| `kill -9` / Power Outage | Next `ttp start` detects the orphaned lock file, clears any stale mount stacks, and auto-restores                                                                                                                                         |
| Manual emergency         | Run `sudo ./scripts/restore-network.sh` to flush all nftables rules, reset DNS, and delete the lock file                                                                                                                                  |

## Known Behavior & Limitations

> [!WARNING]
>
> * **Tor Browser**: Applications using an explicit SOCKS5 proxy will create a double Tor hop. Use a regular browser instead while TTP is active.
> * **DNS-over-HTTPS (DoH)**: Normal browsers (Firefox, Chrome, Brave, Edge) may use DoH, bypassing system DNS. TTP mitigates DoH via a 3-layer defense: (1) all outbound TCP traffic (including DoH) is redirected to Tor TransPort; (2) common DoH canary domains are mapped to `0.0.0.0` in `torrc`; (3) public DoH IP resolvers are blocked on TCP/UDP port 443 (blocking HTTP/3 QUIC DoH). For maximum security, disable **DoH / "Secure DNS"** in your browser settings.
> * **IPv6**: Fully supported when available. TTP dynamically detects IPv6 loopback and routes IPv6 traffic through Tor. If the host lacks IPv6 loopback support OR if the `--no-ipv6` option is passed, TTP drops all outgoing IPv6 traffic to prevent leaks.
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

## Verification

TTP's zero-leak claim is measured, not asserted. The
[Network Sandbox Engine](https://github.com/onyks-os/NetworkSandboxEngine) builds
an isolated network namespace, loads TTP's *real* generated ruleset into it,
generates the traffic a leak would consist of, and watches the boundary `veth`
interface with a Scapy sniffer.

**Every containment test runs twice.** `assert no leaks` is also true when the
sniffer never started, when the interface name is wrong, or when the traffic
never left the process, so each test first runs the same stimulus with the
ruleset **flushed** and requires the packet to be seen. Only then does it assert
that TTP's ruleset stops it. A harness that cannot observe a leak fails the
test rather than passing it.

Covered: plain DNS (UDP and TCP), ordinary TCP, DoT on 853, QUIC DoH on UDP/443,
ICMP, arbitrary UDP, IPv6 — plus the other direction, that a bypassed UID can
still reach the LAN. A firewall that blocked everything would pass the first
seven and fail the eighth.

```bash
# libpcap is required: the sniffer compiles a BPF filter, and Scapy dlopen()s
# the unversioned libpcap.so that only the -devel/-dev package ships.
sudo apt install nftables iproute2 conntrack libpcap0.8 libpcap-dev   # Debian/Ubuntu
sudo dnf install nftables iproute2 conntrack libpcap libpcap-devel    # Fedora/RHEL
pip install -e ".[nse]"
make test-nse            # runs as root; TTP_REQUIRE_NSE=1 so it cannot skip itself
```

This runs in CI on every push (the **Zero-leak ruleset verification** job) and as
a step in `scripts/verify.sh` before a release.

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
├── scripts/                # Installation, verification, and VM management scripts
├── assets/                 # Branding and demo assets
├── packaging/              # Packaging configurations (.deb, .rpm, Arch PKGBUILD)
├── ttp/                    # Main Python source package
│   └── resources/          # Internal package resources (SELinux policies, etc.)
├── tests/                  # Unit, integration, and leak testing suites
└── docs/                   # Technical documentation, threat models, and ADRs
```

## Contributing

Contributions are welcome, and the areas where help matters most are narrow and
specific:

1. **Linux networking** - nftables, routing tables, network namespaces, VPN
   interface detection.
2. **Tor internals** - daemon configuration, Stem, bridges, bootstrap edge cases.
3. **CI/CD** - keeping the privileged test suites fast and reliable on GitHub
   Actions.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), which documents the two rules this
codebase is built on: never fix a bug without adding the check that would have
caught it, and a test that asserts an absence must first prove it can detect a
presence.

| | |
| :--- | :--- |
| Bugs and feature requests | [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues) |
| Security vulnerabilities | [SECURITY.md](SECURITY.md) - please do not open a public issue |
| Version support and EOL | [SUPPORT.md](SUPPORT.md) |
| Releases and packages | [GitHub Releases](https://github.com/onyks-os/TransparentTorProxy/releases) · [PyPI](https://pypi.org/project/transparent-tor-proxy/) |

This project is maintained in free time. A [star](https://github.com/onyks-os/TransparentTorProxy)
helps others find it; [sponsorship](https://github.com/sponsors/onyks-os) helps
it keep going.

## License

MIT. See [LICENSE](LICENSE) for more information.
