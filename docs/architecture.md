# TTP - Technical Architecture & Design

**MVP Language:** Python 3  

* **Target OS:** Any systemd-based Linux distribution *(Debian, Ubuntu, Fedora, Arch, etc.)*

---

## Table of Contents

1. [Project Goal](#1-project-goal)
2. [Module Architecture](#2-module-architecture)
3. [Module Details](#3-module-details)
4. [Command Line Interface](#4-command-line-interface)
5. [Dependencies](#5-dependencies)
6. [Project Structure](#6-project-structure)
7. [Branding & Assets](#7-branding--assets)
8. [Deployment & Installation Logic](#8-deployment--installation-logic)
9. [Packaging Pipeline](#9-packaging-pipeline)
10. [Development and Test Environment](#10-development-and-test-environment)
11. [Unit Tests - Specifications](#11-unit-tests--specifications)

**Related documents:**
- [interfaces.md](interfaces.md) — Full CLI, Tor, and system interface reference (OSPS-SA-02.01)
- [security-assessment.md](security-assessment.md) — STRIDE threat model and risk assessment (OSPS-SA-03.01)

---

## 1. Project Goal

**TTP (Transparent Tor Proxy)** is a CLI tool for Linux that intercepts all outgoing network traffic from a user and forces it through the Tor network, without requiring per-application manual configuration.

Unlike similar tools (TorGhost, Anonsurf), TTP is designed to:

* Work on any modern Linux distribution with systemd and nftables.
* Be **crash-safe**: the network state is always restored.
* Be readable and maintainable.
* Be distributable as native system packages (`.deb`, `.rpm`, `PKGBUILD`).

---

## 2. Module Architecture

The project is divided into independent Python modules. Each module has a single responsibility and can be tested in isolation.

| Module           | Area             | Responsibility                                                                   |
| :--------------- | :--------------- | :------------------------------------------------------------------------------- |
| `tor_detect.py`  | **Detection**    | Checks Tor presence, status, config, user, and SELinux state.                    |
| `tor_install.py` | **Installation** | Installs Tor via PM, manages SELinux policies, configures `torrc`.               |
| `firewall.py`    | **Firewall**     | Generates and applies `nftables` rules in isolated `inet ttp` table (Stateless). |
| `dns.py`         | **DNS**          | Manages DNS via Kernel-level `mount --bind` overlay.                             |
| `state.py`       | **State**        | Manages volatile lock file in `/run/ttp` and recovery logic.                     |
| `tor_control.py` | **Control**      | Encapsulates Tor interaction (Stem, Bootstrap, IP Check).                        |
| `system_info.py` | **Diagnostic**   | Gathers system state (torrc, rules, logs) for debugging.                         |
| `watchdog.py`    | **Watchdog**     | Manages the session background watchdog, auto-healing, and emergency killswitch. |
| `cli.py`         | **Interface**    | Typer entry point: start, stop, refresh, status, check, logs, etc.               |

### 2.1 Execution Flow - `start`

1. **cli**: Verifies root execution.
2. **state**: Checks for existing/orphaned locks and verifies `tmpfs` free space (**pre-flight check**).
3. **detect**: Verifies Tor installation and config.
4. **install**: Installs/configures Tor if missing. Performs **SELinux optimization** on Fedora.
5. **firewall**: Generates and atomically applies rules in isolated `inet ttp` table.
6. **dns**: Clears any stale overlays (idempotency guard), then modifies active interface DNS using `mount --bind` overlay on `/etc/resolv.conf`.
7. **state**: Initializes volatile runtime in `/run/ttp` and writes lock file.
8. **cli**: Waits for Tor bootstrap via ControlSocket, verifies IP.
9. **watchdog**: Starts the volatile systemd watchdog service (`ttp-watchdog.service`) if watchdog monitoring is enabled.
10. **cli**: Returns to the prompt.

### 2.2 Execution Flow - `stop` / crash

> [!NOTE]  
> **Normal:** `ttp stop` -> stops the watchdog service -> graceful Tor `SHUTDOWN` -> restores firewall/DNS -> deletes lock.

> [!TIP]
> **Emergency Restore:** `ttp stop --restore-only` bypasses session checks and forces network cleanup. Useful if TTP crashed and the lock file was lost.

> [!WARNING]
> **Crash (SIGTERM/SIGINT):** Signal handler ensures restoration before shutdown.

> [!IMPORTANT]
> **Worst-case (kill -9):** Next `ttp start` detects orphaned lock and auto-restores.

### 2.3 Flow - `refresh`

Sends `NEWNYM` signal via Stem. Tor changes circuits. Traffic flows normally during the switch.

---

## 3. Module Details

### 3.1 `tor_detect.py`

Module functionality:

* Installed? (`shutil.which`)
* Running? (`pgrep -x tor`)
* Configured? (Checks `TransPort`, `DNSPort`, `ControlSocket`)
* User? (Live inspection `ps -eo user:32,comm` -> `/etc/passwd` -> fallback)
* SELinux? (Checks if OS is Fedora-family and if SELinux is `Enforcing`)
* **Firewalld?** (Detects if `firewalld` is active to warn about potential `nftables` conflicts).

### 3.2 `tor_install.py`

Intervenes if detection fails or system needs optimization.

1. Detects package manager (`apt-get`, `pacman`, `dnf`, `zypper`).
2. Installs `tor`.
3. **SELinux Optimization**: If on Fedora and enforcing, compiles the custom SELinux policy on-the-fly. The policy source (`.te`) is stored as an internal package resource and accessed via `importlib.resources`.
4. Generates a volatile `torrc` in `/run/tor/ttp/torrc`.
5. Writes a dedicated `ttp-tor.service` unit to `/run/systemd/system/` (volatile, evaporates on reboot).
6. Starts the TTP Tor instance via `systemctl start ttp-tor`.

### 3.3 `firewall.py`

Generates rules applied atomically via `nft -f` into the dedicated `inet ttp` table.

**Design principles:**

1. **Stateless Logic**: No system-wide rule backups are performed. All modifications are isolated to the `ttp` table.
2. **Atomic Cleanup**: Restoration is performed via `nft destroy table inet ttp`, faster and safer than rule-by-rule deletion.
3. **Multi-Chain Architecture**: A NAT hook (`output`/`prerouting`) handles redirection to Tor ports; a filter hook (`filter_out`) implements the Kill-Switch, rejecting everything that is not explicitly allowed.
4. **Split Tunneling**: UIDs/GIDs are resolved via Python's `pwd`/`grp` libraries and injected as `meta skuid`/`meta skgid` rules — no shell interpolation.
5. **Emergency Killswitch**: `apply_emergency_killswitch()` replaces the table with a minimal drop-all configuration (loopback exempt), used by the watchdog on persistent integrity failure.

> For the complete chain structure, rule execution order, and external interface specification see [`interfaces.md § 3.1`](interfaces.md#31-nftables-firewall).

### 3.4 `dns.py`

Implements a **stateless overlay** by bind-mounting a volatile resolver file from `/run/ttp/resolv.conf` over `/etc/resolv.conf`.

**Design rationale:**

* **Non-destructive by design**: The original file is never modified on disk — the overlay is transparent to the OS and evaporates on reboot.
* **Idempotency guard**: Before applying, `/proc/mounts` is scanned to remove any stale layers from prior unclean exits, ensuring multiple invocations are safe.
* **Symlink safety**: The real path of `/etc/resolv.conf` is resolved before mounting (common issue on systemd-managed systems where it is a symlink to `systemd-resolved`).
* **DoH/DoT mitigation**: DoT is blocked at the firewall layer (`firewall.py`); well-known DoH resolver IPs are blocked on port 443 to trigger system fallback; other unlisted DoH is routed through Tor; and DoH canary domains are mapped to `0.0.0.0` in the generated `torrc` to disable browser-level DoH where supported.

> For mount source/target paths, teardown behavior, and the full attribute table see [`interfaces.md § 3.2`](interfaces.md#32-dns-subsystem).

### 3.5 `state.py`

Manages `/run/ttp/ttp.lock` (JSON) on a volatile `tmpfs` mount. This ensures that session state disappears on power loss, preventing stale lock issues. Contains PID, timestamps, and metadata. Detects orphaned sessions. Also handles the **tmpfs pre-flight check** (`check_tmpfs_space`) to ensure at least 5MB of RAM is free before starting, preventing `ENOSPC` crashes mid-setup.

### 3.6 `cli.py`

Typer CLI acting as the primary orchestrator. It manages the **TTP Tor service lifecycle** via a dedicated `ttp-tor.service` unit, handling signals (`SIGINT`/`SIGTERM`) to ensure clean network restoration.

> For the full command reference, options, exit codes, and root-privilege requirements see [`interfaces.md § 1`](interfaces.md#1-command-line-interface-cli).

### 3.7 `tor_control.py`

Encapsulates all communication with the Tor daemon.

* Connects to Tor's ControlPort/ControlSocket.
* Monitors bootstrap progress.
* Requests new circuits via `Signal.NEWNYM`.
* Executes graceful teardown via `Signal.SHUTDOWN` to close circuits cryptographically before network restoration.
* Verifies exit IP via multiple endpoints for resilience (`check.torproject.org`, `ipify`, `ifconfig.me`).

### 3.8 `system_info.py`

Pure data gathering module, decoupled from UI.

* Reads `/etc/os-release`.
* Captures Tor service status via `systemctl status`.
* Greps active `torrc` settings.
* Captures `nft list ruleset`.
* Captures DNS state from `/etc/resolv.conf` overlay.
* Returns results as a flat dictionary for the CLI to render.

### 3.9 `watchdog.py`

Implements continuous, proactive session monitoring and auto-healing features to ensure absolute traffic security.

* **Volatile Service Daemon**: Configures and writes a dynamic systemd service unit (`/run/systemd/system/ttp-watchdog.service`) that runs the command `ttp watchdog run`. Because it resides in `/run/`, it evaporates on system reboot.
* **Continuous Monitoring Loop**: Inspects the core subsystems every 15 seconds:
  1. **DNS Integrity**: Confirms `/etc/resolv.conf` (or its realpath) is still a valid active `mount --bind` mountpoint.
  2. **Firewall Integrity**: Confirms that the `inet ttp` nftables table exists and contains the `filter_out` chain, as well as verifying any active bypass exceptions (users/groups) registered in the session lock.
  3. **Tor daemon health**: Confirms the ControlSocket is open and active, falling back to checking if the systemd `ttp-tor.service` is in an active state.
* **Auto-Healing ("First Strike")**: If an integrity check fails, the watchdog triggers a single-strike recovery attempt based on the failing component (e.g. re-running DNS overlay, regenerating firewall rules including bypass configurations, or restarting the `ttp-tor` service). It then sleeps for 3 seconds to let changes stabilize.
* **Emergency Killswitch ("Second Strike")**: If the subsequent check still fails, the watchdog instantly activates the emergency killswitch via `firewall.apply_emergency_killswitch()`, completely isolating the physical network interfaces to prevent traffic leakage. It then alerts the user using a system-wide terminal broadcast (`wall`) and a critical desktop popup (`notify-send`).

### 3.10 Architecture Graph & Module Interactions

The following dependency graph illustrates how modules interact with each other and with the underlying Linux system. `cli.py` acts as the controller, coordinating the specialized modules, and `watchdog.py` runs as a daemon monitoring session health.

```mermaid
%%{init: {
  "flowchart": {"defaultRenderer": "elk"},
  "theme": "base",
  "themeVariables": {
    "fontFamily": "JetBrains Mono, monospace",
    "background": "transparent",
    "lineColor": "#4a4a4a",
    "textColor": "#9ca3af"
  }
}}%%
graph TD
    classDef orchestrator fill:#0a0a0a,stroke:#22d3ee,stroke-width:2px,color:#fff,rx:6px,ry:6px
    classDef module fill:#0a0a0a,stroke:#262626,stroke-width:1px,color:#e5e5e5,rx:6px,ry:6px
    classDef system fill:#111111,stroke:#22d3ee,stroke-width:1px,stroke-dasharray: 4 4,color:#22d3ee,rx:6px,ry:6px

    %% Nodes
    CLI["cli.py<br/>Controller"]:::orchestrator
    
    STATE["state.py<br/>Lock & Recovery"]:::module
    DETECT["tor_detect.py<br/>Inspection (Read-Only)"]:::module
    INSTALL["tor_install.py<br/>System Mod (Read/Write)"]:::module
    FIREWALL["firewall.py<br/>nftables"]:::module
    DNS["dns.py<br/>Routing"]:::module
    CONTROL["tor_control.py<br/>Stem / Tor API"]:::module
    SYSINFO["system_info.py<br/>Diagnostics"]:::module
    WATCHDOG["watchdog.py<br/>Session Integrity"]:::module

    TOR(("Tor Daemon")):::system
    KERNEL(("Linux Kernel / OS")):::system

    %% Orchestrator Flow
    CLI -->|1. Manages session| STATE
    CLI -->|2. Prepares environment| INSTALL
    CLI -->|3. Injects routing| FIREWALL
    CLI -->|4. Redirects queries| DNS
    CLI -->|5. Starts ttp-tor| TOR
    CLI -->|6. Verifies & rotates IP| CONTROL
    CLI -->|7. Starts integrity checks| WATCHDOG
    CLI -->|Generates reports| SYSINFO

    %% Inter-module Dependencies
    INSTALL -->|Uses to verify state| DETECT
    SYSINFO -->|Reads current state| DETECT
    SYSINFO -->|Reads lock file| STATE
    SYSINFO -->|Reads DNS config| DNS
    SYSINFO -->|Checks Bootstrap| CONTROL
    WATCHDOG -->|Reads state lock| STATE
    WATCHDOG -->|Restores DNS overlay| DNS
    WATCHDOG -->|Re-applies/isolates firewall| FIREWALL

    %% System Interactions
    INSTALL -->|Generates volatile torrc & unit| KERNEL
    FIREWALL -->|Creates 'inet ttp' table| KERNEL
    DNS -->|mount --bind overlay| KERNEL
    DETECT -->|Scans processes & OS| KERNEL
    TOR -->|Managed via systemctl| KERNEL
    CONTROL -->|ControlSocket / Port| TOR
    WATCHDOG -->|Monitors ttp-tor & writes service| KERNEL
```

---

## 4. Command Line Interface

The full CLI reference — all commands, options, exit codes, and privilege requirements — is maintained as the single authoritative source in:

**[`docs/interfaces.md § 1 — Command Line Interface`](interfaces.md#1-command-line-interface-cli)**

Duplicated inline lists are intentionally omitted here to avoid version skew.

---

## 5. Dependencies

| Library    | Source | Purpose                            |
| :--------- | :----- | :--------------------------------- |
| `stem`     | PyPI   | Tor daemon control via Socket/Port |
| `typer`    | PyPI   | CLI framework                      |
| `rich`     | PyPI   | Terminal styling                   |
| `tor`      | System | Tor daemon                         |
| `nftables` | System | Firewall backend                   |

---

## 6. Project Structure

*(See README.md for full tree. Uses standard `pyproject.toml` distribution).*

---

## 7. Branding & Assets

TTP follows a consistent visual identity to ensure professional representation across documentation and web-based platforms.

| Asset            | Path                              | Usage                                                     |
| :--------------- | :-------------------------------- | :-------------------------------------------------------- |
| **Project Logo** | `assets/icon.png`                 | Main branding, README header, and social previews.        |
| **Favicon Set**  | `assets/favicon/`                 | Icons for web documentation and browser-based interfaces. |
| **Web Manifest** | `assets/favicon/site.webmanifest` | PWA and mobile-friendly metadata.                         |

The brand color palette is primarily **Black (#000000)** and **Cyan (#22d3ee)**, reflecting the tool's focus on privacy and high-performance networking.

---

## 8. Deployment & Installation Logic

TTP supports multiple installation methods, ranked by their ability to handle system-level dependencies and security policies.

### 8.1 Hierarchy of Installation

1. **Native Packages (`.deb`, `.rpm`, `PKGBUILD`) [Recommended]**: The most robust method. The OS package manager handles `tor` and `nftables` installation and ensures that SELinux policies (on Fedora) are registered at the kernel level.
2. **Universal Source Script (`scripts/install.sh`)**: An "intelligent" installer that creates an isolated virtual environment in `/opt/ttp`. It detects the host OS and, if SELinux is *Enforcing*, it compiles the `ttp_tor_policy.te` policy module on the fly.
3. **Python Packaging (`pipx`, `pip`) [Fallback]**: Standard Python distribution. While convenient, this method cannot install system dependencies or compile SELinux policies.

### 8.2 PEP 668 & System Stability

Modern Linux distributions (Ubuntu 23.04+, Debian 12+) implement **PEP 668** (Externally Managed Environments), which blocks global `pip install`.

* TTP recommends using **pipx** for a clean, isolated Python-only install.
* Manual venv management is supported for advanced users.

### 8.3 The SELinux Factor

A key architectural feature is the **dynamic SELinux policy**. Because Tor is restricted by default on RHEL/Fedora, it cannot bind to ports like 9040 (TransPort) without specific permissions.

* The **Native RPM** and the **Source Installer** both handle this by compiling a type-enforcement file into a binary policy module.
* **pip/pipx** installations will likely fail on Fedora unless the user manually handles SELinux or sets it to *Permissive* mode.

### 8.4 Uninstallation Safety

Because TTP modifies core network settings (Firewall and DNS), uninstallation requires care.

* **Native packages** use `prerm` or `preun` scripts to ensure the network is restored before the code is removed.
* **Source uninstaller** (`scripts/uninstall.sh`) explicitly calls `ttp stop` and `restore-network.sh`.
* **pipx/pip** users must manually run `ttp stop` before removing the package, as the Python package manager has no hook to restore system state.

---

## 9. Packaging Pipeline

Building system packages is handled by scripts in the `packaging/` directory:

* `release.sh`: Orchestrates the full release: Python wheel/sdist build + `twine check`, cleanup of prior artifacts, `.deb` (via `build_deb.sh`), `.rpm` when `rpmbuild` is available (via `build_rpm.sh`), and `SHA256SUMS.txt` for the produced packages. Invoked by `make build`.
* Step 0 runs `python -m build` with `TMPDIR` set **only for that command** to a project-local `.build_tmp` directory on disk. That avoids heavy use of RAM-backed `/tmp` on memory-constrained machines. The variable is not exported to the rest of the script so downstream tools (for example `dpkg-deb` inside `build_deb.sh`) keep using the system default temporary directory.
* `build_deb.sh`: Generates a Debian archive.
* `build_rpm.sh`: Generates a Fedora RPM (requires `rpm-build`).
* `PKGBUILD`: Standard Arch build recipe.

---

## 10. Development and Test Environment

### QEMU VM Configuration

* **OS:** Debian 13 (Trixie) Netinstall
* **Network:** NAT + Host-Only (SSH)
* **Workflow:** Code on host -> `scripts/vm/send.sh` or `rsync` -> Test on VM via SSH.

### CI/CD Automation (Makefile)

TTP employs a `Makefile` in the root directory to provide a unified entry point for local CI/CD. This ensures atomicity and consistency across different developer environments.

* **`make test`**: Executes unit tests via `pytest` (Phase 1).
* **`make integration-<distro>`**: Orchestrates Docker-based system tests for a specific distribution (Phase 2).
* **`make verify`**: The mandatory pre-commit pipeline. It runs the full suite (Unit + all Integration tests).
* **`make build`**: Compiles native system packages (`.deb`, `.rpm`) using the logic in `packaging/`.
* **`make clean`**: Purges all temporary build artifacts, `__pycache__`, and compiled packages.
* **`make pypi` / `make testpypi`**: Automates the build and upload of Python wheels to PyPI/TestPyPI.

### Testing Strategy

| Phase | Environment      | Goal                           | Status                      |
| :---- | :--------------- | :----------------------------- | :-------------------------- |
| 1     | Unit (Host)      | pytest, fully mocked           | PASS                        |
| 2     | Integration      | Docker testing (`.test` files) | PASS (Debian, Arch, Fedora) |
| 3     | Portability (VM) | Debian 13, Ubuntu              | PASS                        |

---

## 11. Unit Tests - Specifications

*(Tests run without root, using `unittest.mock`)*

* **`test_tor_detect.py`**: Verifies dictionary output across varying torrc and process states.
* **`test_firewall.py`**: Asserts DNS redirect appears BEFORE LAN bypass (critical - gateway DNS leak prevention), BEFORE loopback accept, BEFORE TCP redirect. Verifies IPv6 drop (when unsupported) or redirection (when supported), DoT rejection, DoH IP-level blocking, bypass user/group (split tunneling) rule injection, and emergency killswitch table application.
* **`test_dns.py`**: Asserts correct mount --bind overlay, stale mount cleanup, and lazy umount.
* **`test_state.py`**: Asserts lock creation, reading, and orphan detection.
* **`test_cli.py`**: Verifies command orchestration, option injection, UI flow, and non-root OSError safety.
* **`test_tor_control.py`**: Verifies Tor daemon interaction, IP checking logic, and circuit bootstrap/rotation.
* **`test_tor_install.py`**: Asserts correct PM selection, torrc generation (including DoH blocking mapping), and service management.
* **`test_watchdog.py`**: Verifies volatile systemd unit generation, watchdog start/stop flow (mocking systemctl commands), integrity check behavior under healthy/failing states, auto-healing routing for DNS/Firewall/Tor, emergency killswitch execution, and watchdog main loop iteration logic.
