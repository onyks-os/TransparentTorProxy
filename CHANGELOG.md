<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.6] - 2026-06-25

### Added

- **Application Exclusion via cgroups v2 Bypass (`ttp bypass`)**: Added the new `ttp bypass <command>` CLI command. This command de-escalates privileges securely to the invoking user and runs the target application inside a systemd transient scope under `ttp-bypass.slice` using `systemd-run`.
- **cgroups v2 Firewall Rules**: Configured `apply_rules()` to inject `socket cgroupv2 level 1 "ttp-bypass.slice" accept` into the `output` NAT and `filter_out` filter chains, allowing any processes running inside the slice to bypass Tor transparent proxying atomically.
- **Privilege-Separated Watchdog User**: Added system user and group `ttp-watchdog` configuration to run the background watchdog daemon with only `CAP_NET_ADMIN` capabilities instead of root (`CAP_SYS_ADMIN`).
- **Polkit Authorization Rules**: Added `ttp/resources/polkit/50-ttp-watchdog.rules` to authorize the `ttp-watchdog` user to restart the Tor daemon and watchdog services via systemd without elevated privileges.
- **Fail-Closed Watchdog Policy**: Modified the watchdog to implement a strict fail-closed policy. Under DNS overlay mount or firewall tampering/failure, the watchdog immediately applies the emergency killswitch and halts (rather than attempting unsafe file-modifying operations without root privileges).
- **Arch, Debian, RPM, and Installer Integration**: Updated installers and packages to dynamically create the `ttp-watchdog` system user and group, deploy the Polkit policy rule, and clean them up during uninstallation.
- **CLI Thin Orchestrator (Modularization)**: Refactored the monolithic `cli.py` (previously over 1200 lines) into a pure, thin Typer orchestrator (under 150 lines). All operational logic has been extracted into isolated command modules under `ttp/commands/` (e.g., `start.py`, `stop_restart.py`, `session.py`, `admin.py`, `watchdog.py`), dramatically improving maintainability and testability.
- **Micro-Sleep Teardown Optimization**: Refined the "Zero-Leak" graceful shutdown sequence. Reduced the socket slaughter wait time from 1.5 seconds down to a precise 300ms micro-sleep, significantly accelerating the shutdown process without compromising the delivery of TCP RST and ICMP Port Unreachable packets.
- **Protocol-Specific Socket Slaughter**: Hardened the Active Socket Slaughter implementation by explicitly targeting UDP connections with `meta l4proto udp counter reject` rather than relying on a generic reject, ensuring precise ICMP error generation for pending connections.

### Changed

- **Systemd Hard Requirement**: Declared systemd as strictly required for TTP. Start, restart, and bypass CLI commands check for systemd on startup and fail immediately with a descriptive error message if missing. Removed references to systemd-less environments, Alpine Linux, or Void Linux in documents, ADRs, and help strings.
- **Bypass Command Sudo Check**: Improved the `ttp bypass` CLI command to fail early with a clean, descriptive error message ("This command must be run with sudo to safely delegate privileges via systemd-run.") if executed without `sudo` or outside a `sudo` environment.

## [0.4.5] - 2026-06-21

### Added

- **Zero-Leak Shutdown (Graceful Teardown with Active Socket Slaughter)**: Implemented a multi-stage active socket termination and lockdown sequence during `ttp stop` to eliminate in-flight cleartext traffic leaks. Before final firewall ruleset removal, a temporary lockdown drop rule is applied (exempting the Tor daemon), followed by an **Active Socket Slaughter** phase injecting TCP Reset (`meta l4proto tcp counter reject with tcp reset`) and standard reject rules with a 1.5-second micro-delay. This actively terminates pending local connections before lowering the firewall.
- **Connection Tracking Flush**: Added automatic Netfilter connection tracking state invalidation via `conntrack -F` (when the `conntrack` utility is available) to terminate active TCP/UDP streams before final firewall ruleset removal.
- **IPv6 Force Disable Flag**: Added `--no-ipv6` CLI option to `start` and `restart` commands, allowing users to force drop all outbound IPv6 traffic via `nftables` rules (`meta nfproto ipv6 drop`) to prevent leaks even if the host machine supports IPv6.
- **System Integrity Watchdog Auto-Healing for IPv6**: Integrated `--no-ipv6` state checking into the session watchdog. During auto-healing operations, the watchdog reads the state lock and correctly re-applies firewall, DNS, and Tor configurations with IPv6 disabled if configured.
- **CLI Reports for IPv6 Status**: Updated `status` and `check` commands to explicitly show the status of IPv6 traffic routing: `Enabled (Redirected)`, `Disabled (Force Dropped)`, or `Disabled (Not supported by host)`.
- **Bring Your Own Daemon (BYOD) Mode**: Added `--external-daemon` and `--tor-uid` CLI options to both `start` and `restart` commands, allowing TTP to run on systemd-less environments (such as Alpine Linux or Void Linux) and inside lightweight Docker containers.
- **Passive Health Check & UID Parser**: Implemented socket owner auto-detection reading `/proc/net/tcp` and `/proc/net/tcp6` to find Tor's numeric UID (resolving firewall loops), alongside passive TCP/UDP port checks on the target ports when using `--external-daemon`.
- **Network Sandbox Engine (NSE) Integration**: Fully integrated the PyPI package `network-sandbox-engine` and `pyroute2` for automated ruleset tests.
- **Zero-Leak PCAP Ruleset Test**: Added `tests/test_nse_rules.py` to validate `nftables` schemas in isolated namespaces, using an asynchronous Scapy sniffer to assert zero cleartext packets escaping to the WAN.
- **Chaos Monkey Stress Test**: Introduced `tests/chaos_monkey.py` to verify watchdog/killswitch auto-healing resilience under injected failures.
- **Architectural Decision Records (ADRs)**: Created a dedicated `docs/decisions/` directory containing records for all major architectural decisions (0001 through 0008) made since project inception.
- **Split Tunneling by UID/GID**: Added `--bypass-user` and `--bypass-group` options to the `start` and `restart` CLI commands. These options accept usernames or groupnames (supporting individual values, comma-separated lists, or multiple flags), resolve them dynamically to numeric UIDs/GIDs via standard Python `pwd`/`grp` libraries, and store them in the session lock file `ttp.lock`.
- **Bypass Firewall Exceptions**: Generates `meta skuid <uid> accept` and `meta skgid <gid> accept` nftables rules placed at the top of the output, prerouting, and filter_out chains. This allows bypassed users and groups to access the cleartext internet directly, bypassing both Tor NAT redirection and the emergency killswitch.
- **Watchdog Bypass Auto-Healing**: Updated the background watchdog daemon to read the bypassed users/groups from the session lock file, dynamically verify that their firewall bypass rules are active in the running nftables ruleset, and trigger auto-healing to restore them if missing or modified.
- **Strict Lock Permissions**: The volatile lock file `/run/ttp/ttp.lock` is now created/updated with strict `0o644` permissions to protect active session state from unauthorized write access.
- **`docs/interfaces.md`** (OSPS-SA-02.01): New authoritative reference for all external interfaces — full CLI command table with options, exit codes and root-privilege requirements; Tor integration (managed ports, control protocol, `torrc` directives, pluggable transports); system integration (nftables table/chain/rule-order, DNS bind-mount overlay, volatile systemd units, filesystem path inventory); and external network endpoints used for verification.
- **`docs/bridges.md`**: New user guide for obtaining, configuring, and verifying Tor Bridges and Pluggable Transports (`obfs4`, `snowflake`) in TTP.
- **`docs/documentation-policy.md`**: New repository policy specifying required tests, changelog, and component documentation updates for each type of repository modification.
- **`docs/security-assessment.md`** (OSPS-SA-03.01): New STRIDE threat model and risk assessment covering all TTP components (`firewall.py`, `dns.py`, `tor_install.py`/`tor_control.py`, `state.py`, `watchdog.py`, `cli.py`), trust boundary diagram, known limitations table with severity ratings, supply chain security controls, and a 16-item security controls summary matrix.
- **`MAINTAINERS.md`**: New governance document listing Project Lead, a `## Project Roles` table mapping each operational role (Code Reviewer, Release Manager, Security Officer, CI/CD Maintainer) to its current holder, access to sensitive resources, merge policy, and maintainer onboarding/offboarding process.
- **`DEPENDENCIES.md`**: New dependency policy document covering runtime and dev/build Python dependencies with version constraints and licenses, system-level dependencies, optional dynamic dependencies (SELinux tools, pluggable transports), and policies for vetting, version pinning, vulnerability monitoring (`pip-audit --path .`), and upgrading.

### Changed

- **`README.md` Optimization**: Replaced the redundant and detailed `How It Works` section with a high-level summary and direct link to the authoritative `docs/architecture.md` documentation.
- **RPM Packaging Builder & CI**: Added `--nodeps` to `rpmbuild` in `packaging/build_rpm.sh` to prevent build-time dependency checking failures in Debian/Ubuntu-based environments lacking an RPM database. Updated the GitHub Actions release workflow to install `checkpolicy` and `policycoreutils-python-utils` for compiling the SELinux policy, and added fallback macro definitions for `%python3_sitelib` and `%_unitdir` in `packaging/ttp.spec` to support building on non-RPM hosts.

### Fixed

- **Garbage Collection Namespace Bug**: Fixed premature namespace teardown in integration tests by maintaining a reference to the `ns_sandbox` generator fixture context.
- **Multicast Filtering in Leak sniffer**: Added IGMP/multicast/NDP packet exclusions to prevent false-positive leak assertions in ruleset tests.

## [0.4.0] - 2026-06-09

### Added


- **Native Transparent IPv6 Support**: Implemented dynamic IPv6 loopback detection, generating dual-stack or IPv4-only configurations depending on system availability. Added comprehensive IPv6 `nftables` rules for DNS/TCP redirection, loopback exemptions, and RFC 4193/RFC 3927 local range bypassing.
- **Network Resilient Watchdog**: Watchdog service now detects physical network carrier drops and default route removal. Under network offline states, watchdog checks are safely suspended to prevent false-positive emergency lockouts, automatically resuming after link reconnection and circuit stabilization.
- **Structured JSON Logging**: Added global `--log-format` command-line option supporting `text` and `json` outputs. Selecting `json` configures stdout/stderr and file log outputs to emit single-line structured JSON records with UTC ISO 8601 timestamps, log levels, logger namespaces, messages, and exception stack traces.
- **Extended DoH Domain Blocking**: Added `MapAddress` entries in `torrc` to neutralize DoH canary domains for Cloudflare (`use-application-dns.net`), Google, Quad9, OpenDNS, and AdGuard, signalling DoH-compliant browsers to fall back to the system resolver (which is safely routed through Tor).
- **DoH IP-Level Blocking**: Added `filter_out` nftables rules to reject TCP port 443 traffic destined for well-known DoH resolver IPs (Cloudflare, Google, Quad9, OpenDNS) - both IPv4 and IPv6 - as a defence-in-depth measure against non-compliant browsers that ignore the canary domain.
- **CI/CD: Ruff Format Check**: Added `ruff format --check` as the first step in `scripts/verify.sh` to enforce consistent formatting before any other pipeline step.
- **`CONTRIBUTING.md`**: Added `## Coding Standards` section (ruff check/format commands, PEP 8 reference, type annotation requirement, no-dead-code rule) and `## Developer Certificate of Origin (DCO)` section (sign-off requirement, `git commit -s` instructions, `git rebase --signoff` for retroactive signing, full DCO v1.1 text in collapsible block). Both sections added to the Table of Contents.
- **`docs/architecture.md`**: Removed duplicated content now canonical in `interfaces.md`. Section 4 (CLI command list) replaced with a cross-reference. Section 3.3 (`firewall.py`) condensed to design principles only, with execution order detail referenced from `interfaces.md § 3.1`. Section 3.4 (`dns.py`) condensed to design rationale only, with attribute table referenced from `interfaces.md § 3.2`. Section 3.6 (`cli.py`) trimmed to remove inline command enumeration, referencing `interfaces.md § 1`.
- **`README.md`**: `## Known Behavior` section renamed to `## Known Behavior & Limitations` and condensed — verbose inline explanations removed in favour of a reference to `docs/security-assessment.md` as the single source of truth for the risk breakdown.
- **`SECURITY.md`**: `## Scope` bullet list condensed to a one-sentence summary with a cross-reference to `docs/security-assessment.md` for the full threat model.
- **`docs/security-assessment.md`**: Dependency monitoring table (§ 5.2) replaced with a cross-reference to `DEPENDENCIES.md § 2.3` as the authoritative source for CVE scanning and Dependabot configuration.

### Fixed

- **Critical: DNS Leak via LAN Bypass Rule Ordering** (`firewall.py`): The `nftables` `output` chain evaluated the LAN bypass rule (`ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept`) *before* the DNS redirect rule. Browsers that cache the LAN gateway (e.g. `192.168.1.1:53`) as their DNS resolver would have their queries accepted by the LAN bypass and sent directly to the ISP resolver - bypassing Tor entirely. The DNS redirect rule now runs *before* the LAN bypass in both the `output` and `prerouting` chains. Discovered via manual leak testing on [browserleaks.com/dns](https://browserleaks.com/dns).
- **Watchdog: Passive Tor Health Check (False Negative)** (`watchdog.py`): `check_system_integrity()` was verifying Tor health via `ctrl.close()`, a local Python object operation that succeeds even when the Tor daemon has crashed and only a stale socket file remains. Replaced with `ctrl.get_info("status/bootstrap-phase")`, an active round-trip query that correctly raises an exception on a dead or stale socket.
- **Watchdog: Ignored Auto-Healing Return Value (Killswitch Delay)** (`watchdog.py`): `run_watchdog_loop()` ignored the return value of `attempt_auto_healing()`. If the healing command itself failed (e.g. `nft` unable to re-apply rules), the loop would still wait 3 seconds, re-run the integrity check, detect the same failure, and only then activate the killswitch - creating a window where traffic could flow in cleartext. The emergency killswitch is now triggered immediately if `attempt_auto_healing()` returns `False`.
- **SELinux Module Version Inconsistency** (`scripts/install.sh`): The shell installer checked for the presence of the `ttp_tor_policy` module without verifying its version. If v1.0 was installed, the script would skip reinstallation while Python's `tor_detect.py` would still report the module as outdated (requiring v1.1). The check is now `grep -qE "ttp_tor_policy[[:space:]]+1\.1"`, consistent with the Python detection logic.

## [0.3.5] - 2026-05-22

### Added

- **Watchdog Daemon & Emergency Killswitch (Proactive Integrity)**: Introduced a background monitoring watchdog service (`ttp-watchdog.service`) that continuously verifies session integrity (Tor socket connection or systemd service status, nftables 'inet ttp' table and 'filter_out' chain presence, and DNS overlay mount).
- **Proactive Auto-Healing**: Added capability to dynamically attempt single-strike repair (re-applying rules, restarting Tor, or re-mounting DNS resolv.conf) before taking drastic actions.
- **Hard Network Lockout**: Implemented `apply_emergency_killswitch()` which drops all incoming, outgoing, and forwarding network traffic (except `lo`) in case of a persistent two-strike integrity failure, sending system-wide alerts via `wall` and desktop notifications via `notify-send`.
- **LAN Bypass Automatic Control**: Integrated automatic LAN bypass (`--no-lan-bypass` to disable) which dynamically injects nftables rules to accept traffic destined for RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and Link-Local (169.254.0.0/16) networks.
- **DoH/DoT DNS Leak Mitigation**: Mitigated DNS leaks by blocking outgoing DoT traffic (`tcp dport 853 reject` in the firewall) and forcing browser-level DoH to disable by mapping Mozilla's canary domain (`use-application-dns.net`) to `0.0.0.0` inside `torrc` via `MapAddress`.
- **Selective Root Routing**: Enhanced default security by routing all root processes (including `sudo` commands) through Tor. Added `--allow-root` to the CLI to explicitly opt-out and allow root processes to bypass Tor.
- **Watchdog CLI Commands**: Added Typer command group `ttp watchdog` (`start`, `stop`, `status`, `run`) and optional `--watchdog` / `-w` flags in `start` and `restart` commands.

### Fixed

- **CLI Non-Root Crashes**: Caught `OSError` in logging setup to prevent CLI crashes when calling `ttp --help` or commands without root privileges.

## [0.3.0] - 2026-05-13

### Added

- **Volatile Standard Core**: Fully volatile runtime. All runtime metadata, locks, and logs are now stored in `/run/ttp` (tmpfs), leaving zero traces on the host's physical disk.
- **Native Service Management**: Tor runs as a dedicated `ttp-tor.service` systemd unit with a volatile unit file in `/run/systemd/system/`. This avoids hijacking the system's own `tor.service` and its sandboxing restrictions.
- **Port Conflict Resolution**: Set `SocksPort 0` by default and switched to a private Unix ControlSocket (`/run/tor/ttp/control.sock`). This allows TTP to coexist with other Tor instances without "Address already in use" errors.
- **Stateless DNS Overlay**: Replaced physical `/etc/resolv.conf` overwrites with a `mount --bind` strategy. This allows for a clean, non-destructive redirection of DNS queries.
- **Lazy Umount Fallback**: Added `umount -l` support to ensure the DNS overlay is successfully removed during teardown even if the resource is busy.
- **Mount Stacking Prevention**: Automatically clears stale DNS mount overlays to ensure absolute idempotency, even after unclean kills.
- **Graceful Teardown**: Sends a cryptographic `SHUTDOWN` signal to Tor before removing firewall rules, ensuring all circuits close cleanly and preventing cleartext `RST` packet leaks.
- **Pre-flight Safety Check**: Verifies sufficient `tmpfs` space before execution to prevent out-of-memory crashes mid-setup.
- **Persistent Entry Guards**: `DataDirectory /var/lib/tor/ttp/` preserves Entry Guards across runs for fast bootstrap.

### Changed

- **Volatile Logging**: Logs moved from `/var/log/ttp.log` to `/run/ttp/ttp.log`. The log size is now capped at 1MB to prevent memory exhaustion in the RAM disk.
- **Diagnostic Refactoring**: Updated `ttp logs`, `ttp status`, and `ttp diagnose` to reflect the native service management architecture.

### Fixed

- **Release packaging**: `packaging/release.sh` runs `python -m build` with a project-local temp directory (`.build_tmp`) so builds do not exhaust RAM-backed `/tmp` on small hosts. `TMPDIR` is not exported for the whole script, so later steps (for example `dpkg-deb`) still see a valid temporary directory.

## [0.2.0] - 2026-05-05

### Added

- **Diagnostic Commands**: Added `ttp check` for quick network status and `ttp check-leak` for manual DNS/IP leak verification.
- **Log Streaming**: Added `ttp logs` wrapper to easily stream Tor daemon logs (`journalctl`) for debugging.
- **Restart Command**: Added `ttp restart` for quick session resets.
- **Configurable Timeout**: Added `--bootstrap-timeout` flag to `start` and `restart` commands (defaults to 180s) to support slower networks.
- **Emergency Recovery**: Added `--restore-only` flag to the `stop` command to force network cleanup and DNS restoration even if TTP crashed or lost its lock file.
- **Log Management**: Enabled `RotatingFileHandler` for TTP logs (`/var/log/ttp.log`) with a 5MB limit to prevent unbounded disk usage.
- **Firewalld Conflict Detection**: Added explicit detection and warning if `firewalld` is active during startup to prevent rule conflicts on Fedora/RHEL.

### Changed

- **Build Pipeline**: Extended the `verify` target in the Makefile to automatically trigger the packaging scripts (`make build`) upon successful tests.
- **Status Reporting**: The `ttp status` command now actively resolves the external IP (if connected) to display the active exit node.

## [0.1.1] - 2026-05-01

### Added

- **CI/CD Automation (Makefile)**: Introduced a root-level `Makefile` to provide a unified entry point for unit tests and multi-distro Docker integration tests (`make verify`).
- **Project Renaming**: Officially renamed the project to `transparent-tor-proxy` for PyPI and native packages to improve clarity and avoid collisions, while preserving the `ttp` command for the CLI.
- **Call for Contributors**: Added a dedicated section in README.md to attract new developers and experts to the project.

### Changed

- **Repository Reorganization**: Professionalized the project structure:
  - Moved system scripts (`install.sh`, `uninstall.sh`, `restore-network.sh`) to `scripts/`.
  - Consolidated QEMU VM and Docker testing assets into `scripts/vm/`.
  - Integrated internal assets into the Python package namespace under `ttp/resources/`.
- **Modern Asset Management**: Transitioned from manual path manipulation to `importlib.resources` for accessing the SELinux policy source, ensuring compatibility with all installation methods (pip, venv, native packages).
- **Documentation Overhaul**: Renamed `TDD.md` to `architecture.md` and updated all documentation to reflect the new architecture and modern packaging standards.

### Fixed

- **Path Robustness**: All shell scripts and Makefiles now resolve the project root absolutely, allowing execution from any working directory without breaking relative paths.
- **CLI Help Accuracy**: Updated internal CLI help messages to point to the new script locations.

## [0.1.0] - 2026-04-27

### Added

- **Exception Hierarchy**: Introduced `TTPError` base class and specialized exceptions (`FirewallError`, `DNSError`, `StateError`, `TorError`) for professional error handling and selective recovery.
- **CI/CD Pipeline**: Integrated GitHub Actions for automated quality assurance:
  - **Ruff**: Static analysis and linting for Python.
  - **ShellCheck**: Security and syntax auditing for shell scripts.
  - **Pytest**: Automated testing across Python 3.10, 3.11, 3.12, and 3.13.
- **Resilient Verification**: Tor verification now queries multiple endpoints (`check.torproject.org`, `ipify`, `ifconfig.me`) to prevent failures if one service is down.
- **Settling Delay**: Added a tactical 2-second delay between Tor reaching 100% bootstrap and the initial IP verification to allow circuits to stabilize.
- **Native Packaging**: Fully automated build scripts (`build_deb.sh`, `build_rpm.sh`) and PKGBUILD for Arch Linux, including complete metadata and license files.

### Changed

- **Transparent SELinux Compilation**: TTP no longer ships pre-compiled opaque `.pp` binaries. The custom `ttp_tor_policy` module for RHEL/Fedora families is now compiled on-the-fly from its `.te` source during installation.
- **Hardened DNS Logic**: Transitioned from "best-effort" execution to strict verification. DNS configuration failures now trigger immediate alerts and automatic rollback to prevent IP leaks.
- **Stateless Firewall Architecture**: Transitioned to a dedicated `inet ttp` table. This eliminates the need for complex system ruleset backups and ensures atomic, risk-free cleanup via `nft destroy`.
- **Crash-Safe State Management**: Hardened session locking to handle read-only filesystems and unexpected process terminations.

### Fixed

- Fixed a bug where the emergency recovery script `restore-network.sh` was deployed without content.
- Resolved multiple ShellCheck warnings related to word splitting and unquoted variables in `install.sh` and `uninstall.sh`.
- Corrected unused imports and linting errors identified by the new CI pipeline.

## [0.0.1] - 2026-04-10

- Initial internal release candidate.
- Core logic for firewall redirection (nftables) and DNS management (resolvectl).
- Basic Typer CLI interface.
