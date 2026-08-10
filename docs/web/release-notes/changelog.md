# Release Notes & Changelog

All notable changes to Transparent Tor Proxy (TTP) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.7] - 2026-08-09

### Added

- **Strict No Auto-Install Policy**: Project-wide policy enforcement prohibiting automatic package installations. If required binaries (`tor`, `obfs4proxy`, `snowflake-client`) are missing, TTP displays distro-aware package installation guidance (`apt`, `dnf`, `pacman`, `zypper`), official Tor Project documentation URLs, and gracefully exits with status code `0`.
- **`tor_config` & `tor_service` Submodules**: Refactored `tor_install.py` by extracting pure `torrc` configuration generation into `ttp/tor_config.py` and volatile `systemd` service lifecycle management into `ttp/tor_service.py`.
- **`ttp/firewall/` Package Architecture**: Converted `firewall.py` into a specialized package `ttp/firewall/` composed of `builder.py` (pure ruleset string generator), `runner.py` (`nft` execution engine & atomic cleanup), and `emergency.py` (lockdown, socket slaughter, emergency killswitch).
- **HTTP/3 (QUIC) Anti-DoH Prevention**: Added explicit `udp dport 443 reject` rules for public DoH IPv4/IPv6 resolver IP sets to prevent browser HTTP/3 QUIC DoH bypasses.
- **Explicit Ruff Code Quality Rules**: Added `pyproject.toml` configuration enforcing `isort`, `flake8-bugbear`, `pyupgrade`, `flake8-simplify`, `flake8-logging-format`, and performance lints (`E`, `F`, `W`, `I`, `B`, `UP`, `SIM`, `G`, `PIE`, `RUF`, `PERF`). Added `make format` target for automated formatting and lint fixing.
- **Start Command Submodule Extraction**: Refactored `ttp/commands/start.py` by extracting pre-flight checks into `ttp/commands/_preflight.py` and Tor setup into `ttp/commands/_tor_setup.py`.
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

- **Standardized Error Handling**: Unified CLI error handling across `_validation.py` and `watchdog.py` to consistently raise `typer.Exit(code=1)` with Rich formatted error panels.
- **Flaky NSE Test Resolution**: Hardened `test_bypassed_user_escape` in `tests/test_nse_rules.py` with ARP cache warmup, Scapy sniffer initialization delays, and multi-packet transmissions.
- **Systemd Hard Requirement**: Declared systemd as strictly required for TTP. Start, restart, and bypass CLI commands check for systemd on startup and fail immediately with a descriptive error message if missing. Removed references to systemd-less environments, Alpine Linux, or Void Linux in documents, ADRs, and help strings.
- **Bypass Command Sudo Check**: Improved the `ttp bypass` CLI command to fail early with a clean, descriptive error message ("This command must be run with sudo to safely delegate privileges via systemd-run.") if executed without `sudo` or outside a `sudo` environment.

---

## [0.4.5] - 2026-06-21

### Added

- **Zero-Leak Shutdown (Graceful Teardown with Active Socket Slaughter)**: Implemented a multi-stage active socket termination and lockdown sequence during `ttp stop` to eliminate in-flight cleartext traffic leaks.
- **Connection Tracking Flush**: Added automatic Netfilter connection tracking state invalidation via `conntrack -F` to terminate active TCP/UDP streams before final firewall ruleset removal.
- **IPv6 Force Disable Flag**: Added `--no-ipv6` CLI option to `start` and `restart` commands.
- **Bring Your Own Daemon (BYOD) Mode**: Added `--external-daemon` and `--tor-uid` CLI options.
- **Network Sandbox Engine (NSE) Integration**: Fully integrated `network-sandbox-engine` and `pyroute2` for automated ruleset tests.
- **Split Tunneling by UID/GID**: Added `--bypass-user` and `--bypass-group` options.

---

## [0.4.0] - 2026-06-09

### Added

- **Native Transparent IPv6 Support**: Implemented dynamic IPv6 loopback detection and dual-stack nftables rules.
- **Network Resilient Watchdog**: Detects physical carrier drops and route removal to prevent false-positive lockouts.
- **Structured JSON Logging**: Added `--log-format json` support.
- **Extended DoH Domain & IP Blocking**: Added MapAddress entries for DoH canary domains and nftables drop rules for public DoH resolvers.

---

## [0.3.5] - 2026-05-22

### Added

- **Watchdog Daemon & Emergency Killswitch**: Introduced `ttp-watchdog.service` and emergency drop-all killswitch.
- **LAN Bypass Control**: Automatically injects rules for RFC 1918 and Link-Local subnets.

---

## [0.3.0] - 2026-05-13

### Added

- **Volatile Standard Core**: Stored session metadata in `/run/ttp` (tmpfs).
- **Stateless DNS Overlay**: Replaced physical file overwrites with kernel `mount --bind` on `/etc/resolv.conf`.

---

## [0.2.0] - 2026-05-05

### Added

- **Diagnostic Commands**: Added `ttp check`, `ttp check-leak`, `ttp logs`, and `ttp restart`.

---

## [0.1.1] - 2026-05-01

### Added

- **CI/CD Automation (Makefile)**: Introduced root-level `Makefile` for unit and integration testing.

---

## [0.1.0] - 2026-04-27

### Added

- **Exception Hierarchy**: Introduced `TTPError` base class.
- **Stateless Firewall Architecture**: Transitioned to dedicated `inet ttp` table.

---

## [0.0.1] - 2026-04-10

- Initial internal release candidate.
