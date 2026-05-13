# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
