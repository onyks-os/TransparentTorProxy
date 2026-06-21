<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# Dependency Policy and Reference

This document outlines the system and library dependencies for Transparent Tor Proxy (TTP), detailing the vetting, tracking, vulnerability management, and upgrading policies.

---

## 1. Dependency Directory

### 1.1 Python Dependencies

#### Runtime Dependencies
These are required to run the core `ttp` application.

| Dependency                               | Version Constraint | License | Purpose                                                                                                   |
| :--------------------------------------- | :----------------- | :------ | :-------------------------------------------------------------------------------------------------------- |
| [typer](https://pypi.org/project/typer/) | `>=0.9.0`          | MIT     | CLI command construction, parameter validation, and user interface.                                       |
| [stem](https://pypi.org/project/stem/)   | `>=1.8.0`          | LGPLv3  | Interfacing with the Tor control port/socket (e.g., authenticating, checking status, signaling `NEWNYM`). |
| [rich](https://pypi.org/project/rich/)   | `>=13.0.0`         | MIT     | Rich text formatting, colorized terminal outputs, and interactive styling.                                |

#### Build & Development Dependencies
These are required only for building package distributions (`.deb`, `.rpm`, wheel) or running the test/verification suite.

| Dependency                                                   | Version Constraint  | License    | Purpose                                                     |
| :----------------------------------------------------------- | :------------------ | :--------- | :---------------------------------------------------------- |
| [hatchling](https://pypi.org/project/hatchling/)             | N/A (Build Backend) | MIT        | Modern build backend specified in PEP 517 build-system.     |
| [pytest](https://pypi.org/project/pytest/)                   | `>=7.0.0`           | MIT        | Test suite execution and test assertions.                   |
| [ruff](https://pypi.org/project/ruff/)                       | `>=0.1.0`           | MIT        | Code style enforcement, linting, and formatting checks.     |
| [build](https://pypi.org/project/build/)                     | `>=1.0.0`           | MIT        | Python packaging build frontend.                            |
| [twine](https://pypi.org/project/twine/)                                             | `>=4.0.0`           | Apache-2.0 | Tool for securely publishing distribution packages to PyPI.                                |
| [bump-my-version](https://pypi.org/project/bump-my-version/)                         | `>=0.20.0`          | MIT        | Version management tool to automate release numbering.                                      |
| [network-sandbox-engine](https://pypi.org/project/network-sandbox-engine/)           | `>=1.1.0`          | MIT        | Isolated netns/Scapy nftables rules validation engine for `tests/test_nse_rules.py`.       |
| [pyroute2](https://pypi.org/project/pyroute2/)                                        | `>=0.7.0`          | Apache-2.0 | Netlink-based route management inside network namespaces (avoids `/sys` mount in Docker).   |

### 1.2 System-Level Dependencies

Because TTP performs low-level routing and networking modifications, it relies on several system binaries and services.

| Package/Binary                     | Requirement | Purpose                                                                                                    |
| :--------------------------------- | :---------- | :--------------------------------------------------------------------------------------------------------- |
| **Python**                         | `>=3.10`    | The primary runtime interpreter.                                                                           |
| **systemd**                        | Required    | Managing the lifecycle of the dedicated `ttp-tor.service` and `ttp-watchdog.service` units (not required in BYOD/external-daemon mode). |
| **nftables** (`nft`)               | Required    | Atomic firewall rule application, redirecting TCP and DNS traffic, and enforcing the emergency killswitch. |
| **tor**                            | Required    | The Tor network routing daemon. (Auto-installed if missing on supported package managers).                 |
| **util-linux** (`mount`, `umount`) | Required    | Performing stateless bind-mounting overlays on `/etc/resolv.conf` to prevent DNS leaks.                    |

### 1.3 Optional & Dynamic Dependencies

Depending on your distribution's configuration and active features, additional dependencies may be required:

*   **SELinux Build Tools** (`checkpolicy`, `policycoreutils`): Required on Red Hat, Fedora, or CentOS systems where SELinux is in `Enforcing` mode. These are automatically installed (via `dnf`) to compile and load the custom `ttp_tor_policy.te` module allowing Tor to bind to non-standard ports.
*   **Pluggable Transports** (`obfs4proxy`, `snowflake-client`): Required when using Tor bridges. TTP will automatically detect if these are missing and attempt to install them via the system package manager (`apt-get`, `dnf`, `pacman`, `zypper`) if bridges of these types are configured.
*   **Network Utilities** (`dig` from bind-utils/dnsutils, `curl`): Used for leak detection, diagnostics, and testing scripts.

---

## 2. Dependency Management Policies

TTP aligns with open-source best practices (including OpenSSF standards) to ensure dependencies do not introduce security vulnerabilities or software instability.

### 2.1 Dependency Vetting and Selection
Before introducing any new external dependency, contributors must evaluate the candidate library against the following criteria:
1.  **Necessity:** Is the dependency strictly necessary? Can the functionality be implemented securely using the Python standard library?
2.  **Maintenance & Health:** Is the project actively maintained? Does it have a history of prompt security patching? Avoid projects with long periods of inactivity or unaddressed critical issues.
3.  **Licensing:** Dependencies must use permissive open-source licenses compatible with the MIT license (e.g., MIT, BSD, Apache-2.0, LGPL). Copyleft licenses like GPLv3 for libraries should be avoided to preserve project licensing flexibility.
4.  **Security Footprint:** Evaluate the dependency's transitive tree. Minimize libraries that drag in dozens of sub-dependencies.

### 2.2 Version Pinning & Range Rules
*   **Direct Python Dependencies:** Specified in `pyproject.toml` using minimum version ranges (e.g., `typer>=0.9.0`). This prevents dependency resolution conflicts when installed alongside other libraries in user environments.
*   **Native & System Packages:** Managed by system package managers (`apt`, `dnf`, `pacman`). Version pinning is deferred to the OS package distribution mechanisms to ensure security patches are applied by the upstream distribution.

### 2.3 Vulnerability Monitoring & Remediation
We proactively scan and monitor our dependency graph:
*   **Dependabot:** Configured on GitHub to monitor dependencies daily. It automatically raises Pull Requests (PRs) when updates or security advisories (CVEs) are released for any direct or build dependency.
*   **Vulnerability Scanning (`pip-audit`):** Developers should run `pip-audit` scoped to the **project directory only** to avoid false positives from unrelated system-level Python packages:
    ```bash
    pip install pip-audit

    # Audit only TTP's declared dependencies (correct)
    pip-audit --path /path/to/TransparentTorProxy

    # Or from within the project's venv
    source venv/bin/activate && pip-audit
    ```
    > **Note:** Running `pip-audit` without arguments from a global Python environment will scan *all* system packages (e.g., DNF, SETools, system utilities), producing false positives unrelated to TTP. Always use `--path` or scope to the project venv.
*   **Remediation SLA:** High and critical vulnerability updates identified in dependencies are addressed and released within 7 days of advisory publication.

### 2.4 Upgrading Dependencies
Dependencies should be reviewed and upgraded regularly to stay current with performance and security enhancements.
1.  **Automated PRs:** Review and merge Dependabot updates after the automated CI/CD pipeline completes successfully.
2.  **Manual Upgrades:** When changing minimum version constraints in `pyproject.toml`, run:
    ```bash
    make verify
    ```
    to ensure full unit and integration test compliance before committing changes.