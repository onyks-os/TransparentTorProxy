# Reference: System and Python Dependencies

This document provides an exhaustive inventory of Python package requirements, system binaries, optional extras, and distribution package matrices for TTP.

---

## 1. Python Dependencies

### Core Runtime Dependencies
Required for basic TTP execution (`pip install transparent-tor-proxy` or package installation):

| Package | Constraint | License | Primary Purpose |
|---|---|---|---|
| [typer](https://pypi.org/project/typer/) | `>=0.9.0` | MIT | CLI command construction & parameter validation. |
| [stem](https://pypi.org/project/stem/) | `>=1.8.0` | LGPLv3 | Interfacing with Tor Control Socket/Port (`NEWNYM`, circuit validation). |
| [rich](https://pypi.org/project/rich/) | `>=15.0.0` | MIT | Terminal formatting, progress spinners, and diagnostic panels. |
| [transitions](https://pypi.org/project/transitions/) | `>=0.9.3` | MIT | Finite State Machine engine governing the watchdog daemon. |

### Optional Extras

| Group | Package | Constraint | Purpose |
|---|---|---|---|
| `nse` | [network-sandbox-engine](https://pypi.org/project/network-sandbox-engine/) | `>=1.1.1` | Isolated network namespace testing & Scapy rule validation. |
| `nse` | [pyroute2](https://pypi.org/project/pyroute2/) | `>=0.7.0` | Netlink route & interface management inside sandbox namespaces. |
| `dev` | [pytest](https://pypi.org/project/pytest/) | `>=9.1.1` | Unit & integration test runner. |
| `dev` | [hypothesis](https://pypi.org/project/hypothesis/) | `>=6.0.0` | Property-based fuzz testing. |
| `dev` | [ruff](https://pypi.org/project/ruff/) | `>=0.1.0` | Python linter and code formatter. |
| `dev` | [mypy](https://pypi.org/project/mypy/) | `>=1.10.0` | Static type checker. |
| `dev` | [mkdocs-material](https://pypi.org/project/mkdocs-material/) | `>=9.5.0` | Documentation site generation. |
| `dev` | [mkdocstrings](https://pypi.org/project/mkdocstrings/) | `>=0.24.0` | Automatic docstring extraction for API reference. |

---

## 2. System-Level Dependencies

### Required Core Binaries

| Binary / Service | Required Version | Package Name (Debian/Fedora/Arch) | Purpose |
|---|---|---|---|
| **Python** | `>=3.10` | `python3` | Execution interpreter. |
| **systemd** | Required | `systemd` | Service lifecycle (`ttp-tor.service`) and transient scopes (`systemd-run`). |
| **nftables** (`nft`) | `>=0.9` | `nftables` | Kernel packet redirection (`inet ttp` table). |
| **tor** | `>=0.4.7` | `tor` | Tor routing daemon. |
| **util-linux** | Required | `util-linux` | Kernel VFS bind-mount overlay (`mount --bind`, `umount -l`). |
| **iproute2** (`ip`) | Required | `iproute2` | Network interface and routing table inspection. |

### Optional Helper Binaries

| Binary | Package Name | Purpose |
|---|---|---|
| `dig` | `bind-utils` / `dnsutils` | DNS leak verification in `ttp check-leak`. |
| `curl` | `curl` | HTTP endpoint verification in `ttp check`. |
| `semodule` | `policycoreutils` | Compiling and loading `ttp-tor.cil` SELinux policy modules on Fedora/RHEL. |

### Pluggable Transport Binaries (Censorship Circumvention)

TTP enforces a **Strict No Auto-Install Policy**. Pluggable transport helpers are checked dynamically when `--bridge` or `--bridge-file` flags are used:

| Transport | Binary | Debian / Ubuntu | Fedora / RHEL | Arch Linux |
|---|---|---|---|---|
| `obfs4` | `obfs4proxy` | `apt install obfs4proxy` | `dnf install obfs4proxy` | `pacman -S obfs4proxy` |
| `snowflake` | `snowflake-client` | `apt install snowflake-client` | `dnf install snowflake-client` | `pacman -S snowflake` |

---

## 3. Native Package Requirements Matrix

When building or installing TTP native packages (`.deb`, `.rpm`, `PKGBUILD`), distribution package managers resolve system dependencies automatically according to this mapping:

=== "Debian / Ubuntu (.deb)"

    ```text
    Depends: python3 (>= 3.10), python3-typer, python3-stem, python3-rich, python3-transitions, nftables, tor, systemd, util-linux
    Recommends: obfs4proxy, snowflake-client, dnsutils, curl
    ```

=== "Fedora / RHEL (.rpm)"

    ```text
    Requires: python3 >= 3.10, python3-typer, python3-stem, python3-rich, python3-transitions, nftables, tor, systemd, util-linux
    Recommends: obfs4proxy, snowflake-client, bind-utils, curl
    ```

=== "Arch Linux (PKGBUILD)"

    ```text
    depends=('python>=3.10' 'python-typer' 'python-stem' 'python-rich' 'python-transitions' 'nftables' 'tor' 'systemd' 'util-linux')
    optdepends=('obfs4proxy: obfs4 bridge support' 'snowflake: Snowflake bridge support' 'bind: DNS leak probes')
    ```
