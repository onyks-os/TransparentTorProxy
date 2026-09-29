# Reference: System and Python Dependencies

This document provides an exhaustive inventory of Python package requirements, system binaries, optional extras, and distribution package matrices for TTP.

---

## 1. Python Dependencies

### Core Runtime Dependencies

Required for basic TTP execution (`pip install transparent-tor-proxy` or package installation):

The floors are the versions Ubuntu 24.04 LTS ships, and CI runs the unit suite against
exactly those (`packaging/oldest-supported.txt`). The watchdog is the only user of
`transitions`: without it, everything else works and `--watchdog` is refused before
the session starts.

| Package | Constraint | License | Primary Purpose |
|---|---|---|---|
| [typer](https://pypi.org/project/typer/) | `>=0.9.0` | MIT | CLI command construction & parameter validation. |
| [stem](https://pypi.org/project/stem/) | `>=1.8.2` | LGPLv3 | Interfacing with Tor Control Socket/Port (`NEWNYM`, circuit validation). |
| [rich](https://pypi.org/project/rich/) | `>=13.7.1` | MIT | Terminal formatting, progress spinners, and diagnostic panels. |
| [transitions](https://pypi.org/project/transitions/) | `>=0.9.0` | MIT | Finite State Machine engine governing the watchdog daemon. |

### Optional Extras

| Group | Package | Constraint | Purpose |
|---|---|---|---|
| `nse` | [network-sandbox-engine](https://pypi.org/project/network-sandbox-engine/) | `>=2.1.2,<3` | Isolated network namespace testing & Scapy rule validation. |
| `nse` | [pyroute2](https://pypi.org/project/pyroute2/) | unpinned | Netlink route & interface management inside sandbox namespaces. |
| `dev` | [pytest](https://pypi.org/project/pytest/) | `>=9.1.1` | Unit & integration test runner. |
| `dev` | [hypothesis](https://pypi.org/project/hypothesis/) | `>=6.0.0` | Property-based fuzz testing. |
| `dev` | [pytest-cov](https://pypi.org/project/pytest-cov/) | `>=5.0.0` | Coverage measurement and the CI ratchet. |
| `dev` | [ruff](https://pypi.org/project/ruff/) | `>=0.1.0` | Python linter and code formatter. |
| `dev` | [mypy](https://pypi.org/project/mypy/) | `>=1.10.0` | Static type checker. |
| docs (CI) | [mkdocs-material](https://pypi.org/project/mkdocs-material/) | unpinned | Documentation site generation. Installed by `.github/workflows/docs.yml`, not by an extra. |
| docs (CI) | [mkdocstrings](https://pypi.org/project/mkdocstrings/) | unpinned | Automatic docstring extraction for the API reference. Same. |

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
| `semodule` | `policycoreutils` | Loading the `ttp_tor_policy` SELinux module on Fedora/RHEL. |

### Pluggable Transport Binaries (Censorship Circumvention)

TTP enforces a **Strict No Auto-Install Policy**. Pluggable transport helpers are checked dynamically when `--bridge` or `--bridge-file` flags are used:

| Transport | Binary | Debian / Ubuntu | Fedora / RHEL | Arch Linux |
|---|---|---|---|---|
| `obfs4` | `obfs4proxy` | `apt install obfs4proxy` | `dnf install obfs4proxy` | `pacman -S obfs4proxy` |
| `snowflake` | `snowflake-client` | `apt install snowflake-client` | `dnf install snowflake-client` | `pacman -S snowflake` |

---

## 3. Native Package Requirements Matrix

What each native package declares, from `packaging/build_deb.sh`,
`packaging/ttp.spec` and `packaging/PKGBUILD`. `tests/test_packaging_dependencies.py`
fails if a runtime dependency in `pyproject.toml` is missing from any of them, and
CI installs every package in a clean container before a release is signed
(`packaging/smoke_test.sh`).

=== "Debian / Ubuntu (.deb)"

    ```text
    Depends: python3, python3-typer, python3-rich (>= 13.7.1), python3-stem,
             python3-transitions (>= 0.9.0), nftables, tor
    ```

    Tested on Debian 13 and Ubuntu 24.04.

=== "Fedora (.rpm)"

    ```text
    Requires: python3, python3-typer, python3-rich, python3-stem, python3-six,
              nftables, tor, policycoreutils
    Provides: bundled(python3dist(transitions)) = 0.9.3
    ```

    Built on, and tested on, Fedora 44 (Python 3.14). Fedora does not package
    `transitions`, so the .rpm bundles it in `/usr/lib/transparent-tor-proxy/vendor`,
    which TTP uses only when the system has no `transitions` of its own.

=== "Arch Linux (PKGBUILD)"

    ```text
    depends=('python' 'python-typer' 'python-rich' 'python-stem' 'python-six' 'nftables' 'tor')
    ```

    `transitions` is only in the AUR, so the PKGBUILD bundles it the same way as the
    .rpm, from a wheel pinned by SHA-256.
