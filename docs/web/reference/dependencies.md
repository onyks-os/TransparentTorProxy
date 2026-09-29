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

What each native package declares today, copied from `packaging/build_deb.sh`,
`packaging/ttp.spec` and `packaging/PKGBUILD`:

=== "Debian / Ubuntu (.deb)"

    ```text
    Depends: python3, python3-typer, python3-rich, python3-stem, nftables, tor
    ```

=== "Fedora / RHEL (.rpm)"

    ```text
    Requires: python3, python3-typer, python3-rich, python3-stem, nftables, tor, policycoreutils
    ```

=== "Arch Linux (PKGBUILD)"

    ```text
    depends=('python' 'python-typer' 'python-rich' 'python-stem' 'nftables' 'tor')
    ```

!!! warning "`transitions` is not declared"
    None of the three packages declares `transitions`, which the watchdog imports.
    On a host where it is not installed, the watchdog cannot start and `ttp stop`
    fails before tearing the session down. Until the packages declare it, install
    it yourself (`python3-transitions` on Debian, or `pip install transitions`), or
    install TTP with `pip`/`pipx`, which resolves it from `pyproject.toml`.
