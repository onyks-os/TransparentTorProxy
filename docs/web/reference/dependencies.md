# Reference: Dependency Directory & Policy

---

## 1. Python Dependencies

### Runtime Dependencies
Required to run the core `ttp` application.

| Dependency | Version Constraint | License | Purpose |
|---|---|---|---|
| [typer](https://pypi.org/project/typer/) | `>=0.9.0` | MIT | CLI command construction & parameter validation. |
| [stem](https://pypi.org/project/stem/) | `>=1.8.0` | LGPLv3 | Interfacing with Tor Control Socket/Port. |
| [rich](https://pypi.org/project/rich/) | `>=15.0.0` | MIT | Rich text terminal formatting & progress bars. |
| [transitions](https://pypi.org/project/transitions/) | `>=0.9.3` | MIT | Finite State Machine engine for watchdog daemon. |

### Optional / Development Extras

| Dependency | Extra Group | Version | Purpose |
|---|---|---|---|
| [network-sandbox-engine](https://pypi.org/project/network-sandbox-engine/) | `nse` | `>=1.1.1` | Isolated netns & Scapy nftables rules validation engine. |
| [pyroute2](https://pypi.org/project/pyroute2/) | `nse` | `>=0.7.0` | Netlink route management inside network namespaces. |

---

## 2. System-Level Dependencies

| Binary/Service | Requirement | Purpose |
|---|---|---|
| **Python** | `>=3.10` | Primary runtime interpreter. |
| **systemd** | Required | Managing `ttp-tor.service` lifecycle. |
| **nftables** (`nft`) | Required | Atomic firewall rule application & redirection. |
| **tor** | Required | Tor routing daemon. |
| **util-linux** | Required | Bind-mounting overlay on `/etc/resolv.conf`. |
