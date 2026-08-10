# TTP — Transparent Tor Proxy for Linux

A Linux CLI tool that transparently routes **all system traffic** through the Tor network using `nftables`.

!!! warning "Security & Privacy Notice"
    TTP is a tool designed to aid privacy by routing traffic through Tor. However, no tool can guarantee 100% anonymity. Your safety depends on user behavior (e.g. browser choice, account log-ins). For high-risk activities or whistleblowing, use [TailsOS](https://tails.net/) or official [Tor Browser](https://www.torproject.org/) directly.

---

## Key Features

* **Volatile Core**: Session state, locks, and temporary configurations reside strictly in RAM (`tmpfs`), leaving zero residue on disk.
* **No Per-Application Setup**: Global network-layer interception via `inet ttp` nftables tables.
* **Stateless DNS Overlay**: Directs system DNS through Tor via a kernel `mount --bind` overlay on `/etc/resolv.conf` and `systemd-resolved` drop-ins.
* **FSM Watchdog & Killswitch**: Background monitoring using a Finite State Machine (`transitions`) with automatic integrity repairs and emergency network lockout.
* **Preserved LAN & Bypass**: Exclude local subnets (RFC 1918) or specific UIDs/GIDs (`--bypass-user` / `--bypass-group`) from proxying.
* **Zero IPv6 Leaks**: Dual-stack redirection or total IPv6 outbound drop policy.

---

## Quick Start

```bash
# 1. Install TTP (Debian / Ubuntu)
sudo apt install ./transparent-tor-proxy_0.4.7_all.deb

# 2. Start Transparent Tor Proxy
sudo ttp start

# 3. Check status & verify Tor circuit
ttp status
ttp check

# 4. Stop session cleanly
sudo ttp stop
```
