# TTP Development Roadmap — 2026

This document outlines the **realistic, near-term** development plan for Transparent Tor Proxy (TTP). Items beyond this scope are tracked as ideas in [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues) rather than committed release dates.

---

## Current Status (v0.4.6)

Delivered:
- Volatile core, stateless nftables, DNS overlay + systemd-resolved bypass
- Watchdog with auto-healing and emergency killswitch
- Split tunneling (UID/GID + cgroups v2 `ttp bypass`)
- Tor bridges (obfs4/snowflake), BYOD mode, zero-leak teardown
- Privilege-separated watchdog user (`ttp-watchdog` + `CAP_NET_ADMIN`)
- NSE ruleset tests, chaos monkey, multi-distro Docker integration

---

## v0.4.7 — Hardening & Reliability (Q3–Q4 2026)

**Goal:** Make the project maintainable and trustworthy for contributors.

| Item | Description |
| :--- | :---------- |
| **CI integration tests** | Run Debian Docker integration on every PR (in progress). |
| **Test suite hygiene** | Keep unit tests green after every architectural change; mark root/NSE tests explicitly. |
| **CLI modularization** | Split `cli.py` into `ttp/commands/` (phase 1: shared helpers + lifecycle — done). |
| **Watchdog FSM** | Replace procedural watchdog logic with a formal state machine (`transitions` library) for predictable killswitch transitions. |
| **systemd-resolved hardening** | Refine ADR 0009 implementation based on field reports (D-Bus/NSS edge cases). |

---

## v0.5.0 — Compatibility & Observability (Q1 2027)

**Goal:** Reduce friction for real-world desktop use.

| Item | Description |
| :--- | :---------- |
| **VPN coexistence** | Detect `tun+`/`wg+` interfaces and generate compatible nftables rules for Tor-over-VPN / VPN-over-Tor. |
| **Desktop notifications** | DBus notifications for killswitch activation, circuit rotation, watchdog alerts. |
| **`ttp monitor` (TUI)** | Real-time bandwidth/circuit stats via Rich or Textual. |

*Deferred until v0.5.0+ unless a contributor picks them up:*
- Playwright L7 leak tests in CI
- System tray applet

---

## v0.6.0 — Isolation Model (Q2 2027+)

**Goal:** Optional per-application isolation instead of (or alongside) system-wide routing.

| Item | Description |
| :--- | :---------- |
| **`ttp run <app>`** | Transient network namespaces routed through Tor via veth pairs. |
| **Zero system leaks mode** | Host stays on clearnet; only sandboxed apps use Tor. |

*Research / long-term (no committed date):*
- eBPF/bpftrace syscall auditing
- Kubernetes sidecar packaging
- Netlink/pyroute2 migration (see ADR backlog — frozen unless active monitoring requires it)

---

## Explicitly Out of Scope (for now)

These were removed from committed release dates because they require a larger team or change the product category:

- Full GUI / system tray as a core deliverable
- Cloud-native K8s sidecar as a v1.0 requirement
- Mathematical leak proofs via eBPF (research track only)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Priority areas where help is most needed:

1. **Linux networking** — nftables, network namespaces, VPN interface detection
2. **CI/CD** — keeping integration tests fast and reliable on GitHub Actions
3. **Tor internals** — Stem, bridges, bootstrap edge cases
