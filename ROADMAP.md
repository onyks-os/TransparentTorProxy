# TTP Development Roadmap — 2026

This document outlines the **realistic, near-term** development plan for Transparent Tor Proxy (TTP). Items beyond this scope are tracked as ideas in [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues) rather than committed release dates.

---

## Current Status (v0.4.7 — shipped)

Delivered:

- Volatile core, stateless nftables, DNS overlay + systemd-resolved bypass
- Watchdog governed by a formal FSM (`transitions`), with auto-healing and emergency killswitch
- Split tunneling (UID/GID + cgroups v2 `ttp bypass`)
- Tor bridges (obfs4/snowflake), BYOD mode, zero-leak teardown
- Privilege-separated watchdog user (`ttp-watchdog` + `CAP_NET_ADMIN`)
- NSE ruleset tests (written; wired into CI in 0.4.8), chaos monkey, multi-distro Docker integration
- `cli.py` split into `ttp/commands/`; Debian Docker integration runs on every push and PR
- Single quality gate: CI and `scripts/verify.sh` both delegate to `make lint` / `make test`,
  so ruff, mypy, ShellCheck and the secret scan cannot drift apart

---

## v0.4.8 — Verification Debt (in progress)

**Goal:** Make a green test suite mean something. Every item here exists because a
real defect survived the current suite, not because the metric looked low.

### Done

| Item | Outcome |
| :--- | :------ |
| **Zero-leak suite is executed** | `tests/test_nse_rules.py` had no make target, no CI job and no step in `verify.sh`, and its marker is excluded from the default run. It now has `make test-nse`, a CI job on every push, and a pre-release step. |
| **Positive controls** | Every containment test first runs its stimulus with the ruleset flushed and requires the leak to be *observed*. "The sniffer saw nothing" can no longer be mistaken for "the firewall blocked it". |
| **State and validation coverage** | `_ports.py` 45% → 100%, `_validation.py` 58% → 98%, `tor_install.py` 64% → 100%, `state.py` 66% → 99%, `firewall/builder.py` 79% → 100%, `ux.py` 57% → 100%. Total 80% → 86%, 295 tests → 428. |
| **Coverage is enforceable** | `make coverage` invoked `pytest --cov` without `pytest-cov` being a dependency, so it failed outright. Fixed, and `--cov-fail-under` now ratchets it. |
| **markdownlint (and ShellCheck) in CI** | Both were invoked only when present and had never been installed on the runner. Both are installed, the job asserts they are on PATH, and the backlog they had accumulated is fixed. |
| **NSE pinned to `>=2.1.0,<3`** | Was `>=1.1.1`, open across a major with breaking changes. 2.1.0 is the first release whose oracle cannot report a clean result having observed nothing. |
| **Release rehearsal in CI** | `make packages` runs on every push and asserts every artifact the release job signs actually exists, plus `twine check`. The two blockers that motivated this were invisible until tag time, when the tag already existed. |

### Remaining

| Item | Description |
| :--- | :---------- |
| **Behavioural CLI tests** | `tests/test_cli_*.py` assert on the sequence of internal calls rather than on the effect. That is how `ttp restart` shipped broken *with a dedicated passing test that asserted the broken call list*. Mock at the system boundary (`subprocess`, `pwd`, filesystem) and assert on the generated ruleset, `torrc`, and lock file — the shape `tests/test_firewall.py` already uses. |

---

## v0.4.9 — systemd-resolved field hardening

| Item | Description |
| :--- | :---------- |
| **systemd-resolved hardening** | Refine the ADR 0009 implementation based on field reports (D-Bus/NSS edge cases). Carried over from the 0.4.7 cycle: it needs real-world reports to act on, so it is scheduled where the reports will exist rather than kept open indefinitely. |

---

## v0.5.0 — Compatibility & Observability (Q1 2027)

**Goal:** Reduce friction for real-world desktop use.

| Item | Description |
| :--- | :---------- |
| **VPN coexistence** | Detect `tun+`/`wg+` interfaces and generate compatible nftables rules for Tor-over-VPN / VPN-over-Tor. |
| **Desktop notifications** | Extend the existing `wall` + `notify-send` alerts in `ttp/watchdog/alerts.py` to proper D-Bus notifications, and cover circuit rotation as well as killswitch activation. |
| **`ttp monitor` (TUI)** | Real-time bandwidth/circuit stats via Rich or Textual. |
| **Supply chain & reproducibility** | The project already publishes Sigstore-signed assets, an SBOM, and a verification guide; what is missing is evidence they hold. Verify the published signatures in CI, keep the build backend pinned deliberately rather than by accident, and check that a rebuild of the same tag produces identical artifacts. |

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
