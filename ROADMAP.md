# TTP Development Roadmap — 2026

This document outlines the **realistic, near-term** development plan for Transparent Tor Proxy (TTP). Items beyond this scope are tracked as ideas in [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues) rather than committed release dates.

---

## Current Status (v0.4.11)

Delivered and in use:

- Volatile core, stateless nftables, DNS overlay + systemd-resolved bypass
- Watchdog governed by a formal FSM (`transitions`), woken by nftables and inotify events; it restarts a failed Tor, and otherwise applies an emergency killswitch it holds until `ttp stop`
- Split tunneling (UID/GID + cgroups v2 `ttp bypass`)
- Tor bridges (obfs4/snowflake), BYOD mode, zero-leak teardown
- Privilege-separated watchdog user (`ttp-watchdog` + `CAP_NET_ADMIN`)
- Tor started as its own account with no capabilities; both units TTP starts sandboxed by systemd; Tor verification parsed as `nobody`
- Distinct exit code (`3`) for a session that is up but whose Tor routing is unverified ([ADR 0011](docs/decisions/0011-start-exit-codes.md))

What backs those claims, as of this release:

| Evidence | Where it runs |
| :------- | :------------ |
| **Zero-leak ruleset suite.** TTP's real ruleset in a network namespace, every containment test preceded by a positive control, alongside Docker-, ufw-, firewalld- and WireGuard-shaped competing rulesets. | CI, every push and PR (`make test-nse`) |
| **Lifecycle transitions.** Shutdown, reboot and suspend/resume onto a new network, judged from a packet capture taken outside the guest, under systemd-networkd (Debian 13) and NetworkManager (Fedora 44, SELinux enforcing). | CI, in a VM, when firewall, lifecycle, DNS or watchdog code changes, and weekly |
| **Watchdog chaos sweep.** Every fault once, each audit paired with a canary, TCP and UDP, in three variants. | CI, in a VM, same trigger |
| **Integration suite** on Debian, Fedora and Arch. | CI, every push and PR |
| **Unit suite.** 1083 tests, 99.8% line coverage of `ttp/`, ratchet at 99%. Also run against the oldest supported dependency versions (Ubuntu 24.04's). | CI, Python 3.10-3.13 |
| **Release integrity.** Every release verified from what was published (signatures bound to the tag's workflow, checksums, PyPI bytes) after release and weekly; builds reproducible, and each release rebuilt from its tag and compared. | CI, on every change and after every release |

What is *not* protected, and says so: a session does not survive a reboot, and
TTP has no start-at-boot mode ([security assessment, 4.3](docs/security-assessment.md#43-lifecycle-transitions-what-is-measured-and-what-is-not)).

---

## Released

### v0.4.11 — Less root

A security fix
([GHSA-wc5v-93m5-3vc6](https://github.com/onyks-os/TransparentTorProxy/security/advisories/GHSA-wc5v-93m5-3vc6)):
`--bridge-file` is read with the caller's permissions, not root's. And the first
step of taking root out of TTP's moving parts: Tor starts as its own account
with no capabilities, both units are sandboxed (`systemd-analyze security`:
ttp-tor 9.6 -> 3.2, ttp-watchdog 6.6 -> 3.4), and the third-party answers used
to verify Tor are parsed by `nobody`.

### v0.4.10 — Release integrity

The first reproducible release: rebuilt from its tag and compared byte for byte
with what was published. Signatures verified from the release page after every
release and weekly, a hash-pinned build environment, one SBOM per package, and
unit coverage from 96% to 99.9% - the new tests being the failure paths.

### v0.4.9 — Audit and verification

TTP's first end-to-end security audit ([report](docs/security/audit-2026-09.md)),
and the verification work it set off. The VM lifecycle suite, the chaos sweep in CI
and the competing-ruleset tests found real leaks that no unit test had reached: DNS
carried to a LAN resolver by a foreign DNAT chain, a watchdog that stopped with Tor,
exited once its killswitch was engaged, passed a flushed table, and never received
the nftables events it subscribed to. All are fixed, and each has the test that
would have caught it. The field hardening of systemd-resolved planned for this
release did not happen: no field report ever arrived to act on. It is replaced in
v0.5.0 by something measurable.

### v0.4.8 — Verification debt

Made a green suite mean something: the zero-leak suite wired into CI with positive
controls, coverage made enforceable, markdownlint and ShellCheck actually installed
on the runner, the NSE dependency pinned, a release rehearsal on every push, and
behavioural CLI tests in place of call-count assertions.

---

## v0.5.0 — Compatibility & Observability (Q1 2027)

**Goal:** Reduce friction for real-world desktop use.

| Item | Description |
| :--- | :---------- |
| **VPN coexistence** | Detect `tun+`/`wg+` interfaces and generate compatible nftables rules for Tor-over-VPN / VPN-over-Tor. |
| **Desktop notifications** | Today nothing reaches anyone. `alerts.py` calls `wall`, but terminals are writable only by their owner and the `tty` group, which `ttp-watchdog` is not in; and `notify-send`, but from a system service with no user's session bus. Delivering them means crossing a privilege boundary - a small root helper started through polkit, or a per-user agent listening on the system bus - which needs an ADR before code. Then cover circuit rotation as well as killswitch activation. |
| **`ttp monitor` (TUI)** | Real-time bandwidth/circuit stats via Rich or Textual. |
| **Supply chain & reproducibility** | *Done ahead of schedule; ships in 0.4.10.* Published releases are verified from what was published (signatures bound to the tag's workflow, checksums, PyPI bytes) after every release and weekly; the build environment is pinned by version and hash; every artifact has its own SBOM; and builds are reproducible - checked on every change, and every release is rebuilt from its tag and compared. See `docs/verification.md`. |
| **systemd-resolved drop rule, measured** | [ADR 0009](docs/decisions/0009-systemd-resolved-bypass.md)'s last layer — `meta skuid <resolved> ip daddr != 127.0.0.1 drop` — is what turns a resolved misconfiguration (a per-link DNS server, a VPN pushing `~.`) into a failed lookup instead of a leak. Today it is only checked as a string in the generated ruleset. Add an NSE test that sends a query as resolved's UID and requires it to be seen with the ruleset flushed and dropped with it loaded. |

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

These are not planned: each either needs a larger team, changes the product category, or would add no protection:

- Full GUI / system tray as a core deliverable
- Cloud-native K8s sidecar as a v1.0 requirement
- Mathematical leak proofs via eBPF (research track only)
- A DNS configuration auditor (`ttp doctor --dns`, [#43](https://github.com/onyks-os/TransparentTorProxy/issues/43)).
  For every process that is not bypassed, the structural guarantee already contains
  DoH, DoT and per-application resolvers ([ADR 0012](docs/decisions/0012-doh-dot-and-browser-leaks-are-out-of-scope.md)),
  so an auditor would add visibility, not protection, at the cost of a parser per
  application. What it would have reported is documented instead, with the manual
  checks: [Applications that resolve DNS on their own](docs/web/how-to/apps-with-own-dns.md).

---

## Contributing

TTP has one maintainer and is looking for more: reviewers for the nftables ruleset,
a co-maintainer, and people who run it on distributions CI does not cover. See
[#40](https://github.com/onyks-os/TransparentTorProxy/issues/40).

See [CONTRIBUTING.md](CONTRIBUTING.md). Priority areas where help is most needed:

1. **Linux networking** — nftables, network namespaces, VPN interface detection
2. **CI/CD** — keeping integration tests fast and reliable on GitHub Actions
3. **Tor internals** — Stem, bridges, bootstrap edge cases
