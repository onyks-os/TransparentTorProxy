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

## v0.5.0 — Compatibility & Observability

**Goal:** Make desktop operation reliable and make reported state match the evidence.

The maintainer approves behavior and architecture before implementation. The
order below is the agreed discussion order; an estimate does not approve an
undecided feature. Estimates are focused engineering days for one developer,
including implementation, tests and documentation after contract approval.
They exclude decision waiting time and are not a release-date commitment.

| Order | Work | Approval / delivery status | Estimated remaining effort |
| :--- | :--- | :--- | :--- |
| 1 | **Measured systemd-resolved UID restriction:** IPv4 then IPv6; UDP/TCP DNS and non-DNS with LAN bypass, competing NAT, positive controls, kernel trace attribution and rule-removal mutation. These are firewall tests, not end-to-end DNS/Tor tests. | Approved; implemented for 0.5.0. Numeric Docker fixture priority and nftables 1.0.6-compatible teardown are included. | Complete; release validation below. |
| 1a | **Hardened-host compatibility:** readable installed code and DNS artifacts under restrictive umasks; temporary inherited-global `DNSSEC=no`; preserve explicit per-link `DNSSEC=yes` and refuse startup before network changes, with documentation and exit code `4`. No new flag. | Approved; implemented for 0.5.0. Runtime behavior was diagnosed on Fedora; automated permission, preflight and resolver tests cover the fix. | Complete; release validation below. |
| 2 | **Degraded-state contract:** distinguish inconclusive Tor verification, requested versus live watchdog, and killswitch requested/applied/verified. Correct claims of isolation only after defining what evidence supports them. | Definition and approval still required. Earlier assistant proposals about exit codes and watchdog policy are not approved. The DNSSEC refusal code `4` is the specific approved exception. | 2–4 days |
| 3 | **Delivered desktop notifications:** define recipients, events, delivery evidence and the privilege boundary between the system service and desktop sessions before choosing an implementation. | Definition and architecture approval required. | 3–5 days |
| 4 | **`ttp monitor`:** present trustworthy session, watchdog and containment information; define which other metrics are useful and actually available. Depends on item 2. | Definition and approval required; no UI toolkit or metric set selected. | 2–4 days |
| 5 | **VPN compatibility:** first define supported topologies, startup/shutdown order, DNS behavior and what happens when either VPN or Tor fails. Interface names alone do not establish a topology. | Definition and approval required; neither Tor-over-VPN nor VPN-over-Tor is approved yet. | 5–10 days, topology-dependent |
| Release | **Integration and release validation:** unit/NSE tests, resolver compatibility, VM lifecycle, packaging, documentation and regression review across supported distributions. | Required before publishing 0.5.0. | 2–3 days |

Indicative remaining total: **14–26 focused engineering days** after the pending
contracts are approved. The VPN scope is the largest uncertainty. NSE changes
needed to support future scenarios must be scoped separately; these estimates do
not authorize changes to NSE.

Supply-chain verification and reproducible builds already shipped in 0.4.10;
they remain release checks rather than unfinished 0.5.0 feature work.

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
