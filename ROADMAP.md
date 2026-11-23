# TTP Development Roadmap — 2026

This document outlines the **realistic, near-term** development plan for Transparent Tor Proxy (TTP). Items beyond this scope are tracked as ideas in [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues) rather than committed release dates.

---

## Current Status (v0.5.1)

Delivered and in use:

- Volatile core, stateless nftables, DNS overlay + systemd-resolved bypass
- Watchdog governed by a formal FSM (`transitions`), woken by nftables and inotify events; it restarts a failed Tor, and otherwise applies an emergency killswitch it holds until `ttp stop`
- Split tunneling (UID/GID + cgroups v2 `ttp bypass`)
- Tor bridges (obfs4/snowflake), BYOD mode, zero-leak teardown
- Privilege-separated watchdog user (`ttp-watchdog` + `CAP_NET_ADMIN`)
- Tor started as its own account with no capabilities; both units TTP starts sandboxed by systemd; Tor verification parsed as `nobody`
- Distinct exit code (`3`) for a session that is up but whose Tor routing is unverified ([ADR 0011](docs/decisions/0011-start-exit-codes.md))
- Session evidence: a required watchdog proves readiness before `ttp start` succeeds, typed status/check results with diagnostic codes 5–9, and an emergency held until `ttp stop` ([ADR 0013](docs/decisions/0013-session-evidence-and-notifications.md))
- Optional desktop notifications through an unprivileged recipient agent, and the passive `ttp monitor` ([ADR 0014](docs/decisions/0014-passive-monitor.md))
- Optional VPN before Tor for a native NetworkManager WireGuard tunnel ([ADR 0015](docs/decisions/0015-required-vpn-before-tor.md))
- Verified enforce-mode AppArmor confinement of Tor on AppArmor kernels

What backs those claims, as of this release:

| Evidence | Where it runs |
| :------- | :------------ |
| **Zero-leak ruleset suite.** TTP's real ruleset in a network namespace (NSE 2.5.1, incomplete captures and windows without their closing beacon rejected, probes and canaries matched by probe ID, round trip answered by a logging receiver in an isolated host namespace), every containment test preceded by a positive control, alongside Docker-, ufw-, firewalld- and WireGuard-shaped competing rulesets. | CI, every push and PR (`make test-nse`) |
| **Lifecycle transitions.** Shutdown, reboot and suspend/resume onto a new network, judged from a packet capture taken outside the guest, under systemd-networkd (Debian 13) and NetworkManager (Fedora 44, SELinux enforcing). | CI, in a VM, when firewall, lifecycle, DNS or watchdog code changes, and weekly |
| **Watchdog chaos sweep.** Every fault once, each audit paired with a canary, TCP and UDP, in three variants. | CI, in a VM, same trigger |
| **Required VPN gates.** Real Tor through WireGuard in a Debian 13 VM with an external observer: six IPv4/IPv6 topologies, a private obfs4 bridge, suspend/resume and reboot. ParrotOS Home 7.4 (AppArmor enforcing) qualified by hand on the release candidate. | CI, in a VM, when VPN, firewall or lifecycle code changes, and weekly |
| **Integration suite** on Debian, Fedora and Arch. | CI, every push and PR |
| **Unit suite.** 1816 tests, 99.0% line coverage of `ttp/`, ratchet at 99%. Also run against the oldest supported dependency versions (Ubuntu 24.04's). | CI, Python 3.12-3.13 |
| **Release integrity.** Every release verified from what was published (signatures bound to the tag's workflow, checksums, PyPI bytes) after release and weekly; builds reproducible, and each release rebuilt from its tag and compared. | CI, on every change and after every release |

What is *not* protected, and says so: a session does not survive a reboot, and
TTP has no start-at-boot mode ([security assessment, 4.3](docs/security-assessment.md#43-lifecycle-transitions-what-is-measured-and-what-is-not)).

---

## Released

### v0.5.1 — Maintenance

Missing Tor or a missing pluggable transport exits `1` instead of `0`; `logs`,
`status`, `check-leak` and `watchdog status` ask for `sudo` instead of crashing
or reporting an unreadable session as inactive; the documentation describes
0.5.0's commands and exit codes in full; and the NSE round-trip test runs its
echo server in an isolated host namespace (NSE 2.3.0), out of reach of the
host's firewall.

### v0.5.0 — Compatibility & Observability

Reported state made to match the evidence: a required watchdog that proves it is
evaluating, typed session observations, an emergency held until `ttp stop`,
`ttp monitor`, optional desktop notifications, and an optional VPN before Tor,
qualified in VMs across six IPv4/IPv6 topologies, an obfs4 bridge,
suspend/resume, reboot and ParrotOS. Hardened hosts work: restrictive umasks,
an explicit per-link `DNSSEC=yes` refused before any change, and
systemd-resolved restricted by UID with measured tests.

Defects found during qualification and fixed before release, in TTP itself or
in the evidence its tests produce:

| Finding | Effect before the fix | Fix |
| :--- | :--- | :--- |
| O01 — optimistic DNS/UDP verdicts | Timeouts, DNS errors or aggregate counters could certify containment without external evidence. | #132 |
| F01 — unobserved fault interval | Chaos recovery audits ran after the fault; exposure during injection and response was not measured. | #149 |
| E01 — Tor automap inside LAN bypass | With LAN bypass, TCP and UDP to Tor's synthetic onion addresses left the host directly. | #150 |
| Orphaned redirected sockets at `ttp stop` | A FIN to the destination tried during the session, and RSTs with a stale `::1` destination (IPv6), left in cleartext after stop; Tor's ends in LAST-ACK still did once conntrack had forgotten them (21 RSTs in a dual-stack run). | #152, #165 |
| `ttp check` sampling the watchdog mid-evaluation | With a required watchdog, `check` could latch emergency on a healthy session (2 of ~56 CI VPN runs, one `check` each). | #154 |

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

## v0.6.0 — Hardening & Leak-Test Evidence (planned)

**Goal:** Close current evidence gaps and measure containment throughout faults
and transitions before expanding the isolation model.

The [leak-testing and hardening plan](docs/security/leak-testing-plan.md) defines
the existing coverage, scenario IDs, priorities, controls, artifacts and release
acceptance criteria. It adapts Whonix-style dependency removal and packet
observation to TTP's host boundary. This is planned testing work, not a claim
that the new matrix has run or approval for changing runtime defaults.

| Order | Work | Completion evidence |
| :--- | :--- | :--- |
| 1 | Correct optimistic DNS verdicts and reconcile public claims; investigate LAN/virtual-address overlap. | Timeout/error/counter-only results cannot certify containment; candidate behavior reproduced before assigning impact. |
| 2 | Extend the existing observer and chaos/lifecycle fixtures with continuous traffic and external capture. | No initial fault window omitted; controls, phase boundaries and capture completeness verified. |
| 3 | Extend DNS, FIN/RST, IPv6, startup/rollback, route changes, bypass and local-service tests. | Required P0/P1 combinations have targeted mutation controls and separate allowed-path checks. |
| 4 | Add real browser/WebRTC tests and extend required-VPN fault observation. | Application traffic and initial failure intervals measured; network and browser-privacy findings distinguished. |
| 5 | Qualify the release candidate and seek focused independent human review. | Traceable matrix and artifacts, explicit residual limits and no missing required evidence. |

Confirmed current in-scope leaks and false-positive test logic enter the earliest
applicable release; the plan does not defer them automatically to 0.6.0. The
0.5.0 VPN qualification gates remain required before every release. NSE changes
must be scoped separately. No calendar commitment is made for this work.

*Deferred unless a contributor picks it up:* a system tray applet. Real
browser tests are order 4 above.

### Isolation model — deferred until core hardening is qualified

Optional per-application isolation remains a later design track:

| Item | Description |
| :--- | :--- |
| **`ttp run <app>`** | Transient network namespaces routed through Tor via veth pairs. |
| **Application-scoped routing** | Host stays on clearnet; only selected sandboxed apps use Tor. Requires its own threat model and evidence. |

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
