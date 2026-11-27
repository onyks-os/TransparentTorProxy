<!-- Copyright (c) 2026 onyks-os; SPDX-License-Identifier: MIT -->

# Leak testing and hardening plan

Status: planned work, recorded on 2026-11-10. This document schedules testing
and investigation; it does not change runtime defaults, accept a new
architecture, or claim that the scenarios below have passed.

Baseline: local checkout based on `a802d17`, with 0.5.0 in development and
existing local VPN fixture changes. Coverage descriptions below come from
source inspection, not a fresh execution of CI. Record the exact commit and
working-tree diff with every subsequent qualification run.

## 1. Objective and boundaries

Extend the existing NSE, integration, lifecycle and VPN suites to answer:

1. Can ordinary, non-exempt applications send prohibited traffic while the
   session is protected, including during supported failures and transitions?
2. Do permitted TCP and DNS operations actually work through Tor?
3. Can the observer detect a deliberately introduced leak in this exact case?
4. Do CLI and watchdog observations describe the evidence without overstating it?

Here, a **direct leak** is prohibited application traffic crossing the observed
boundary outside the required Tor/VPN path. HTTPS sent directly is still a
leak; TLS encryption is not proof that Tor carried the connection. Do not infer
Tor use from a different public IP alone.

The [Whonix leak tests](https://www.whonix.org/wiki/Dev/Leak_Tests) motivate
dependency-removal, Tor-loss, FIN/RST and application-specific experiments.
Their VM commands and historical expected DNS responses must be adapted to
TTP's host architecture and the installed Tor version.

| Boundary | Required treatment |
| :--- | :--- |
| Ordinary applications in the protected host network namespace | Core containment target; include deliberate attempts to ignore application proxy settings |
| Managed Tor and explicit bypass identities | Record their exact exemptions and separately test that they cannot accidentally be granted to an ordinary identity |
| LAN and local services | Test the documented exceptions and their consequences; private addressing alone does not establish trust |
| Routed containers/namespaces | Measure the documented forwarding behavior; do not advertise a general gateway feature |
| Bridged/macvlan/ipvlan or other paths outside the controlled hooks | Demonstrate and document the boundary where feasible; do not count them as protected |
| Root, CAP_NET_ADMIN/CAP_NET_RAW and a compromised host kernel | Trusted/privileged actors, not a malware-containment promise; privileged fault injection measures recovery and exposure |
| Browser fingerprinting, accounts and document metadata | Separate application privacy observations from network containment |
| Reboot and deliberate stop | Expected end of protection under the current contract; record direct traffic without calling the interval protected |

Tails provides a useful same-system comparison for DNS, privileged exceptions
and access to local services: [Tor enforcement](https://tails.net/contribute/design/Tor_enforcement/).
Qubes illustrates an enforcement boundary TTP does not have:
[network policy in another qube](https://doc.qubes-os.org/en/r4.3/user/security-in-qubes/firewall.html).

## 2. Current evidence and the first gaps

"Implemented" below identifies an existing test, not a current qualification
result. Every row needs a recorded run before it supports a release claim.

| Area | Existing implementation to extend | Gap / first action |
| :--- | :--- | :--- |
| Kernel ruleset containment | [NSE suite](../../tests/test_nse_rules.py) on NSE stimuli, receivers and window beacons, [classifier](../../tests/nse_classifier.py) | Retain positive controls, same-capture canaries and rule attribution; add the missing scenario families below |
| DNS integration verdict | [DNS probe](../../tests/leak/test_dns_leak.py), [oracle](../../tests/leak/oracle.py), [oracle tests](../../tests/test_leak_oracle.py) | Confirmed inference defect: a timeout or error rcode does not establish local containment; a global redirect counter is not per-query attribution |
| Fault response | [Chaos sweep](../../tests/chaos_monkey.py), [VM wrapper](../../scripts/vm/lifecycle/chaos.sh) | The sweep waits 18 seconds before auditing; continuously observe the interval immediately after injection |
| Startup and rollback | [Start command](../../ttp/commands/start.py), CLI/failure-path unit suites | Existing lifecycle probe is stopped across startup; measure the actual sequence and each interrupted phase externally |
| Lifecycle | [VM scenarios](../../scripts/vm/lifecycle/run.sh), [probe](../../scripts/vm/lifecycle/probe.py), [capture reader](../../scripts/vm/lifecycle/egress.py) | Extend the IPv4 sentinel probe to the required families/protocols and validate capture completeness and phase boundaries |
| LAN / virtual addresses | [Rules builder](../../ttp/firewall/builder.py), [Tor configuration](../../ttp/tor_config.py) | Confirmed range overlap: automap addresses are inside LAN exemptions placed before TCP redirect. Reproduce the effect with a controlled onion service before assigning impact |
| Watchdog contract | [Supervision tests](../../tests/test_supervision_contract.py), [session safety tests](../../tests/test_session_safety.py), [systemd fixture](../../scripts/check-session-services.sh) | Keep existing isolated process-failure tests; add continuous external traffic observation in the full running session |
| Required VPN | [Offline fixture](../../scripts/check-vpn.sh), [QEMU fixture](../../scripts/vm/vpn/run.py), [capture tests](../../tests/test_vpn_vm_capture.py) | Reuse observer work where suitable; complete the existing [0.5.0 qualification gates](../web/how-to/vpn.md#validation-limits-and-release-gate) without moving them into a later release |
| Public claims | [README](../../README.md), [assessment](../security-assessment.md), [verification explanation](../web/explanation/verification.md) | Reconcile scope, persistence, browser advice, recovery timing and the distinction between configured rules and observed traffic |

The range overlap is an investigation candidate, not a reproduced leak. The
DNS verdict problem and chaos observation gap are findings about test evidence.
Neither alone proves that the normal ruleset leaks.

## 3. Evidence contract before more scenarios

### 3.1 Verdicts

Network containment, permitted-path availability, recovery timing and reported
session health are separate results. A dead Tor can be contained and unavailable.
A working Tor connection does not exclude a simultaneous UDP leak.

| Observation | Containment conclusion |
| :--- | :--- |
| Matching prohibited packet at the external observer or controlled receiver | Leak, even if the watchdog later closes the path |
| No matching packet, complete capture, attempted stimulus and successful controls | Contained for the stated boundary and observation interval |
| DNS timeout, SERVFAIL, REFUSED, NOTIMP or other reply shape alone | Inconclusive about the network path |
| Aggregate redirect counter increased | Supporting diagnostic only; does not identify the tested flow |
| Missing/truncated capture, failed observer readiness, lost capture data, unavailable target/control or failed stimulus | Inconclusive / harness failure; never a green containment result |
| Unsupported combination deliberately excluded by the support contract | Explicit not-applicable with reason; never converted to coverage |
| Traffic after deliberate release of protection or reboot | Expected unprotected behavior, reported separately |

Validate the exact socket error: do not translate every `OSError` into a
local firewall refusal. An error may describe routing, a remote response or a
broken experiment. Update oracle unit tests when the evidence contract changes,
including tests that currently encode the optimistic inference.

### 3.2 Controls and observation

- Use the production-generated ruleset. Reuse NSE rather than maintaining a
  second handwritten TTP ruleset in the harness.
- Give each stimulus a unique run/scenario/sequence identifier; use randomized
  DNS names in a controlled zone to avoid cache-dependent results. Correlate
  query name/transaction/flow and TCP tuples/flags where applicable.
- Prove that the same prohibited path is observable without protection, in
  both IP families being claimed. A positive control that never reaches the
  observer invalidates the experiment.
- Keep existing canaries where bypass is the scenario. For no-bypass and
  emergency tests, verify capture health without adding a bypass to the
  protected actor. Use observer-side health evidence and pre/post controls;
  do not manufacture an exemption that changes the policy under test.
- Start capture and stimulus before fault injection; keep them running through
  detection, containment and the final hold interval. Delays may set deadlines,
  but must not remove the initial failure window from observation.
- Use an observer outside the protected guest, on every relevant virtual NIC,
  before host-side NAT can obscure the experiment. For hardware qualification,
  capture on an upstream peer/router. Guest logs and nft traces supplement it.
- Record stimulus cadence, attempted/sent/refused counts, capture readiness,
  capture drops where available and sequence gaps. A periodic probe bounds
  what was sampled; it cannot prove the absence of shorter unsampled windows.
- Mutate the specific enforcement rule/path in a disposable instance and require
  the expected leak to be detected. Flushing all rules alone is insufficient
  calibration for every feature-specific regression.
- Check permitted-path availability with real requests separately. For example,
  TCP/53 containment does not imply TCP DNS functionality: expectations follow
  the actual Tor listener, not the firewall redirect syntax.
- Keep unknown traffic and malformed capture input visible. Do not globally
  exempt all UDP, ICMPv6, private destinations, control traffic or TLS. Scope
  every exception to its profile, direction, endpoint and required fields.

Tor DNS support must be version-checked; the current
[Tor manual](https://manpages.debian.org/unstable/tor/tor.1.en.html) describes
A/AAAA/PTR support. Historical "AAAA must fail" recipes are not a leak oracle.

### 3.3 Protected intervals and time

| Interval | Meaning and required assertion |
| :--- | :--- |
| Before the first enforcement barrier | Measure and label as unprotected; do not promise protection from the instant `ttp start` is invoked |
| First barrier committed through successful start | Identify the actual boundary; test containment while DNS, state and supervision are being prepared |
| Failed start / rollback | Record whether protection is retained or deliberately removed and when; compare with a documented failure contract |
| Healthy session through a non-firewall fault | Require continued containment when the existing kernel barrier should still hold |
| Enforcement barrier removed by privileged injection | Measure every observed escaped packet and recovery time; a later recovery pass does not erase the leak |
| Emergency hold | Require containment until explicit stop, including watchdog restart and network return |
| Stop / restore-only | Assert the documented ordering through intentional release; report subsequent clearnet separately |

Timestamp injection commands with observer-side before/after brackets, and
record guest monotonic events plus a mapping with uncertainty. Do not subtract
guest and QEMU wall clocks as if synchronized. Preserve continuous captures;
phase markers or file rotation must not create unobserved gaps. Report timing
as measured bounds, with repetition count and load conditions, not an
instantaneous-response guarantee.

If removal of all host enforcement exposes traffic, the immediate result is a
documented architectural limit and measured exposure. Additional enforcement
or topology changes require a separate design decision; adding a second table
does not protect against an unrestricted `flush ruleset`.

## 4. Scenario backlog

All IDs below start as **planned**. P0 means fix misleading evidence or triage
a possible current defect first; P1 is the proposed hardening release minimum;
P2 expands environmental breadth after the P1 gate. A reproduced in-scope
runtime leak blocks the affected release regardless of its original priority.

### 4.1 Instrument and DNS

| ID / priority | Extend | Experiment | Required evidence / calibration |
| :--- | :--- | :--- | :--- |
| O01 / P0 | DNS oracle and unit tests | Deliver a direct DNS request to a receiver that drops replies or returns error rcodes; add unrelated concurrent redirected DNS | External packet still means leak; timeout/error/counter alone stays inconclusive; old inference fails the regression |
| O02 / P0 | Capture readers and classifier tests (lifecycle reader: [tests](../../tests/test_lifecycle_egress.py)) | Empty, reply-only, truncated and corrupt capture; wrong NIC; absent stimulus; hidden IP family; unsupported Ethernet/IPv6 layout | No false clean verdict. Distinguish intentional snap length from missing required bytes; correct stimulus is detected in the control |
| D01 / P1 | NSE DNS + controlled integration | UDP/TCP 53 to public and LAN resolvers, port rewrites and competing DNAT priorities, IPv4/IPv6 | Unique query/flow observed externally when unprotected; blocked or attributed to Tor when protected; mutate the relevant safeguard |
| D02 / P1 | DNS overlay / resolved integration | After managed Tor has bootstrapped, disable non-Tor resolver paths and clear caches; request fresh names through libc, direct DNS and resolved IPC | Permitted resolution still works through Tor, or documented failure is contained; restored alternative path is a calibrated leak control |
| D03 / P1 | DNS functional tests | A/AAAA/PTR and unsupported TXT/MX/DNSKEY; UDP/TCP requests; explicit per-link DNSSEC policy | Separate supported answers from safe refusal and connectivity loss; verify DNSSEC preflight refusal happens before network changes |
| D04 / P1 | Ruleset + real client integration | DoH on listed and unlisted endpoints, DoT, QUIC/DoH and fallback to TCP | TCP uses Tor where supported, prohibited UDP never exits directly; compare remote source with an independent Tor-use check |
| D05 / P2 | Resolver service integration | Multiple links, cached and uncached lookups, search domains, stub/full resolv.conf forms, resolver restart and DHCP DNS replacement | No new direct resolver path; overlay restored correctly; unrelated LAN/name-resolution behavior explicitly recorded |

D02 adapts Whonix's host-DNS removal to a single host. Preserve or explicitly
exclude bootstrap name dependencies of bridges/transports; breaking their
bootstrap DNS must not be scored as a leak or mistaken for successful routing.

### 4.2 TCP, UDP and packet shapes

| ID / priority | Extend | Experiment | Required evidence / calibration |
| :--- | :--- | :--- | :--- |
| T01 / P1 | NSE + real-Tor VM | Open TCP through Tor, stop/kill Tor, then close normally or abort; repeat during teardown | No direct FIN/ACK, RST/ACK, retransmission or payload to the controlled destination; exact flag class visible in calibration |
| T02 / P1 | Existing pre-start send/receive tests | Connections established before start: sending, receive-only, idle then resumed; public/local host source addresses | Existing direct connection cannot carry protected traffic; reset/termination behavior and LAN exception remain explicit |
| T03 / P1 | Leak probes | Arbitrary UDP, STUN, QUIC, ICMP/ICMPv6, multiple ports and both families while Tor is healthy/down | Non-exempt direct egress is detected independently of response; permitted TCP still works in the healthy case |
| T04 / P2 | NSE stimuli/classifier | IPv4 fragments, IPv6 fragments/extension headers, unusual TCP flags and other IP protocols | Classifier demonstrably sees each class before containment is evaluated; unsupported parsing is inconclusive rather than clean |
| T05 / P1 | Real-Tor VM | Long-running upload/download plus new connections while Tor listeners/circuits fail and restart | Capture covers the whole failure; destination logs distinguish Tor exits from the direct path; availability reported separately |

Generate ordinary socket close/abort traffic first for T01. Crafted raw-packet
variants belong to privileged packet-shape testing and do not establish a
security promise against applications holding raw-packet capabilities.

### 4.3 Faults, lifecycle and networking

| ID / priority | Extend | Experiment | Required evidence / calibration |
| :--- | :--- | :--- | :--- |
| F01 / P0 | Chaos VM + external observer | Continuously stimulate TCP, UDP and DNS while running all existing injections, in chained/fresh/no-bypass variants | Observe injection-to-reaction interval; report leaks and recovery separately; no 18-second blind interval |
| F02 / P1 | Session systemd fixture + full VM | Watchdog SIGKILL, SIGSTOP, timed-out check, lost event subscription and restart with an existing emergency latch | Kernel barrier behavior observed continuously; stale supervision never reported healthy; independent handler and latch behavior verified |
| F03 / P1 | Chaos / DNS fixture | Unmount or replace overlay, restart resolved, make evidence unreadable, fail subscription/readback | Containment and unknown evidence distinguished; repairs do not silently reopen a latched emergency |
| L01 / P1 | Startup VM | Continuous traffic during normal start; fail/interrupt Tor setup, rules load, DNS setup, lock write and watchdog readiness separately | Exact first protection boundary and each rollback outcome observed; inject faults at acknowledged phase checkpoints |
| L02 / P1 | Teardown NSE + VM | Normal stop, restore-only, partial cleanup, interrupted cleanup and restart; retain live application sockets | Ordering measured through deliberate release; required-VPN guard retained while managed Tor remains live; no retrospective protected claim |
| L03 / P1 | Existing lifecycle VM | Shutdown, reboot and suspend/resume with new subnet, both families where applicable | Shutdown containment; reboot explicitly inactive/unprotected; resume containment or documented latched emergency with complete capture |
| N01 / P1 | VM network fixture | New interface/address/default route, IPv6 appearing after start, route deletion/fallback, DHCP renewal and NetworkManager restart | Every NIC observed; ordinary actor cannot acquire a new direct route while protected; packet-level controls per family |
| N02 / P2 | Hardware/VM matrix | Ethernet-to-Wi-Fi handover, captive portal, real sleep/wake, physical link loss and reconnect | Repeatable recipe, upstream capture and recorded hardware/kernel; no claim that virtual S3 qualifies every laptop |
| N03 / P1 | Competing-ruleset NSE + VM | Existing Docker/UFW/firewalld/WireGuard shapes; reload real firewall managers during traffic | Distinguish coexistence from destructive removal; rule-specific mutation detects regressions; recovery cannot hide initial exposure |

L01 requires documenting the intended failure contract before assigning pass
criteria to rollback. That contract is [Startup phases and their failure contract](../web/explanation/startup.md). The plan does not silently change a failed start into a
persistent lockdown feature. Keep full-capture diagnostics even for failures
that occur before the normal session lock exists.

### 4.4 Exceptions and applications

| ID / priority | Extend | Experiment | Required evidence / calibration |
| :--- | :--- | :--- | :--- |
| E01 / P0 | Ruleset + controlled onion service | Resolve onion names into configured virtual ranges and connect with LAN bypass enabled/disabled; include IPv4/IPv6 and reused mappings | Confirm actual route and Tor handoff; any direct synthetic-destination packet is visible; establish impact before choosing a fix |
| E02 / P1 | Bypass tests | UID, GID, supplementary groups, cgroup ancestry/child processes and explicit root bypass; verify a neighboring ordinary identity | Only documented principals bypass; descendant/group semantics tested; no accidental exemption from unrelated counter or service identity |
| E03 / P1 | LAN tests | Private destinations on-link and behind another route, LAN DNS, IPv6 ULA/link-local, `--no-lan-bypass` | Distinguish expected exception from prohibited egress; strict profile forbids application LAN traffic while required control traffic stays explicit |
| E04 / P1 | Local service integration | Ordinary process calls a local HTTP/SOCKS/DNS broker running under an exempt identity; inspect listener/control-socket permissions | Identify actual indirect egress and access requirements. If policy permits it, document the trust boundary; otherwise reproduce and fix access enforcement |
| E05 / P1 | Forwarding tests | Routed container/netns versus bridge/macvlan paths; system Tor coexisting with managed Tor; representative BYOD configuration | Document each controlled hook/exemption; exercise contained and intentionally excluded paths without a blanket container-protection claim |
| A01 / P1 | New browser fixture using existing VM observer | Chromium and Firefox with system DNS, DoH, QUIC on/off; page requests during Tor loss | Real requests work over Tor; direct traffic identified externally; a browser fixture cannot pass merely because every request failed |
| A02 / P1 | STUN + browser fixture | WebRTC ICE/STUN/TURN, including TCP/TLS fallback, with fresh browser profiles | Server-reflexive public IP evidence checked against capture; local/mDNS candidates reported separately from WAN leaks |
| A03 / P2 | Application integration | curl, package download, SSH and an application that ignores proxy configuration; retry/fallback during faults | Controlled receiver logs and whole-interface capture; root package-manager behavior tested according to the selected bypass profile |

Use controlled receivers and a small controlled web page rather than depending
on public leak-test website UI. No public BitTorrent traffic is necessary;
if that family is later added, use a private tracker/peer fixture. Network
containment tests do not endorse an application as anonymous or suitable for Tor.

### 4.5 Required VPN qualification

| ID / priority | Extend | Experiment | Required evidence / calibration |
| :--- | :--- | :--- | :--- |
| V01 / existing 0.5.0 gate | Offline + QEMU VPN fixtures | Complete bridge, IPv6 underlay/tunnel combinations, suspend/reboot and ParrotOS qualification already required by the VPN guide | Real Tor and DNS where claimed; separately calibrated underlay/tunnel observations; unsupported profiles refused before changes |
| V02 / P1 | QEMU VPN fixture | Continuous ordinary and Tor-identity traffic during tunnel removal, route fallback, changed interface identity/endpoint and NetworkManager restart | No direct Tor fallback; only narrowly allowed transport/control traffic on physical link; capture includes the initial failure window |
| V03 / P1 | VPN stop/emergency tests | Watchdog loss, reconnect after fault, partial stop and Tor cgroup still populated | Emergency remains latched; guard removal requires documented termination evidence; expected clearnet only after deliberate release |

The VPN observer must distinguish outer WireGuard traffic, DHCP/ND/ARP control
traffic and application payload. An allowlist based on the WireGuard mark and
endpoint is not authenticated process identity; privileged spoofing remains a
documented trust boundary. Passing an offline Tor-UID probe does not qualify a
real Tor circuit, a transport, a provider or an untested IP-family combination.

## 5. Matrix selection and CI cost

Avoid an unbounded Cartesian product. Keep an explicit scenario manifest with
each required combination, its expected policy, implemented test and latest
evidence. Use pairwise coverage for secondary dimensions, but always include
the high-risk interactions below.

| Dimension | Required baseline | Extended coverage |
| :--- | :--- | :--- |
| Session policy | Managed Tor, ordinary identity, no bypass; default LAN behavior; strict no-LAN; watchdog on/off | Each explicit UID/GID/cgroup/root bypass separately, then selected combinations; notifications on/off for state accuracy |
| Tor ownership | Dedicated managed daemon | Representative supported BYOD profile, separate lifecycle expectations and coexisting system Tor |
| Address families | IPv4; IPv6 enabled; IPv6 disabled on a host that really has IPv6 | IPv6 introduced during session, family-specific route changes, packet-shape cases |
| Resolver | No resolved; real systemd-resolved stub and IPC | Alternate resolv.conf forms, multi-link DNS/DNSSEC and restart |
| Platform | Debian/systemd-networkd and Fedora/NetworkManager with SELinux enforcing | Arch integration, oldest supported nftables/kernel where obtainable, Fedora 45 package qualification and required ParrotOS VPN checks |
| Tor path | Controlled offline path for rule tests; public Tor for end-to-end claims | Qualified bridges/transports and required VPN; record exact transport/version |
| Execution | Fresh-session and no-bypass faults; existing chained sweep retained | Repeated seeded stress and actual hardware handover/sleep |

Mandatory interactions: LAN + automap; competing DNAT + LAN DNS; resolved UID
and IPv6; disabled IPv6 + each bypass; healthy versus dead Tor + FIN/RST;
watchdog loss + existing emergency; new NIC/default route + active session;
VPN fallback + Tor UID; stop failure + populated Tor cgroup. No-bypass tests
must also run without an added canary exemption. Test watchdog-off containment
with intact rules without expecting automatic repair of removed enforcement.

| Cadence | Proposed contents | Treatment |
| :--- | :--- | :--- |
| Relevant PRs | Oracle/capture unit tests, NSE and affected integration scenarios | Deterministic required checks; triggers include the harness, classifier, settings and safety/evidence dependencies |
| Relevant privileged/lifecycle PRs | Bounded VM core: F01, L01/L02, T01, N01 and affected VPN cases | Required when changing the exercised contract; hard timeout and artifacts on failure |
| Scheduled | Full distro/profile manifest, browsers and repeated faults | Fixed seeds plus recorded varied seeds; publish failures and uncovered combinations |
| Release candidate | Full P0/P1 manifest for that exact candidate and supported profiles, existing release/package checks | Zero unresolved in-scope leaks and zero missing required evidence; no reliance on an earlier commit's green run |
| Hardware qualification | N02 on named systems | Manual recipe with attached artifacts; scope claims to measured hardware |

A flaky or unavailable public-Tor dependency can invalidate a run, but must not
turn it green. Preserve the first failure before a bounded rerun; do not retry
away a captured leak. Additional NSE capabilities must be scoped separately
from TTP work, preserving the existing dependency boundary.

## 6. Delivery order

These are reviewable implementation slices, not a request to implement every
row at once. Split further when evidence requires it. Record each scenario as
planned, implemented, measured, blocked or not-applicable with supporting links.

| Slice | Depends on | Deliverable and completion criterion |
| :--- | :--- | :--- |
| 1. Correct evidence | This plan | O01 and focused oracle regressions; timeout/error/counter-only observations cannot certify containment; reconcile public claims |
| 2. Triage current behavior | Slice 1 evidence contract | E01 reproduction plus captures; L01 first-barrier and rollback contract inventory; confirmed current leaks enter the affected release's fix queue |
| 3. Trust the observer | Slice 1 | O02, continuous capture/stimulus, sequence IDs, phase/time model and controlled receivers; deliberately blind/broken experiments fail visibly |
| 4. Observe faults | Slices 2–3 | F01–F03 and L01–L03; retain old recovery checks but publish initial exposure and recovery separately |
| 5. Expand kernel paths | Slice 3 | D01–D04, T01–T03, N01/N03 and E02–E05; specific mutations and allowed-path checks for each family |
| 6. Qualify real applications | Slices 3–5 | A01/A02 and T05 with real Tor; browser privacy observations separated from network verdicts |
| 7. Finish VPN evidence | Existing ADR 0015 contract; slice 3 for new observer features | V01 stays a 0.5.0 gate; V02/V03 extend coverage without widening supported VPN configurations |
| 8. Release and review | All required P0/P1 evidence | Published matrix/artifacts, refreshed threat assessment and focused independent human review; record reviewer availability and unresolved findings honestly |

Confirmed false-positive test logic should be corrected at the earliest
applicable release. Do not defer a demonstrated in-scope runtime leak simply
because this plan is associated with post-0.5.0 work. Existing 0.5.0 VPN gates
remain mandatory for publishing that feature as supported.

Default-on watchdog, default-off LAN, local-service access restrictions,
pre-start persistent protection and any new isolation architecture are separate
product decisions. Bring measured failures and compatibility effects to those
decisions; the testing plan does not silently approve them. Defer `ttp run`
until the core P0/P1 evidence is complete.

## 7. Required artifacts and release acceptance

Each scenario result must retain:

- Scenario ID, exact source revision/diff, seed, distro image/checksum, kernel,
  nftables/systemd/Tor versions and effective profile; never VPN credentials or
  private keys. Use disposable test identities and non-sensitive application data.
- Raw captures for all relevant interfaces, receiver/query logs, stimulus counts,
  observer readiness/completeness and controls/mutation results. A missing
  required artifact invalidates the result.
- Phase/injection timeline with clock uncertainty; kernel rules and counters,
  routing/interface snapshots, session/watchdog evidence and relevant journal.
- Separate containment, permitted-path availability, reaction/hold and UI-state
  conclusions; first/last forbidden packet, packet/byte count and timing bounds
  when exposure occurs. Include the actual sampled interval/cadence.
- Machine-readable summary and a short human explanation. Link every claimed
  property to scenario IDs and exact artifacts; publish matrix totals for
  measured, missing, failed and not-applicable combinations.

The hardening release gate is complete only when required P0/P1 combinations
are measured against the release candidate; ordinary in-scope traffic has no
observed prohibited egress in its protected intervals; allowed paths work;
controls and targeted mutants establish that regressions can be detected;
and unknown/missing evidence cannot produce a pass. Privileged removal of the
entire barrier must retain its measured exposure and explicit scope limitation
instead of being presented as continuous protection.

Update README, security assessment, verification explanation and VM recipes
with those exact limits. The current AI-assisted audit is useful evidence but
must remain distinct from independent human review. Security-critical runtime
fixes follow the repository's documentation and regression requirements.

## 8. Reference methods

- [Whonix leak tests](https://www.whonix.org/wiki/Dev/Leak_Tests): dependency
  removal, Tor loss, FIN/RST and application-specific observation.
- [Tails Tor enforcement](https://tails.net/contribute/design/Tor_enforcement/):
  same-system resolver handling, privileged exceptions and local-service access.
- [Qubes firewall](https://doc.qubes-os.org/en/r4.3/user/security-in-qubes/firewall.html):
  enforcement separated from the client, and lifecycle caveats.
- [ExpressVPN leak-testing tools](https://www.expressvpn.com/digital-security-lab/leak-testing-tools):
  network transitions, unreachable endpoints and process crashes.
- [Mullvad test manager](https://github.com/mullvad/mullvadvpn-app/tree/main/test/test-manager):
  VM-based end-to-end application testing.

These sources inform the experiments. They do not establish equivalence to
their security architectures or certification by those projects.
