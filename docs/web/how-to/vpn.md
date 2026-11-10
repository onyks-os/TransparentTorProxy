<!-- Copyright (c) 2026 onyks-os; SPDX-License-Identifier: MIT -->

# Require a VPN before Tor

This optional 0.5.0 feature is unreleased. Its release qualification, including
ParrotOS VM testing, must complete before it is described as supported in a
published release. See the validation limits below.

The supported order is **user → VPN → Tor → destination**. TTP's Tor connects
to its guards or bridges through the VPN; websites still see a Tor exit.
Combining VPN and Tor does not automatically improve anonymity. The VPN knows
your source address and can observe connections to Tor. This does not prevent
traffic correlation, browser fingerprinting, account identification, or a
privileged administrator changing the host. See the
[Tor Project advice](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
and [Whonix's comparison](https://www.whonix.org/wiki/Tunnels).

## Supported configuration and prerequisites

| Requirement | Initial contract |
| --- | --- |
| VPN backend | Native NetworkManager WireGuard; already active before TTP |
| Selection | Explicit NetworkManager connection UUID; no guessing by interface name |
| Peers | Exactly one, with a numeric fixed IP and port |
| Routing | Full IPv4 tunnel; full IPv6 tunnel or explicit `--no-ipv6` |
| Physical underlay | Ordinary Ethernet/Wi-Fi, VM Ethernet or veth; VLAN, bridge, bond and other virtual underlays are refused in the initial implementation |
| Supervision | Watchdog required; optional desktop notifications remain independent |
| Service teardown | Unified cgroup v2; retain protection until the managed Tor cgroup is empty |
| Tor | Dedicated TTP-managed instance, including its bridge transport children |
| Bypasses | No root, UID/GID, cgroup or LAN bypass |
| Ownership | VPN configuration, credentials, activation and shutdown remain with the user/VPN manager |

OpenVPN, provider applications, `wg-quick`, VPN-after-Tor, split-tunnel VPNs,
multiple VPNs/peers, endpoint hostnames/roaming, and external Tor daemons are
outside the initial contract. A VPN client which flushes unrelated firewall
tables is incompatible. Containers, forwarded clients and gateway deployments
are not covered by this mode; forwarding is blocked.

Applications with network administration or raw-packet capabilities require
separate trust. In particular, the mark/endpoint exception identifies allowed
WireGuard transport packets, not an authenticated application identity. Do not
use this mode as a sandbox for privileged pentesting tools or malicious root
processes; they can manipulate networking or exploit control-traffic exceptions.

Install NetworkManager, WireGuard tools (`wg`), iproute2 (`ip`) and systemd's
`busctl` using the distribution package manager if absent. These are optional
mode dependencies; TTP does not install them. Existing TTP dependencies still
apply. NetworkManager's selected peer must have full-tunnel AllowedIPs, a live
nonzero WireGuard fwmark, and consistent kernel settings. TTP refuses ambiguous
or changed evidence instead of rewriting the profile or routing policy.

## Start the session

Configure and activate the VPN using your existing trusted workflow. TTP does
not import a provider configuration or fetch credentials. Inspect public profile
identities with:

```bash
nmcli -f NAME,UUID,TYPE,DEVICE connection show --active
```

Then select that connection explicitly (replace the sample UUID):

```bash
sudo ttp start --require-vpn 12345678-1234-4234-8234-123456789012 \
  --watchdog --no-lan-bypass --no-ipv6
```

Omit `--no-ipv6` only when the selected VPN covers IPv6 as well. Add
`--notifications` if you want optional desktop delivery. For direct root
invocations, select a notification recipient as described in
[Supervision and notifications](session-observations.md).

Missing or unsupported VPN evidence returns **10** before network changes.
The effective path, device indices, active-connection identity, public peer,
endpoint and mark are frozen for the session. TTP never requests NetworkManager
GetSecrets or reads WireGuard private/preshared keys. Do not use `wg ... dump`
in diagnostic reports: it can include secrets.

## What enforces the path

Before starting Tor, TTP records private recovery intent and installs a separate
`inet ttp_vpn` table. It permits loopback, the Tor UID on the frozen tunnel
device, and narrowly scoped WireGuard outer packets to the frozen endpoint on
the frozen physical device. Other application egress and forwarding are
blocked even before the main transparent-proxy rules exist. The normal TTP
table gets the same transport exceptions and disables cgroup bypass rules.

The underlay exceptions also allow root-owned DHCPv4 client traffic (68 → 67),
DHCPv6 client traffic (546 → 547), and IPv6 router solicitation/neighbor
discovery with hop limit 255 on the frozen underlay. They are network control
traffic, not a general root exemption. ARP is outside the inet ruleset. Do not
interpret this mode as a promise that no unencapsulated physical packet exists.

The independent table uses explicit postrouting/forward hooks, priorities and drop
policies. Its verification compares kernel JSON against the expected frozen
specification. An observed ruleset hash is not adopted as the specification.
Interface names in the kernel response are resolved back to their indices, so
recreating an interface with the same name does not inherit trust.
The egress check runs after routing: in OUTPUT a redirected TCP connection can
still expose its original tunnel interface even though its destination has
become Tor's loopback listener. Checking the final device avoids blocking that
connection without allowing application packets onto the tunnel or underlay.

The protection does not depend on a polling check noticing a route change:
Tor packets routed to the physical link are already forbidden. The required
watchdog adds bounded observation and emergency response; process scheduling
prevents a promise of immediate notification or instantaneous fault detection.

## Observe evidence and respond to a fault

```bash
sudo ttp status
sudo ttp status --json
sudo ttp monitor
```

VPN state `constrained` means the current local profile/device/routing evidence
agrees with the frozen policy and the independent kernel rules were verified.
It does **not** prove a recent successful provider handshake or continuous
remote reachability. A tunnel may retain its interface and routes while the
remote peer is unreachable. The VPN state and `guard_verified` are independent:
a disconnected profile can be unknown while the kernel guard is still present.

The JSON field `handshake_at` is the last recorded WireGuard handshake in Unix
wall-clock seconds (null when none), not a new connectivity measurement.
The existing rejected-packet counter belongs to the main TTP table; it does not
count packets dropped by the independent VPN guard.

`ttp check` deliberately performs a new Tor verification. A result `IsTor=true`
does not by itself prove a VPN path. If the required VPN evidence is unavailable,
the check requests emergency containment before attempting an external probe.
`status` and `monitor` remain passive. Desktop notifications contain concise
incidents without the public peer key, endpoint or credentials.

Disconnect, profile reactivation, changed device index, changed endpoint/mark,
an observed route fallback or missing/altered guard causes the watchdog to
request emergency containment. A NetworkManager restart or underlay interface
replacement may therefore require a fresh TTP session. No other VPN or direct
Tor connection is silently substituted. Failure to read evidence is unknown.

Emergency containment blocks input, output and forwarding except loopback,
including VPN reconnection traffic. **A reconnected VPN does not reopen the
session.** Existing emergency requested/applied/verified evidence and exit
codes 7/8 still apply; the VPN diagnostic is retained alongside other causes.

## Stop and recover deliberately

Close sensitive applications first. After stopping TTP those applications can
communicate without Tor, and may use the physical network if the external VPN
is down or later disconnects.

```bash
sudo ttp stop
```

TTP stops its watchdog and managed Tor, restores its normal firewall/DNS
changes, verifies Tor has no systemd main/control process or populated cgroup, and removes the VPN
guard last. It leaves the externally managed VPN alone. `ttp restart` refuses
required-VPN sessions before teardown because stop/start has an unprotected
interval. Use explicit stop and then start only after closing sensitive work.

An interrupted startup can leave `vpn-intent.json` and kernel protection even
without a normal session lock. `status` reports retained protection and a new
start refuses to adopt it. Use:

```bash
sudo ttp stop --restore-only
```

If Tor termination or kernel inspection is unconfirmed, protection is retained
and recovery fails visibly. Inspect `journalctl -u ttp-tor -u ttp-watchdog` and
`sudo nft list table inet ttp_vpn`. Do not delete the guard merely to clear a
startup error while Tor might still be running. Preserve console access for
recovery: this mode can intentionally disconnect the host.

The session does not survive reboot. TTP's Tor unit, runtime intent and tables
are volatile; after reboot TTP makes no Tor or VPN guarantee. Your VPN's own
autostart policy is separate.

## Validation limits and release gate

| Qualification | Status |
| --- | --- |
| Adversarial profile, CLI and recovery unit tests | Implemented |
| Real NM/WireGuard, independent capture and guard-removal mutation | Implemented in offline container fixture |
| IPv6 payload/outer transport, required watchdog and explicit stop | Implemented with `TTP_VPN_DUALSTACK=1` |
| Public Tor startup and DNS, IPv4 underlay/tunnel | Implemented in the external QEMU VM fixture |
| DHCPv4 renewal with matching request/ACK and retained emergency across reconnect | Implemented in the external QEMU VM fixture |
| Bridge transport through the required tunnel | Pending release qualification |
| Remaining IPv6 combinations and suspend/reboot transitions | Pending release qualification |
| ParrotOS VM installation and networking | Pending; mandatory before 0.5.0 publication |

`scripts/check-vpn.sh` runs a real NetworkManager/WireGuard tunnel and local
peer inside a disposable offline systemd container. Capture is on the peer's
physical side. Positive controls and deliberate removal of the VPN guard prove
the observer can detect the prohibited direct path. It also tests route fallback,
reconnection with changed identity, coexistence with the TTP table and retained
protection while a systemd Tor test process is live.

That fixture uses a controlled Tor UID probe, **not a public Tor circuit**. It
does not establish real-provider compatibility, every IPv6 combination, DHCP renewal,
Tor bridges, suspend/resume or ParrotOS support. Those require VM qualification
before 0.5.0 release: actual TTP startup and Tor verification through the tunnel,
DNS interception, IPv4/IPv6 underlay and tunnel combinations, transport failures,
watchdog loss, emergency latching, stop/recovery and reboot/suspend transitions
with an observer outside the guest. Include ParrotOS package installation and
its NetworkManager configuration; keep failures/inconclusive results visible.

The [QEMU qualification recipe](vm-testing.md#required-vpn-with-real-tor) covers
the first IPv4 underlay/tunnel path with real Tor, non-exempt hostname-based
HTTPS verification, DHCP renewal, tunnel loss and emergency persistence after
reconnection. It captures the client's physical path outside the guest. Cleartext
controls must be reachable before protection and after explicit stop. The stop
phase ends protection intentionally; restored resolver/network services may
then emit ordinary physical traffic. This does not complete the remaining gates
in the table above.

The architecture follows [Whonix's VPN-before-Tor fail-closed principle](https://www.whonix.org/wiki/Tunnels/Connecting_to_a_VPN_before_Tor)
and the [Qubes community VPN gateway design](https://www.qubes-os.org/doc/vpn/).
Their gateway rules are not copied onto a TTP host. Technical references:
[WireGuard routing](https://www.wireguard.com/netns/),
[NetworkManager non-secret settings API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html),
and [nftables hook/verdict behavior](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
