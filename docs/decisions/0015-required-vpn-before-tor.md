<!-- Copyright (c) 2026 onyks-os; SPDX-License-Identifier: MIT -->

# ADR 0015: Required VPN before managed Tor

## Status

Accepted by the maintainer, 2026-11-08. Implementation and release qualification
in progress for 0.5.0. This approves the VPN scope separately from ADR 0013.

## Decision

The initial mode is user → VPN → Tor → destination, using an already active
native NetworkManager WireGuard connection selected by UUID. Require one peer,
a stable numeric endpoint and a full IPv4 tunnel, with full IPv6 coverage or
explicit `--no-ipv6`. TTP does not own VPN activation, keys or shutdown.
External Tor, OpenVPN, provider applications, wg-quick, multiple/split tunnels
and endpoint roaming are outside this initial contract.

Require the watchdog, disable LAN and all root/UID/GID/cgroup bypass, and refuse
`restart` before teardown. Require local profile/kernel agreement and freeze
active-connection identity, interface indices, peer, endpoint and fwmark. Never
request NetworkManager GetSecrets or WireGuard secret-bearing dump output.

Before managed Tor starts, publish private root recovery intent and install an
independent kernel guard. Its drop policy permits loopback, the Tor UID only
through the frozen tunnel, and narrowly scoped VPN transport/control traffic.
Use a postrouting egress hook to inspect the final device after transparent
redirection; an OUTPUT device match can retain the original route and block
local TransPort traffic. Keep the independent forwarding drop hook.
Normal transparent-proxy rules share the transport exceptions. Verify the guard
against the expected specification, never against a hash first read from the
kernel. Route samples aid diagnosis; packet constraints enforce the boundary.

Loss/change/unreadability of required evidence requests emergency containment,
which remains latched across VPN reconnection until explicit stop. Ordinary
containment verification and precedence from ADR 0013 apply; add code 10 for
required VPN unavailable/refused. Show VPN observations independently of Tor
verification and guard presence. No active requests are added to monitor/status.

Stop Tor before releasing the guard, and remove it last. Interrupted startup
retains enough intent to refuse another session and permit explicit restore-only
recovery. Unconfirmed termination or kernel inspection must retain protection.
The external VPN remains under its owner's control. Reboot ends the TTP session.

## Consequences and validation

This mode can intentionally disconnect a host, including VPN recovery traffic
while emergency containment is latched. It does not inherently improve anonymity
or promise remote VPN liveness. Profile/device status, kernel constraints and a
historical Tor verdict are distinct evidence. Minimal underlay control traffic
and ARP mean the contract is not "no unencapsulated packets".

Use public profile/kernel and CLI adversarial tests, then real WireGuard/NM
kernel tests with an observer outside the tunnel, positive controls and a guard
removal mutation. Release qualification must also cover actual Tor/DNS/bridges,
IPv4/IPv6, lease renewal, network changes, watchdog failure, emergency retention,
stop/recovery and suspend/reboot in disposable VMs, including ParrotOS. The
[operator guide](../web/how-to/vpn.md) is the discoverable source for supported
configurations, limitations, commands, recovery and validation status.
