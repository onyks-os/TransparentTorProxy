# Onion addresses and LAN bypass

Since the development version for 0.5.0, TTP reserves **10.192.0.0/10** and
**fc00::/8** for its managed Tor's virtual addresses. They are synthetic
destinations used for Tor name mappings, not ordinary LAN destinations.
TCP traffic from non-exempt applications to these ranges is redirected to
Tor's TransPort **before LAN exemptions**, even with the default LAN bypass.
Other unredirected traffic to these destinations is rejected before the LAN
and local-address accepts. DNS retains its earlier interception rules.

## What this fixes

Tor's `AutomapHostsOnResolve` returns a virtual A/AAAA address for an onion
name. The application then connects to that address; Tor must receive the
connection and map it back to the onion service. Before this fix, the virtual
IPv4 range overlapped the private IPv4 LAN exemption, and the virtual IPv6
range occupied all ULA (`fc00::/7`). LAN accepts ran before TCP interception.

A disposable VM with real Tor and a fixture-owned ephemeral v3 onion confirmed
direct TCP SYNs and UDP datagrams to the actual mapped addresses on its
external QEMU capture when LAN bypass was enabled. It did not establish a
successful direct onion HTTP transfer or arrival at a public Internet server.
The destination being private does not make that direct egress the intended
Tor handoff. A timeout did not prevent the observed packets from escaping.

## Compatibility and limits

- `10.192.0.0/10` is reserved for Tor. An ordinary LAN service in that range
  cannot be reached directly by a non-exempt application during the session.
- IPv6 automapping now uses `fc00::/8`, the L=0 half of ULA. Locally assigned
  ULA networks in `fd00::/8` retain their normal LAN bypass behavior. This is a
  TTP virtual-address choice, not an assignment of a real routed network.
- Other private and link-local LAN exceptions remain as documented. Use
  `--no-lan-bypass` to disable application LAN bypass generally.
- Explicit Tor/UID/GID/cgroup/root exemptions retain their own semantics. An
  intentionally exempt application is not covered by the ordinary-actor claim.
- Automap addresses are session-local. Close applications, stop TTP explicitly
  and restart after upgrading; discard cached synthetic addresses. Old IPv6
  addresses from the previous `fc00::/7` configuration, especially `fd...`
  mappings, must not be reused as destinations in a new session.
- With `--external-daemon`, TTP does not configure Tor. Align that daemon's
  virtual ranges with these reservations if using automapping. Arbitrary
  custom virtual ranges are not discovered or automatically protected as
  synthetic destinations by this fix.
- A namespace test establishes the redirect/drop behavior, not onion service
  availability. End-to-end requests are checked separately in the VM.

See the [Tor manual](https://manpages.debian.org/unstable/tor/tor.1.en.html)
for automapping, and [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193.html#section-3.1)
for the ULA L bit.

## E01 regression and evidence

```bash
VM_WORK=/absolute/path/to/new-automap-vm bash scripts/vm/automap/run.sh
```

Run this on the VM host, with QEMU/KVM and the same prerequisites as the
[VM guide](vm-testing.md). It provisions a disposable Debian guest and installs
the candidate source. Never run the guest fixture on your normal host.

The fixture creates a nonce-returning loopback HTTP service and an ephemeral
v3 onion through the managed Tor control socket. Its private onion key is
discarded, not written into the evidence. For each LAN policy, real Tor DNS
returns A/AAAA mappings twice; repeated resolution must reuse each mapping.
TCP and UDP probes run as UID/GID 65534, without supplementary groups or
effective capabilities. Eight protected HTTP requests must return the nonce;
all sixteen protected TCP/UDP attempts must have no matching direct packet.

Full-frame capture is taken outside the guest, before user-network NAT.
Non-IP phase beacons delimit each attempt without adding an application IP
exemption. Same-address controls with enforcement removed run before and after
each profile. In the LAN profile, a targeted mutant removes only the virtual
redirect/guard rules; all four family/protocol channels must escape. Control
and mutant intervals are intentionally unprotected and reported separately.
The watchdog is intentionally off for this ruleset experiment, so it cannot
repair the mutation before measurement.

The reader rejects missing controls, incomplete capture or phases, wrong
identity, absent attempts and unavailable protected onion responses. Observed
protected egress remains a leak even if later capture data is lost. Retained
artifacts include the full PCAP, JSONL attempts/phases, JSON report, errors,
source revision/diff and VM logs. The lifecycle workflow runs this gate and
uploads those artifacts; NSE also tests the targeted mutation and ordinary LAN
destinations outside the reservations.

This qualifies the stated synthetic ranges, protocols and profiles. It does
not qualify every custom BYOD configuration, forwarded client, startup/stop
transition or browser behavior. Public Tor or onion publication failures fail
the experiment rather than being treated as successful containment.
