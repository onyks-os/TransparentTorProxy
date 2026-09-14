# 12. DoH, DoT and browser-level leaks are out of scope for the firewall

Date: 2026-09-14

## Status

Accepted.

## Context

TTP's `filter_out` chain carries rules that reject DNS-over-TLS (`tcp dport 853`)
and DNS-over-HTTPS, the latter as a hardcoded blocklist of eight IPv4 and eight
IPv6 addresses belonging to Cloudflare, Google, Quad9 and OpenDNS
(`ttp/firewall/builder.py:148-156`).

Tracing when those rules actually match shows they almost never do:

- **Non-bypassed process, TCP/443.** `nat output` redirects all TCP to Tor's
  `TransPort` at priority `-150`, before `filter_out` runs. By then the
  destination address is `127.0.0.1`, so `ip daddr { 1.1.1.1, ... }` no longer
  matches. The rule never fires.
- **Bypassed process.** The bypass rules are bare `accept` at position 1b of
  `filter_out` (`builder.py:108,114`), above the DoH rejects at position 6. The
  packet is accepted first. The rule never fires. The comment in the ruleset
  claiming these rules "apply to bypassed users" is wrong and is corrected.
- **UDP/443 (QUIC DoH), non-bypassed.** Here the rule does fire — but the
  catch-all `reject` at position 8 would reject the datagram anyway. Redundant.

One case remains: a non-bypassed TCP flow where the NAT redirect failed. That is
genuine defence in depth, and it is the only reason to keep the rules.

The deeper problem is that the blocklist cannot be completed. DoH is
*designed* to be indistinguishable from ordinary HTTPS. There are hundreds of
providers, their addresses change, and any web server can serve DoH on request.
A network-layer filter that tries to enumerate them is losing by construction.

The same reasoning applies one layer up, to WebRTC. TTP rejects all non-exempt
UDP, so a STUN query cannot leave the host — but WebRTC's serious leaks are not
network traffic at all. Host ICE candidates carrying private addresses, mDNS
candidates and local interface enumeration are produced inside the browser and
handed to a web page through a JavaScript API. No firewall can observe them.

## Decision

**The structural guarantee is the claim TTP makes; the blocklists are not.**

TTP guarantees, for every process that is not explicitly bypassed:

1. all TCP is redirected to Tor's `TransPort`;
2. DNS on port 53 is redirected to Tor's `DNSPort`;
3. every other packet is rejected by the catch-all at the bottom of `filter_out`.

That guarantee **subsumes** DoH and DoT for non-bypassed processes. A DoH query
over TCP/443 goes through Tor like any other TCP connection: the resolver sees a
Tor exit, not the user. A DoT query to port 853 likewise. A QUIC DoH query over
UDP is rejected along with all other UDP. None of this depends on knowing who
the resolver is.

For **bypassed** processes, DoH and DoT are explicitly **out of scope**. A
bypass is a deliberate request to sit outside the proxy; filtering the DNS of a
process that is already sending cleartext to the WAN is not a security property,
it is an inconsistency.

**Browser-level WebRTC leaks are out of scope** for the same structural reason:
they are not packets. They are mitigated in the browser
(`media.peerconnection.enabled`, `network.trr.mode`, enterprise policy), and
TTP's documentation says so rather than implying coverage it cannot have.

The existing DoH and DoT rules are **kept**, reclassified as defence in depth
against a failed NAT redirect, and documented as such in the ruleset. They are
not advertised as DoH protection.

## Consequences

- The README and the threat model state the structural guarantee, not a list of
  blocked resolvers. This is a stronger claim and a true one.
- The false comment in `builder.py` about the rules applying to bypassed users
  is corrected; the code no longer claims an effect it does not have.
- The DoH blocklist is not extended. Adding addresses would deepen the
  impression that enumeration is the mechanism, which is the misconception this
  decision exists to remove. If the list is ever touched, it should be to make
  the rules *counted* rather than longer: a non-zero counter on a DoH reject
  means the NAT redirect failed, which is a real alarm about TTP itself.
- The offensive probe formerly named `test_webrtc_leak.py` is renamed
  `test_udp_egress_leak.py` and asserts what it actually verifies — that
  arbitrary WAN-bound UDP is rejected — with STUN kept only as a realistic
  payload.

## Alternatives considered

**Extending the blocklist.** Rejected: unbounded, and it teaches the wrong model
of how the protection works.

**Blocking all outbound TCP/443 except to Tor.** Already the case for
non-bypassed processes, via the NAT redirect. Nothing to add.

**Deep packet inspection to identify DoH.** Rejected: DoH inside TLS is not
distinguishable without breaking TLS, which is not something an anonymity tool
should be building.

**Removing the rules entirely.** Rejected: the failed-NAT case is real, and the
rules are cheap. They are kept with an honest label instead.
