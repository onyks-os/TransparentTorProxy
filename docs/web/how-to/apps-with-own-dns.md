<!--
Copyright (c) 2026 onyks-os
SPDX-License-Identifier: MIT
-->

# How-To: Check applications that resolve DNS on their own

TTP redirects the system's DNS: `/etc/resolv.conf` and `systemd-resolved` both end
at Tor's `DNSPort`. Some applications do not ask the system at all. Browsers can
speak DNS-over-HTTPS (DoH) themselves, `systemd-resolved` can be told to use
DNS-over-TLS (DoT) on one link, and container runtimes run their own resolver.

This page explains what happens to each of them under TTP, and how to check a
host by hand. There is no `ttp` command for it, and that is deliberate: see
[Why there is no DNS auditor](#why-there-is-no-dns-auditor) at the end.

---

## 1. The rule that decides every case

For every process that is **not** bypassed, TTP makes one structural guarantee
([ADR 0012](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0012-doh-dot-and-browser-leaks-are-out-of-scope.md)):

1. all TCP is redirected to Tor's `TransPort`;
2. DNS on port 53, UDP or TCP, is redirected to Tor's `DNSPort`;
3. every other packet is rejected.

So the question for any application is never "does TTP know this resolver?", only
"which of those three does its traffic fall into?". The answer is always one of
three outcomes:

| Outcome | Meaning |
| :--- | :--- |
| **Through Tor** | The query leaves via a Tor exit. Your ISP sees nothing; the resolver sees a Tor exit, not you. |
| **Blocked, not leaking** | The query is rejected. Nothing leaves, but name resolution in that application fails, and it can look like a broken network. |
| **Outside TTP** | The traffic is not TTP's to route: a bypassed process, or a network namespace whose packets never cross the host's IP stack. |

---

## 2. Case by case

| Source | What happens under TTP | Outcome |
| :--- | :--- | :--- |
| **Firefox DoH** (`network.trr.mode` 2 or 3) | DoH is HTTPS on TCP/443, so it goes to Tor like any connection. In managed mode TTP also maps a few well-known DoH hostnames (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`, `doh.opendns.com`, `dns.adguard.com`) and Firefox's canary domain to `0.0.0.0` in `torrc`. A provider reached by one of those names cannot be resolved: mode 2 falls back to the system resolver, mode 3 has no fallback. | Through Tor; mode 3 against a mapped provider is **blocked, not leaking** |
| **Chrome / Chromium "Secure DNS"** (`DnsOverHttpsMode`) | Same transport: TCP/443 to Tor. In the default *automatic* mode Chrome only upgrades to DoH when the system resolver is a known DoH provider, and under TTP the system resolver is loopback. | Through Tor |
| **DoH over QUIC** (UDP/443) | UDP is not redirected, so the catch-all rejects it; browsers retry over TCP. | Blocked, not leaking; then through Tor |
| **DoT from an application** (TCP/853) | TCP, so it goes to Tor. The `dot_rejected` rule only fires if that redirect failed. | Through Tor |
| **`systemd-resolved`, global settings** | TTP's volatile drop-in sets `DNS=127.0.0.1:<DNSPort>`, `Domains=~.` and `DNSOverTLS=no`, so the global path goes to Tor. | Through Tor |
| **`systemd-resolved`, per-link DNS or DoT** (set by NetworkManager, a VPN, `resolvectl dns <link>`) | resolved may still send some queries to a link's own server. TTP drops every packet from resolved's UID that is not addressed to loopback ([ADR 0009](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/decisions/0009-systemd-resolved-bypass.md)), so those lookups fail. | Blocked, not leaking |
| **A bypassed user, group or `ttp bypass` command** | Accepted before any redirect. DoH, DoT and plain DNS all leave in cleartext, by request. | Outside TTP |
| **Docker, default bridge network** | Container traffic is *forwarded* by the host, and TTP's `filter_forward` chain drops all forwarded traffic, so containers have no network while a session is active. | Blocked, not leaking |
| **Docker `--network host`** | The container's processes are host processes. | The rows above apply |
| **macvlan / ipvlan containers, VMs on a Linux bridge** | Their packets leave through the physical device without crossing the host's IP stack. | Outside TTP |

The last row is a limit of transparent proxying in general, not of DNS: see the
[security assessment](https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/security-assessment.md)
for the full list.

---

## 3. Checking by hand

Run these with a session active.

**The system path is TTP's.**

```bash
findmnt /etc/resolv.conf          # a bind mount from /run/ttp/resolv.conf
cat /etc/resolv.conf               # nameserver 127.0.0.1 only
resolvectl status                  # Global: DNS Servers 127.0.0.1:<DNSPort>, DNSOverTLS no
```

In `resolvectl status`, a **Link** section with its own `DNS Servers` or
`DNSOverTLS=yes` is the per-link case above: not a leak, but a likely reason some
names fail to resolve.

**Firefox.** Open `about:config` and read `network.trr.mode`: `0` or `5` is off,
`2` is DoH with fallback, `3` is DoH only. An enterprise policy wins over the pref;
`about:policies` shows it.

**Chrome / Chromium.** Open `chrome://policy` and look for `DnsOverHttpsMode`;
without a policy, the setting is under *Settings → Privacy and security → Security →
Use secure DNS*.

**NetworkManager.** List per-connection DNS overrides:

```bash
nmcli -f NAME,IP4.DNS,IP6.DNS connection show --active
```

**Docker.**

```bash
docker network ls                          # which networks exist
docker inspect -f '{{.HostConfig.NetworkMode}}' <container>
```

`host` is a host process; `bridge` or a user network is forwarded, and blocked;
`macvlan` or `ipvlan` is outside TTP.

**Is the redirect itself holding?** TTP keeps a counter on each rule that should
never fire while the NAT redirect works:

```bash
sudo nft list counters table inet ttp
```

A non-zero `dot_rejected`, `doh_rejected` or `dns_unredirected_rejected` means a
query reached the filter chain without being redirected. That is an alarm about
TTP, not about your applications, and the watchdog treats it as one.

---

## 4. What to do about it

- To keep lookups working, turn off application-level DoH (Firefox
  `network.trr.mode = 5`, Chrome *Use secure DNS* off) and let the system resolver
  go to Tor. Nothing is gained by DoH inside Tor except a second party that sees
  your queries.
- Remove per-link DNS servers and `DNSOverTLS` settings you do not need while a
  session is active, or accept that those names will not resolve.
- For containers that need the network under TTP, use `--network host`.

---

## Why there is no DNS auditor

It was proposed in
[#43](https://github.com/onyks-os/TransparentTorProxy/issues/43): a read-only
auditor that parses every source above and prints a verdict per finding.

It was not built because it would add visibility, not protection. The guarantee in
section 1 holds whether or not anyone audits these settings, and every case above is
already either contained or out of scope by design. The cost, on the other hand,
would be a parser per application (Firefox profiles, Chrome policies, NetworkManager,
Docker), each of which changes format on its own schedule and would need to be
maintained indefinitely. A page that states the outcomes and the manual checks
gives the same answer without that cost.
