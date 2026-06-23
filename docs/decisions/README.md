# Architectural Decision Records (ADRs)

This directory contains the Architectural Decision Records (ADRs) for the **TransparentTorProxy (TTP)** project. 

## Purpose

ADRs serve as a light-weight record of significant design and architectural choices made during the development of TTP. They document:
* **Context**: What was the problem and the environment at the time?
* **Decision**: What choice was made to address it?
* **Consequences**: What are the positive, negative, and neutral trade-offs of that choice?

## Structure of an ADR

Each ADR is formatted using the Markdown standard and named using a sequential ID:
* `0001-some-decision.md`
* `0002-another-decision.md`

## Index of Decisions

1. [0001-volatile-standard-core.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0001-volatile-standard-core.md) — Volatile standard core (`/run/ttp`) to prevent stale lock states.
2. [0002-stateless-dns-overlay.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0002-stateless-dns-overlay.md) — Stateless DNS overlay using `mount --bind` on `/etc/resolv.conf`.
3. [0003-watchdog-emergency-killswitch.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0003-watchdog-emergency-killswitch.md) — Background watchdog and emergency fail-closed killswitch.
4. [0004-split-tunneling-uid-gid.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0004-split-tunneling-uid-gid.md) — Split tunneling exceptions by UID/GID in `nftables`.
5. [0005-tor-bridge-support.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0005-tor-bridge-support.md) — Native bridge and pluggable transports support in generated `torrc`.
6. [0006-subprocess-orchestration.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0006-subprocess-orchestration.md) — Retaining `subprocess`-based network orchestration instead of a native Netlink implementation.
7. [0007-ruleset-testing-with-nse.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0007-ruleset-testing-with-nse.md) — Programmatic testing using Network Sandbox Engine (NSE) and Scapy sniffer.
8. [0008-byod-architecture.md](file:///home/onyks/Documents/GitHub/TransparentTorProxy/docs/decisions/0008-byod-architecture.md) — Support for systemd-less environments via Bring Your Own Daemon (BYOD).
