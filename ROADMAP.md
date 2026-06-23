# TTP Development Roadmap — 2026-2027

This document outlines the strategic vision and release plan for **TransparentTorProxy (TTP)**. The roadmap focuses on improving privilege management, DNS interoperability, formal state verification, and advanced testing tools to ensure absolute leak prevention.

---

## Current Project Status

TTP has successfully consolidated the following major milestones:
* **v0.4.0**: Native IPv6 support, structured JSON logging, and link carrier detection in the watchdog.
* **v0.4.5**: UID/GID split tunneling, Tor bridges & Pluggable Transports (obfs4/snowflake), BYOD Mode, force-disable IPv6, zero-leak graceful teardown with conntrack flush, and advanced testing suites (NSE, Chaos Monkey).
* **v0.4.6**: Application exclusion (cgroups v2 bypass) via systemd transient scopes, privilege dropping (watchdog user `ttp-watchdog` with `CAP_NET_ADMIN`), and strict systemd requirements.

---

## Planned Enhancements & Release Schedule

The following sections detail our strategic objectives and feature releases for the upcoming development cycles, reorganized by functional areas.

### 1. Security Policies (Kernel & OS)

* **Linux Capabilities (Privilege Dropping)**
  * **Priority:** Maximum
  * **Target Release:** v0.4.6 (Completed)
  * **Technical Objective:** Eliminate the need for full-root execution of the Python daemon.
  * **Architectural Notes:** Run the background watchdog daemon under the dedicated `ttp-watchdog` system user, dropping all root privileges and retaining only CAP_NET_ADMIN capabilities.

* **systemd-resolved Bypass**
  * **Priority:** Maximum
  * **Target Release:** v0.4.7 (Q4 2026)
  * **Technical Objective:** Prevent collisions and overrides on the host system's DNS resolver.
  * **Architectural Notes:** Implement DNS routing interception via D-Bus or apply a hardcoded override configuration under `/etc/systemd/resolved.conf.d/`, replacing or complementing the current strategy based on the `mount --bind` overlay.

* **Application Exclusion via Linux cgroups v2 (Bypass)**
  * **Priority:** High
  * **Target Release:** v0.4.6 (Completed)
  * **Technical Objective:** Allow specific processes and their children to bypass the transparent proxy and connect directly to the cleartext internet.
  * **Architectural Notes:** Implement a `ttp bypass <command>` CLI runner that runs commands inside a systemd transient scope under `ttp-bypass.slice` (using `systemd-run`), dropping root privileges to the caller, and uses `nftables` wildcard `socket cgroupv2` rules to permit bypass.

* **Kernel-level Auditing (eBPF)**
  * **Priority:** Medium
  * **Target Release:** v0.6.0 (Q2 2027)
  * **Technical Objective:** Mathematically prove the absence of leaks at the operating system level.
  * **Architectural Notes:** Build `bpftrace` probes to monitor system calls (such as `tcp_v4_connect`) and categorically verify that no cleartext connections escape outside the Tor daemon.

---

### 2. New Python Libraries

* **`transitions`**
  * **Priority:** Maximum
  * **Target Release:** v0.4.7 (Q4 2026)
  * **Purpose:** Implement a formal Finite State Machine (FSM) for the Watchdog.
  * **Architectural Notes:** Replaces the current procedural logic based on `if/else` checks. This makes state transitions (and emergency killswitch activation) formally testable and 100% predictable.

* **`playwright`**
  * **Priority:** High
  * **Target Release:** v0.5.0 (Q1 2027)
  * **Purpose:** Layer 7 Application Leak Testing.
  * **Architectural Notes:** Strictly limited to the CI/CD verification pipeline. Automatically spawns real browsers behind TTP to test application-level leaks, including WebRTC STUN discovery, DNS fallback, and browser fingerprinting.

---

### 3. New Tools & Functional Expansions

* **Native Pluggable Transports**
  * **Priority:** High
  * **Target Release:** v0.4.5 (Completed)
  * **Implementation:** Native integration of `obfs4` and `snowflake` bridges.
  * **Architectural Notes:** Avoids external Python tools or intermediary daemons. Official binaries are installed via the OS package manager, with direct configuration injection into the ephemeral `torrc` file via the `ClientTransportPlugin` directive.

* **Network Sandbox Engine (NSE)**
  * **Priority:** High
  * **Target Release:** v0.4.5 (Completed)
  * **Implementation:** A framework for the isolated validation of `nftables` rulesets.
  * **Architectural Notes:** Features a Svelte frontend and a FastAPI backend. Developed as an independent repository and tool, invoked dynamically during the TTP CI/CD verification phase.

* **Chaos Monkey Script**
  * **Priority:** Medium
  * **Target Release:** v0.4.5 (Completed)
  * **Implementation:** Destructive stress testing of network infrastructure.
  * **Architectural Notes:** An internal script within the test suite that randomly terminates daemons, unmounts overlays, or disconnects virtual/physical interfaces during execution to validate the resilience and reaction time of the Killswitch.

---

### 4. Network Flexibility

* **VPN Compatibility (Chained Tunneling)**
  * **Priority:** High
  * **Target Release:** v0.4.7 (Q4 2026) — *Shifted from Q3 2026*
  * **Technical Objective:** Ensure interoperability with concurrent VPN tunnels.
  * **Architectural Notes:** Automatically detect routes and virtual interfaces (e.g. `tun+`, `wg+`) and generate dedicated `nftables` rules to properly support both *Tor-over-VPN* and *VPN-over-Tor* configurations.

---

### 5. User Experience & Monitoring

* **Desktop Notifications & DBus**
  * **Priority:** High
  * **Target Release:** v0.5.0 (Q1 2027) — *Shifted from Q4 2026*
  * **Technical Objective:** Proactively notify desktop users of critical session events.
  * **Architectural Notes:** Implement a lightweight DBus client to emit notifications for IP rotations, watchdog status changes, or emergency killswitch activations.

* **Bandwidth Monitor (`ttp monitor`)**
  * **Priority:** Medium
  * **Target Release:** v0.5.0 (Q1 2027) — *Shifted from Q4 2026*
  * **Technical Objective:** Provide real-time traffic statistics.
  * **Architectural Notes:** Develop an interactive terminal dashboard (TUI) via Rich or Textual to render download/upload speed and active circuit streams.

* **System Tray Applet GUI**
  * **Priority:** Low
  * **Target Release:** v0.5.0 (Q1 2027) — *Shifted from Q4 2026*
  * **Technical Objective:** Lightweight desktop integration.
  * **Architectural Notes:** A system tray indicator (Gnome Extension or KDE applet) to show connection status, current exit IP country, and latency.

---

### 6. Total Isolation

* **TTP Sandbox (`ttp run <app>`)**
  * **Priority:** High
  * **Target Release:** v0.6.0 (Q2 2027) — *Shifted from Q1 2027*
  * **Technical Objective:** Contain individual applications within isolated network namespaces.
  * **Architectural Notes:** Spawn transient network namespaces connected to the host's Tor instance via `veth` virtual interface pairs, bypassing global system routing changes.

* **Zero System Leaks**
  * **Priority:** High
  * **Target Release:** v0.6.0 (Q2 2027) — *Shifted from Q1 2027*
  * **Technical Objective:** Limit Tor protection exclusively to sandboxed apps.
  * **Architectural Notes:** The host OS remains entirely unproxied on clearnet while only selected applications run in namespaces routed through Tor, completely eliminating system-wide cleartext leak risks.

---

### 7. Future Refactoring: Netlink & pyroute2 Migration

* **Netlink / `pyroute2` Integration**
  * **Target Release:** v0.6.0+ (Frozen in Backlog)
  * **Current Status (v0.4.5):** Network orchestration (namespaces, virtual ethernet pairs, and routing) is managed via `subprocess` calls invoking the `iproute2` and `nftables` host binaries. This current design will be maintained as the overhead (< 50ms) is negligible for the user experience, keeping external dependencies to a minimum.
  * **Migration Trigger Conditions:** Replacing `subprocess` with `pyroute2` will only be evaluated if:
    1. **Active Monitoring:** TTP transitions from a static CLI tool to a stateful daemon that listens in real time to kernel events (e.g., unplugged LAN cable, physical interface IP changes) by subscribing to Netlink sockets.
    2. **Strict Performance Constraints:** Future profiling tests (via `cProfile`) demonstrate that `subprocess` executions account for >20% of the total boot time (excluding Tor bootstrapping).
  * **Expected Impact:**
    * **Pros:** Instantaneous L2/L3 execution, elimination of text-based shell output parsing, and native Python-level handling of Netlink exceptions.
    * **Cons:** Steep learning curve for contributors, heavy external dependency (`pyroute2`), and a massive refactoring of `netns_controller.py` (part of the Network Sandbox Engine).
  * **Tactical Conclusion:** Frozen in backlog.

---

### 8. Cloud-Native & Container Orchestration (Docker / Kubernetes)

* **TTP as a Sidecar Container for Microservices**
  * **Priority:** Low (Long-Term Vision)
  * **Target Release:** Post-v0.6.0 (v1.0.0+)
  * **Technical Objective:** Transform TTP from a host-based desktop tool into a privacy-preserving network primitive for cloud infrastructures and IoT devices.
  * **Architectural Notes:** Package TTP as a minimal, hardened container image (e.g., Alpine Linux). Implement the **Sidecar Pattern** by injecting the TTP container into a Kubernetes Pod or Docker Compose stack alongside a target application. Utilizing TTP's Bring Your Own Daemon (BYOD) architecture, TTP will apply its atomic `nftables` rulesets strictly within the isolated Network Namespace (`netns`) of the Pod. This allows microservices or IoT telemetry stacks to be transparently routed through Tor at Layer 3, without requiring per-application SOCKS5 configuration and without modifying the physical host's global routing.

---

## Contributing to the Roadmap

Are you an engineer with expertise in **Linux kernel networking**, **SELinux**, or **eBPF**?
Help us deliver this roadmap! Check out our [Contributing Guidelines](CONTRIBUTING.md) or join the discussions on [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues).
