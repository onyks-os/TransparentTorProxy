# Transparent Tor Proxy (TTP)

TTP is a Linux system utility that transparently routes all TCP and DNS traffic through the Tor network using `nftables` kernel rules and a volatile runtime architecture.

[Quickstart Guide](tutorials/quickstart.md){ .md-button .md-button--primary }
[Architecture & FSM](explanation/architecture.md){ .md-button }
[GitHub Repository](https://github.com/onyks-os/TransparentTorProxy){ .md-button }

---

!!! warning "Security Notice"
    Transparent proxying routes system network connections through Tor, but it does not modify application-layer identifiers such as browser user-agents, HTTP headers, or TLS client hellos. For comprehensive privacy recommendations and threat modeling guidelines, refer to [Privacy Guides](https://www.privacyguides.org/).

---

## Core Technical Features

<div class="grid cards" markdown>

- **Volatile Runtime Architecture**

    ---

    All session state, runtime `torrc` files, locks, and log buffers are maintained strictly in `/run/ttp` (`tmpfs`). No configuration data or session traces are written to persistent storage.

- **Kernel-Level Network Interception**

    ---

    Traffic is intercepted globally via custom `inet ttp` `nftables` tables. Applications require no individual proxy configuration, environment variables, or wrapper scripts.

- **Stateless DNS Overlay**

    ---

    System DNS resolution is bound to Tor DNSPort (`127.0.0.1:5353`) via an isolated `mount --bind` overlay on `/etc/resolv.conf` and `systemd-resolved` runtime overrides.

- **FSM Watchdog and Self-Healing**

    ---

    A background Finite State Machine monitors `nftables` rule integrity and process health. If tampered with or interrupted, rules are automatically repaired or reset to a closed killswitch state.

- **Subnet and Process Exclusion**

    ---

    Supports RFC 1918 local area network exclusion (`--lan-bypass`) and process isolation by system user or group (`--bypass-user`, `--bypass-group`, `sudo ttp bypass`).

- **IPv6 Leak Prevention**

    ---

    Ensures zero IPv6 leaks through explicit dual-stack redirection rules or a hard outbound drop policy (`--no-ipv6`).

</div>

---

## Quick Usage

```bash
# Start transparent proxy session with default FSM watchdog
sudo ttp start

# Verify Tor circuit connectivity and public exit IP
ttp check

# Display live session state and active options
ttp status

# Terminate session and restore original network state
sudo ttp stop
```

---

## Documentation Structure

<div class="grid cards" markdown>

- **Tutorials**

    ---

    Step-by-step guides for installation, initial configuration, and verifying system proxying.

    [View Tutorials](tutorials/quickstart.md)

- **How-To Guides**

    ---

    Instructions for configuring Tor bridges, user bypass policies, and VM testing environments.

    [View How-To Guides](how-to/bridges.md)

- **Explanation**

    ---

    Deep dives into the `nftables` architecture, DNS mount mechanics, FSM state transitions, and security model.

    [View Architecture](explanation/architecture.md)

- **Reference**

    ---

    Command-line options, global flags, exit codes, system dependencies, and Python API details.

    [View CLI Reference](reference/cli.md)

</div>
