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

    Session state, the generated `torrc`, the lock and the log live only in `tmpfs` (`/run/ttp`, `/run/tor/ttp`), and the session ends with the machine. The only things on disk are Tor's guard and consensus cache (`/var/lib/tor/ttp`) and a few markers in `/var/lib/ttp`.

- **Kernel-Level Network Interception**

    ---

    Traffic is intercepted globally via custom `inet ttp` `nftables` tables. Applications require no individual proxy configuration, environment variables, or wrapper scripts.

- **Stateless DNS Overlay**

    ---

    System DNS resolution is bound to Tor's DNSPort (`127.0.0.1:9054` by default) via a `mount --bind` overlay on `/etc/resolv.conf` and a volatile `systemd-resolved` drop-in, backed by a kernel-level drop on resolved's non-loopback traffic.

- **FSM Watchdog and Killswitch**

    ---

    With `--watchdog`, a background daemon driven by a finite state machine is woken by nftables and inotify events and compares the live table, rule for rule, with the one the session applied. A failed Tor is restarted; a changed table or DNS overlay engages an emergency killswitch, held until `ttp stop`.

- **Subnet and Process Exclusion**

    ---

    Local networks (RFC 1918 and link-local) stay reachable by default (`--no-lan-bypass` routes them through Tor too), and users, groups or single commands can be exempted (`--bypass-user`, `--bypass-group`, `sudo ttp bypass`).

- **IPv6 Leak Prevention**

    ---

    Ensures zero IPv6 leaks through explicit dual-stack redirection rules or a hard outbound drop policy (`--no-ipv6`).

</div>

---

## Quick Usage

```bash
# Start a session, with the integrity watchdog
sudo ttp start --watchdog

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
