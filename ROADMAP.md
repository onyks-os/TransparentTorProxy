# TTP Development Roadmap — 2026

This document outlines the strategic vision and release plan for **TransparentTorProxy (TTP)** for the current year. The roadmap focuses on improving network flexibility, desktop user experience, and introducing advanced isolation mechanisms to eliminate any risk of traffic leaks.

---

## Current Project Status

The project has recently consolidated major security and usability milestones:
* **v0.4.0**: Released transparent IPv6 routing (via nftables), integration of physical link carrier checks in the Watchdog, and structured JSON logging.
* **v0.4.5 (In Progress)**: Successfully completed **UID/GID Split Tunneling** and **Tor Bridges & Pluggable Transports** support (obfs4, Snowflake, Meek).

---

## Planned Releases (2026)

The following table summarizes the planned features for upcoming TTP releases in 2026, excluding those that have already been integrated and verified.

| Version    | Planned Release | Focus Area                    | Feature / Changes                     | Description & Details                                                                                                                                        | Status           |
| :--------- | :-------------- | :---------------------------- | :------------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------- |
| **v0.4.5** | Q3 2026         | **Network Flexibility**       | **VPN Compatibility (Tunneling)**     | Automatic detection and support for mixed configurations (*Tor-over-VPN* or *VPN-over-Tor*) by intercepting tunnel interfaces (`tun0`, `wg0`).               | *Planned (Next)* |
| **v0.5.0** | Q4 2026         | **User Experience & Monitor** | **Desktop Notifications & DBus**      | Send system notifications to the user for IP rotations via `ttp refresh`, status changes, or emergency killswitch activation.                                | *Planned*        |
|            |                 |                               | **Bandwidth Monitor (`ttp monitor`)** | Interactive CLI command with a dynamic terminal dashboard (via Rich or Textual) to display real-time speed (U/D) and traffic events from the Tor socket.     | *Planned*        |
|            |                 |                               | **System Tray Applet GUI**            | Lightweight graphical applet (e.g., Gnome Extension / KDE Applet) to view activation status, current exit IP country, and circuit latency.                   | *Planned*        |
| **v0.6.0** | Q1 2027         | **Total Isolation**           | **TTP Sandbox (`ttp run <app>`)**     | Spawn individual processes in isolated **Network Namespaces** in the Linux kernel, connected via `veth` virtual interface pairs strictly to Tor's TransPort. | *Planned*        |
|            |                 |                               | **Zero System Leaks**                 | Maximum isolation level: the host OS remains clear and only sandboxed applications route through Tor, eliminating global leak risks.                         | *Planned*        |

---

## Future Releases Detail

### TTP v0.4.5 — Network Flexibility (Q3 2026)
*The goal is to ensure maximum interoperability with other network tunnels running on the system.*

* **VPN Compatibility (Chained Tunneling)**:
  * **Problem**: Currently, running TTP concurrently with a VPN (e.g., OpenVPN, WireGuard) can create routing conflicts or cause cleartext leaks.
  * **Solution**: Implement dynamic detection of VPN routes and virtual interfaces (e.g., `tun+`, `wg+`). Generate dedicated `nftables` rules to properly encapsulate traffic for both *Tor-over-VPN* (Tor connection routes inside the VPN tunnel) and *VPN-over-Tor* (the VPN is established over the Tor proxy) scenarios.

---

### TTP v0.5.0 — Graphical Interface & UX (Q4 2026)
*Making TTP friendlier and more interactive for desktop users.*

* **Desktop Notifications & DBus**:
  * Integrate a lightweight DBus client in Python to notify users of critical Watchdog events (e.g., killswitch activation) or to confirm successful IP rotations.
* **Bandwidth Monitor (`ttp monitor`)**:
  * Create an interactive terminal user interface (TUI) dashboard to visualize real-time download/upload graphs and active circuits extracted from Tor's control port.
* **System Tray Applet**:
  * Develop a system tray applet for Gnome/KDE to enable toggling TTP with a single click and monitoring the current protected exit IP.

---

### TTP v0.6.0 — Total Isolation (Q1 2027)
*Achieving the ultimate level of security and isolation using Linux kernel-level namespaces.*

* **TTP Sandbox (`ttp run <app>`)**:
  * Instead of modifying the host's global firewall rules, TTP will spawn a transient Network Namespace.
  * Within the namespace, a virtual `veth` interface pair will connect the sandboxed environment directly to the host's local Tor instance.
* **Zero System Leaks**:
  * This approach isolates a single application (e.g., `ttp run firefox`) without altering the host network, guaranteeing no background system services accidentally leak cleartext traffic.

---

## Contributing to the Roadmap

Are you a Senior Developer with expertise in **Linux Networking**, **SELinux**, or **GUI/TUI in Python**?
Help us deliver this roadmap! Check out our [Contributing Guidelines](CONTRIBUTING.md) or join the discussions on [GitHub Issues](https://github.com/onyks-os/TransparentTorProxy/issues).
