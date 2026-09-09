# Quickstart Guide

This tutorial guides you through installing TTP and running your first transparent Tor proxy session.

---

## 1. System Requirements

Before starting, ensure your system meets these prerequisites:

* **Operating System**: Linux with `systemd` (Debian 12+, Ubuntu 22.04+, Fedora 40+, Arch Linux)
* **Runtime**: Python 3.10 or higher
* **Firewall Engine**: `nftables`
* **Privileges**: Root access (`sudo`)

---

## 2. Installation Options

=== "Debian / Ubuntu (.deb)"

    ```bash
    sudo apt install ./packaging/transparent-tor-proxy_*_all.deb
    ```

=== "Fedora / RHEL (.rpm)"

    ```bash
    sudo dnf install ./packaging/transparent-tor-proxy-*.noarch.rpm
    ```

=== "Arch Linux"

    ```bash
    cd packaging && makepkg -si
    ```

=== "Source Repository"

    ```bash
    git clone https://github.com/onyks-os/TransparentTorProxy.git
    cd TransparentTorProxy
    sudo ./scripts/install.sh
    ```

---

## 3. Starting Your First Session

Start the transparent proxy session with default settings:

```bash
sudo ttp start
```

Upon execution, TTP performs the following automated steps:

1. Launches or verifies the dedicated Tor daemon (`ttp-tor.service`).
2. Applies atomic kernel redirection rules within the `inet ttp` `nftables` table.
3. Overlays `/etc/resolv.conf` to direct system DNS to Tor DNSPort (`127.0.0.1:5353`).
4. Monitors Tor circuit bootstrap progress until 100%.
5. Initializes the background FSM integrity watchdog.

!!! note "Community & Contributions"
    If you find TTP valuable for your workflow, consider starring the [TransparentTorProxy repository on GitHub](https://github.com/onyks-os/TransparentTorProxy). Contributions in the form of issue reports, pull requests, and forks are welcome to help improve system security and compatibility.

---

## 4. Verifying Tor Routing

Confirm that all system traffic and DNS resolutions are routed through Tor:

```bash
# Display live session state and configuration options
ttp status

# Run automated network leak tests and circuit verification
ttp check

# Verify public exit IP address
curl -s https://check.torproject.org/api/ip
```

Expected output for `ttp check` includes verification of the Tor SOCKS port, DNS resolution via DNSPort, and circuit reachability.

---

## 5. Stopping the Session

To terminate the proxy session and restore default system networking:

```bash
sudo ttp stop
```

Stopping the session unmounts the DNS overlay, flushes the `inet ttp` `nftables` ruleset, stops the FSM watchdog, and terminates transient Tor services.
