# Quickstart Guide

This tutorial guides you through installing TTP and running your first transparent Tor proxy session.

---

## 1. System Requirements

Before starting, ensure your system meets these prerequisites:

* **Operating System**: Linux with `systemd`. Native packages are built and tested for Debian 13, Ubuntu 24.04, Fedora 44 and Arch Linux; elsewhere, install with `pipx`.
* **Runtime**: Python 3.10 or higher
* **Firewall Engine**: `nftables`
* **Privileges**: Root access (`sudo`)

---

## 2. Installation Options

Download the `.deb` or `.rpm` from the
[latest release](https://github.com/onyks-os/TransparentTorProxy/releases/latest),
then install it:

=== "Debian 13 / Ubuntu 24.04 (.deb)"

    ```bash
    sudo apt install ./transparent-tor-proxy_*_all.deb
    ```

=== "Fedora 44 (.rpm)"

    ```bash
    sudo dnf install ./transparent-tor-proxy-*.fc44.noarch.rpm
    ```

=== "Arch Linux (from the repository)"

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
3. Overlays `/etc/resolv.conf` to direct system DNS to Tor's DNSPort (`127.0.0.1:9054` by default).
4. Waits for Tor to bootstrap, then confirms through `check.torproject.org` that traffic actually exits through Tor.

Add `--watchdog` to also start the background integrity watchdog.

`start` exits `0` when the session is up and verified, `3` when the session is up and
fail-closed but Tor could not be verified (traffic is blocked, not leaking), and `1`
when there is no session. See the [exit codes](../reference/cli.md#4-cli-exit-codes).

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

`ttp check` confirms through `check.torproject.org` that traffic exits through Tor, and shows the exit IP, the TransPort and DNSPort in use, the IPv6 state and the latency.

---

## 5. Stopping the Session

To terminate the proxy session and restore default system networking:

```bash
sudo ttp stop
```

Stopping the session unmounts the DNS overlay, flushes the `inet ttp` `nftables` ruleset, stops the FSM watchdog, and terminates transient Tor services.
