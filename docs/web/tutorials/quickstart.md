# Quickstart Guide

This tutorial guides you through installing TTP and running your first transparent Tor proxy session in under 5 minutes.

---

## 1. System Requirements

Before starting, ensure your system meets these prerequisites:

- **OS**: Linux with `systemd` (Debian 12+, Ubuntu 22.04+, Fedora 40+, Arch Linux)
- **Runtime**: Python 3.10+
- **Firewall Backend**: `nftables`
- **Privileges**: Root access (`sudo`)

---

## 2. Installation Options

=== "Debian / Ubuntu (.deb)"

    ```bash
    sudo apt install ./packaging/transparent-tor-proxy_0.4.7_all.deb
    ```

=== "Fedora / RHEL (.rpm)"

    ```bash
    sudo dnf install ./packaging/transparent-tor-proxy-0.4.7-1.fc43.noarch.rpm
    ```

=== "Arch Linux"

    ```bash
    cd packaging && makepkg -si
    ```

=== "Universal Script"

    ```bash
    git clone https://github.com/onyks-os/TransparentTorProxy.git
    cd TransparentTorProxy
    sudo ./scripts/install.sh
    ```

---

## 3. Starting Your First Session

Start the transparent proxy session:

```bash
sudo ttp start
```

TTP will automatically:
1. Detect or launch its dedicated systemd Tor service (`ttp-tor.service`).
2. Apply atomic `nftables` redirection rules (`inet ttp` table).
3. Overlay `/etc/resolv.conf` to route DNS queries to Tor DNSPort.
4. Wait for Tor bootstrap (0% to 100%).

---

## 4. Verifying Tor Routing

To confirm your connection is routed through Tor:

```bash
# Check session status
ttp status

# Run network verification probe
ttp check

# Check exit IP via curl
curl -s https://check.torproject.org/api/ip
```

---

## 5. Stopping the Session

To restore default system networking cleanly:

```bash
sudo ttp stop
```
