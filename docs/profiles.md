# TTP – Advanced Security & Usage Profiles

This document details the recommended security and usage profiles for Transparent Tor Proxy (TTP). Depending on your threat model, operational requirements, and target environment, you can configure TTP using one of the profiles below.

---

## 1. Daily Privacy Profile (Standard)
* **Goal**: Anonymize general browsing, bypass geographic restrictions, or hide ISP snooping with minimal overhead.
* **Command**:
  ```bash
  sudo ttp start
  ```
* **Why**: Runs without background active processes (no watchdog overhead), utilizing extremely efficient `nftables` redirect rules and local bypass for smooth home/work LAN printer/NAS sharing.

## 2. Administrative / Maintenance Profile
* **Goal**: Perform local updates (e.g., `apt update`, `dnf upgrade`) or maintenance that requires high bandwidth or direct native route while Tor is active, or speed up initial bootstrapping.
* **Command**:
  ```bash
  sudo ttp start --allow-root
  ```
* **Why**: Routes all default user/system processes through Tor, but exempts system root processes (`uid 0`) allowing them to communicate directly in cleartext for updates or troubleshooting. (Use with caution: increases risk of tool/script leaks if run under `sudo`).

---

## 3. Split Tunneling Profile
* **Goal**: Route all network traffic through Tor except for specific system users or groups (e.g. running a local media server, backups, or gaming in cleartext).
* **Command**:
  ```bash
  sudo ttp start --bypass-user debian-tor,mediauser --bypass-group sysadmin
  ```
* **Why**: Uses `nftables` exceptions to allow the matching local user IDs or group IDs to communicate directly to the cleartext internet, bypassing redirection and the watchdog killswitch.

---

## 4. Censorship Circumvention Profile (Tor Bridges)
* **Goal**: Connect to the Tor network in censored environments where standard Tor entry nodes are blocked.
* **Command**:
  ```bash
  sudo ttp start --use-bridges --bridge-file /path/to/my_bridges.txt
  # OR specify individual bridges directly:
  sudo ttp start --bridge "obfs4 192.0.2.1:1234 ..." --bridge "snowflake 192.0.2.2:4321 ..."
  ```
* **Why**: Configures Tor to connect via bridges. If pluggable transports like `obfs4proxy` or `snowflake-client` are needed, TTP automatically checks their presence and raises an error if they are missing.

---

## 5. Bring Your Own Daemon (BYOD) Profile
* **Goal**: Run TTP inside Docker containers or custom systemd configurations by separating Tor lifecycle management from network redirection routing.
* **Command**:
  ```bash
  # 1. Start Tor manually on target ports (e.g. TransPort 9041, DNSPort 9054)
  # 2. Start TTP delegating daemon control to the host
  sudo ttp start --external-daemon --transport-port 9041 --dns-port 9054
  ```
* **Why**: Bypasses systemd commands entirely, performing a passive healthcheck to verify that Tor is running on the target ports and dynamically parsing socket owners from `/proc/net/tcp` to obtain the UID of the Tor daemon process (avoiding loops). If the external Tor daemon crashes, routing continues to fail closed safely.
