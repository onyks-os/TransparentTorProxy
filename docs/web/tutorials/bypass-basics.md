# Running Applications Outside Tor (Bypass Modes)

This tutorial demonstrates how to exclude specific system users, groups, local networks, or individual CLI processes from transparent Tor proxying using TTP.

---

## 1. Local Network Bypass (LAN Exclusion)

By default, `sudo ttp start` enables local subnet exclusion (RFC 1918 IPv4 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

To explicitly verify or enforce local network exclusion:

```bash
# Start TTP with explicit LAN bypass enabled
sudo ttp start --lan-bypass

# Test local router or LAN service access
ping -c 2 192.168.1.1
```

To route local RFC 1918 subnets through Tor as well, pass `--no-lan-bypass`:

```bash
sudo ttp start --no-lan-bypass
```

---

## 2. Executing Single Commands Outside Tor (`ttp bypass`)

To execute a specific command as an unproxied process without stopping the active TTP session, use `sudo ttp bypass`:

```bash
# Run a network request directly over standard ISP interface
sudo ttp bypass curl -s https://api.ipify.org

# Launch a local development server unproxied
sudo ttp bypass python3 -m http.server 8080
```

`sudo ttp bypass` executes the specified target command inside a transient `systemd` scope (`ttp-bypass.slice`), de-escalating privileges to the invoking user (`SUDO_UID` / `SUDO_GID`) while bypassing `nftables` redirection.

---

## 3. Persistent User and Group Exclusion

If a specific system service, daemon, or user account must permanently bypass transparent proxying:

```bash
# Exclude a specific system user by username
sudo ttp start --bypass-user devuser

# Exclude a system group
sudo ttp start --bypass-group bypass-users
```

Verify that the process running under the excluded user accesses the network directly:

```bash
sudo -u devuser curl -s https://api.ipify.org
```

---

## 4. Session Status Verification

Inspect active bypass rules and excluded entities:

```bash
ttp status
```

The output confirms active session parameters, including registered bypass UIDs, GIDs, and LAN exclusion state.
