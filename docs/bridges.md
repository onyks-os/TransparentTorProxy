# Tor Bridges & Pluggable Transports Guide

This guide explains how TTP uses Tor Bridges and Pluggable Transports to bypass censorship, how to obtain bridge lines, and how to configure them easily.

---

## 1. What are Tor Bridges?

**Bridges** are private Tor relays that are not listed in the public directory. Because there is no public list of bridges, censors cannot easily block all of them.

When regular Tor connection fails (e.g., in countries like China, Iran, Russia, or on restricted corporate/school networks), you can use bridges to connect. TTP supports three types of bridges:

1. **Vanilla (Standard) Bridges**: Regular Tor entry guards on non-standard ports.
2. **obfs4 (Obfuscated) Bridges**: Transports that make Tor traffic look like random noise, preventing deep packet inspection (DPI) from detecting the Tor protocol.
3. **Snowflake Bridges**: Transports that route your traffic through temporary WebRTC proxies run by volunteers in their web browsers. Extremely resilient because proxy IP addresses change constantly.

---

## 2. How to Obtain Bridges

You can get bridge lines directly from the Tor Project:

* **Web**: Visit [bridges.torproject.org](https://bridges.torproject.org/) and follow the instructions to solve a captcha and get bridge lines.
* **Email**: Send an email to [bridges@torproject.org](mailto:bridges@torproject.org) from a **Gmail** or **Riseup** address with the body `get bridges` (or `get transport obfs4` / `get transport snowflake`).
* **Built-in Snowflake**: Snowflake bridges can often be used with a generic configuration since they dynamically connect to brokers. A typical Snowflake bridge line looks like:
  ```text
  snowflake 192.0.2.3:1 2B280B23111094B5E21A4B02A7E30B6780EB7167 connmux=1
  ```

---

## 3. Configuration in TTP

TTP allows you to configure bridges in two ways: passing them directly in the command line or loading them from a text file.

### Option A: Direct CLI Option (`--bridge`)
You can pass one or more individual bridge lines directly to the start/restart command.

```bash
# Start TTP with a single obfs4 bridge
sudo ttp start --bridge "obfs4 192.0.2.1:1234 2B280B23111094B5E21A4B02A7E30B6780EB7167 cert=certstring iat-mode=0"

# Start TTP with multiple bridges (repeat the flag)
sudo ttp start \
  --bridge "obfs4 192.0.2.1:1234 2B280B23111094B5E21A4B02A7E30B6780EB7167 cert=certstring iat-mode=0" \
  --bridge "snowflake 192.0.2.3:1 2B280B23111094B5E21A4B02A7E30B6780EB7167 connmux=1"
```

### Option B: Using a Bridges File (`--bridge-file`)
If you have a list of bridges, save them to a plain text file (one bridge line per line, blank lines and lines starting with `#` are ignored) and specify the path:

```bash
# Start TTP using a list of bridges from a file
sudo ttp start --use-bridges --bridge-file /home/user/my_bridges.txt
```

---

## 4. Under the Hood: Pluggable Transports Auto-Installation

If a bridge requires a **Pluggable Transport** helper binary (such as `obfs4proxy` or `snowflake-client`), TTP handles the dependencies automatically:

1. **Detection**: TTP parses the bridge lines and identifies the required transports.
2. **Path Verification**: It checks if the helper binary is available in the system `$PATH`.
3. **Auto-Installation**: If a binary is missing, TTP automatically invokes the system's package manager to install it:
   * **Debian/Ubuntu**: `apt-get install -y obfs4proxy` or `snowflake-client`
   * **Fedora/RHEL**: `dnf install -y obfs4` or `snowflake-client`
   * **Arch Linux**: `pacman -Sy --noconfirm obfs4proxy` or `snowflake-client`
   * **openSUSE**: `zypper install -y obfs4proxy` or `snowflake-client`
4. **Configuration**: TTP generates the volatile `torrc` and registers the transport plugins:
   ```text
   UseBridges 1
   ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
   ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
   Bridge obfs4 192.0.2.1:1234 ...
   ```

---

## 5. Verifying Bridge Operation

To ensure that your connection is successfully utilizing the configured bridges:

1. **Check Status**:
   ```bash
   ttp status
   ```
   Verify that the session is active and check the exit IP.
2. **Review TTP Logs**:
   ```bash
   sudo ttp logs
   ```
   Look for notices confirming bridge usage or connection to pluggable transport helper processes:
   * `[notice] Delaying directory fetches: Learning about the system's connections`
   * `[notice] Bridge 'obfs4' at ... is up and running.`
   * `[notice] Connection to bridge ... established.`
