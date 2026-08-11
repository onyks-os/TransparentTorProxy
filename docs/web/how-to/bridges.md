# How-To: Tor Bridges and Pluggable Transports

This guide provides instructions for configuring Pluggable Transports (`obfs4`, `snowflake`) in TTP when operating under restricted or censored networks.

---

## 1. Configuring Inline obfs4 Bridges

To use `obfs4` obfuscation bridges directly from the command line:

```bash
# Single obfs4 bridge line
sudo ttp start --bridge "obfs4 192.0.2.1:9344 74A91DF57D70E69D037D770D6C31D89F0A311494 cert=EXAMPLE fingerprint=EXAMPLE"

# Multiple obfs4 bridge lines
sudo ttp start \
  --bridge "obfs4 192.0.2.1:9344 74A91DF57D70E69D037D770D6C31D89F0A311494 cert=ABC..." \
  --bridge "obfs4 198.51.100.2:8443 A91DF57D70E69D037D770D6C31D89F0A311494 cert=XYZ..."
```

---

## 2. Configuring Snowflake Bridges

To use Snowflake domain fronting and WebRTC proxies:

```bash
sudo ttp start --bridge "snowflake 192.0.2.3:1 2B280F2E2C0D9D72E14631D08202F680D1D2C67F url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.voiparound.com:3478"
```

---

## 3. Managing a Dedicated Bridge File

Store multiple bridge lines in a plain text file (e.g., `/etc/ttp/bridges.txt`):

```text
# /etc/ttp/bridges.txt
obfs4 192.0.2.1:9344 74A91DF57D70E69D037D770D6C31D89F0A311494 cert=ABC...
obfs4 198.51.100.2:8443 A91DF57D70E69D037D770D6C31D89F0A311494 cert=XYZ...
snowflake 192.0.2.3:1 2B280F2E2C0D9D72E14631D08202F680D1D2C67F url=https://...
```

Start TTP with the `--bridge-file` parameter:

```bash
sudo ttp start --bridge-file /etc/ttp/bridges.txt
```

---

## 4. Handling Missing Transport Binaries

TTP enforces a strict no auto-install policy. If required pluggable transport binaries (`obfs4proxy` or `snowflake-client`) are missing when bridge options are specified, TTP halts preflight checks and outputs distribution-aware installation guidance:

=== "Debian / Ubuntu"

    ```bash
    sudo apt install obfs4proxy snowflake-client
    ```

=== "Fedora / RHEL"

    ```bash
    sudo dnf install obfs4proxy snowflake-client
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S obfs4proxy snowflake
    ```
