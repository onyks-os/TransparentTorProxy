# How-To: Tor Bridges & Pluggable Transports

When operating in censored networks where direct connections to Tor relays are blocked, TTP allows configuring **Pluggable Transports** (`obfs4`, `meek_lite`, `snowflake`).

---

## 1. Using Bridges via CLI Flags

Pass bridge lines directly to `ttp start`:

```bash
sudo ttp start --bridge "obfs4 192.0.2.1:9344 1234567890ABCDEF..."
```

Multiple bridge flags can be specified:

```bash
sudo ttp start \
  --bridge "obfs4 192.0.2.1:9344 12345..." \
  --bridge "obfs4 192.0.2.2:9344 67890..."
```

---

## 2. Using a Bridge File

Store your bridge lines in a file (e.g. `bridges.txt`):

```text
obfs4 192.0.2.1:9344 1234567890ABCDEF...
snowflake 192.0.2.3:80 9876543210ABCDEF...
```

Then start TTP with `--bridge-file`:

```bash
sudo ttp start --bridge-file /etc/ttp/bridges.txt
```

---

## 3. Dependency Check Policy

TTP enforces a **Strict No Auto-Install Policy**. If required Pluggable Transport binaries (`obfs4proxy`, `snowflake-client`) are missing when bridge flags are used, TTP displays distro-aware package installation guidance:

```text
Missing Dependency: Pluggable transport helper binary 'obfs4proxy' (required for 'obfs4') is missing.

Recommended installation command:
  sudo apt install obfs4proxy
```
