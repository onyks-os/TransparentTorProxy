# How-To: Coexisting with Custom Firewalls (UFW / firewalld)

This guide explains how TTP isolates its `nftables` ruleset to operate alongside active host firewalls such as UFW, `firewalld`, or custom `nftables` / `iptables-nft` configurations.

---

## 1. TTP Table Isolation Architecture

TTP constructs all redirection rules inside a dedicated, isolated `nftables` table named `inet ttp`:

```text
table inet ttp {
    chain prerouting {
        type filter hook prerouting priority dstnat; policy accept;
        ...
    }
    chain output {
        type route hook output priority mangle; policy accept;
        ...
    }
}
```

Because `inet ttp` operates as an independent namespace with distinct netfilter hook priorities (`dstnat` and `mangle`), TTP does not flush, modify, or overwrite pre-existing firewall tables (such as `ip filter`, `inet firewalld`, or `ip ufw`).

---

## 2. Coexisting with UFW (Uncomplicated Firewall)

If UFW is active on your host system:

1. You do not need to disable UFW before starting TTP.
2. Start TTP normally:

```bash
sudo ttp start --lan-bypass
```

1. To inspect both UFW rules and TTP redirection rules simultaneously:

```bash
# View UFW status
sudo ufw status

# View active TTP nftables redirection table
sudo nft list table inet ttp
```

When TTP stops (`sudo ttp stop`), only the `inet ttp` table is flushed and removed. UFW rules remain intact and active.

---

## 3. Coexisting with firewalld (Fedora / RHEL)

On systems running `firewalld`:

1. `firewalld` manages its own `nftables` tables (`inet firewalld`).
2. TTP attaches its hooks alongside `firewalld`.
3. If `firewalld` reloads (`sudo firewall-cmd --reload`), the FSM Watchdog automatically detects any potential netfilter chain resets and repairs the `inet ttp` table within seconds.

Verify coexistence using `sudo ttp status`:

```bash
sudo ttp status
```

---

## 4. Manual Rule Inspection

To inspect the raw netfilter ruleset and verify table separation:

```bash
# List all active nftables tables on the host
sudo nft list tables

# Inspect only TTP redirection chains
sudo nft list table inet ttp
```
