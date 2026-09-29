# How-To: Coexisting with Custom Firewalls (UFW / firewalld)

This guide explains how TTP isolates its `nftables` ruleset to operate alongside active host firewalls such as UFW, `firewalld`, or custom `nftables` / `iptables-nft` configurations.

---

## 1. How TTP's table relates to yours

TTP keeps all of its rules in one table, `inet ttp`, and never touches another
table. It adds four base chains:

| Chain | Hook | Priority | Job |
| :--- | :--- | :--- | :--- |
| `prerouting` | nat prerouting | `dstnat` (-100) | Redirect DNS and TCP arriving from other interfaces |
| `output` | nat output | -150 | Redirect local DNS and TCP to Tor |
| `filter_out` | filter output | `filter` (0) | The kill-switch: reject everything not redirected or exempt |
| `filter_forward` | filter forward | `filter` (0) | Drop all forwarded traffic |

Separate tables do **not** mean separate traffic. Every base chain registered at a
hook sees every packet at that hook, whichever table it belongs to, in priority
order. Two consequences matter:

- **A drop anywhere wins; an accept is only final inside its own chain.** Your
  firewall accepting a packet does not stop TTP's `filter_out` from rejecting it,
  and TTP's rules cannot make your firewall accept something it drops. Containment
  therefore holds with another firewall loaded.
- **The first NAT chain to bind a connection decides its destination.** A foreign
  NAT chain at a higher priority than TTP's (lower number) can redirect a
  connection before TTP sees it. For DNS, TTP rejects any query whose original
  destination was port 53 and that is not headed for Tor's DNSPort, so a foreign
  DNAT to a LAN resolver is blocked rather than leaked.

Both are tested, not assumed: the zero-leak suite runs TTP's real ruleset alongside
Docker-, ufw-, firewalld- (a captured firewalld 2.4.4 ruleset) and WireGuard-
(`wg-quick`, captured) shaped rulesets, and with a foreign DNAT chain. See
[How the zero-leak claim is verified](../explanation/verification.md).

---

## 2. Coexisting with UFW (Uncomplicated Firewall)

If UFW is active on your host system:

1. You do not need to disable UFW before starting TTP.
2. Start TTP normally:

```bash
sudo ttp start
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
3. firewalld's reloads (`firewall-cmd --reload`) rebuild firewalld's own table. If anything does remove or alter TTP's table, the watchdog (when started with `--watchdog`) does not repair it: it engages the emergency killswitch and holds it until `sudo ttp stop`. Without the watchdog, nothing notices.

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
