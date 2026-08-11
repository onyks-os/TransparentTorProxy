# Configuring Dual-Stack & Drop Policies

This tutorial explains how TTP manages IPv6 traffic and guides you through selecting between dual-stack redirection and forced IPv6 drop policies.

---

## 1. Default Dual-Stack IPv6 Redirection

By default, TTP intercepts both IPv4 and IPv6 traffic. Outbound TCP connections over IPv6 are redirected to Tor TransPort via dual-stack `nftables` rules in the `inet ttp` table:

```bash
# Start TTP with default dual-stack redirection
sudo ttp start
```

In dual-stack mode:
* IPv4 TCP traffic is redirected to Tor `127.0.0.1:9040`.
* IPv6 TCP traffic is redirected to Tor `[::1]:9040`.
* DNS queries over IPv4 and IPv6 are bound to Tor DNSPort.

---

## 2. Enforcing Outbound IPv6 Drop Policy (`--no-ipv6`)

If your network interface or local router has partial, unstable, or misconfigured IPv6 support, pass `--no-ipv6` to force a strict drop policy on all outbound IPv6 traffic:

```bash
# Start TTP enforcing zero IPv6 outbound traffic
sudo ttp start --no-ipv6
```

When `--no-ipv6` is active, TTP inserts an `output` hook in `nftables` that explicitly drops all IPv6 packets (`ip6 nexthdr != { icmpv6 } drop`), preventing any unproxied IPv6 leaks.

---

## 3. Verifying IPv6 Leak Prevention

To verify that IPv6 traffic is properly handled or blocked:

```bash
# Run automated TTP connectivity checks
ttp check

# Attempt IPv6 ping (should fail or time out under --no-ipv6)
ping -c 2 -6 2001:4860:4860::8888 || echo "IPv6 outbound blocked."

# Verify public exit IP address via IPv6 endpoint
curl -6 -s https://api64.ipify.org || echo "IPv6 direct access disabled."
```

If `--no-ipv6` is enabled, direct IPv6 connections will fail cleanly while all system networking continues safely over IPv4 Tor circuits.
