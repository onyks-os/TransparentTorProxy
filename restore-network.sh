#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# TTP — Emergency Network Restore
# ══════════════════════════════════════════════════════════════════════
#
# This script is a safety net. Use it ONLY when `sudo ttp stop`
# doesn't work (e.g., the Python venv is broken, the binary was
# deleted, or the system is in a deeply corrupted state).
#
# What it does:
#   1. Flushes the ENTIRE nftables ruleset (not just the TTP table).
#   2. Reverts all DNS interfaces via resolvectl.
#   3. Resets /etc/resolv.conf to a sane default (Cloudflare 1.1.1.1).
#   4. Deletes the TTP lock file so the next `ttp start` works cleanly.
#
# WARNING: Step 1 is destructive — it removes ALL firewall rules,
# not just TTP's. If you have custom nftables rules from other
# software, they will be lost. In most desktop setups this is fine.
#
# Usage:
#   sudo ./restore-network.sh
# ══════════════════════════════════════════════════════════════════════

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (use: sudo ./restore-network.sh)"
  exit 1
fi

echo "[TTP-Emergency] Starting network recovery..."

# 1. Firewall Cleanup
# We brutally flush the entire nftables ruleset to ensure no 'drop' or 
# 'redirect' rules are left active.
if command -v nft >/dev/null 2>&1; then
    nft flush ruleset
    echo "[TTP-Emergency] nftables ruleset flushed."
fi

# 2. DNS Recovery (systemd-resolved)
# We attempt to revert every interface detected by the system to its 
# original DNS settings (usually DHCP).
if command -v resolvectl >/dev/null 2>&1; then
    for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
        resolvectl revert "$iface" >/dev/null 2>&1
    done
    resolvectl flush-caches
    echo "[TTP-Emergency] systemd-resolved interfaces reverted."
fi

# 3. DNS Recovery (resolv.conf)
# If resolv.conf is a real file (not a symlink), we reset it to a sane 
# default (Cloudflare) to guarantee connectivity.
if [ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "[TTP-Emergency] /etc/resolv.conf reset to 1.1.1.1."
fi

# 4. State Cleanup
# Remove the lock file so that a subsequent 'ttp start' doesn't 
# think a session is still active.
rm -f /var/lib/ttp/ttp.lock

echo "[TTP-Emergency] Recovery complete. Your network should be back to normal."
