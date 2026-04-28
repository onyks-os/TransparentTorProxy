#!/bin/bash
# ══════════════════════════════════════════════════════════════════════
# TTP — Universal Uninstaller
# ══════════════════════════════════════════════════════════════════════
#
# This script completely removes TTP from the system, reversing
# everything that install.sh did. It is safe to run even if TTP
# is currently active — it will stop the session first.
#
# Removal steps:
#   1. Stop any active TTP session (restores firewall and DNS).
#   2. Remove the SELinux policy module if it was installed.
#   3. Delete all files: /opt/ttp, /usr/local/bin/ttp, /var/lib/ttp.
#
# Usage:
#   sudo ./uninstall.sh
# ══════════════════════════════════════════════════════════════════════

# Ensure the script is run as root.
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (use: sudo ./uninstall.sh)"
  exit 1
fi

echo "[TTP] Starting system-wide removal..."

# 1. Stop any active sessions
# It's critical to stop the proxy before removing the files, as the 'stop' command
# is needed to restore the firewall and DNS settings.
if [ -f /usr/local/bin/ttp ]; then
    echo "[TTP] Stopping active session..."
    /usr/local/bin/ttp stop 2>/dev/null
fi

# 2. SELinux Cleanup
# If the SELinux module was installed, we should remove it to keep the kernel clean.
if command -v semodule >/dev/null 2>&1; then
    if semodule -l | grep -q "ttp_tor_policy"; then
        echo "[TTP] Removing SELinux module 'ttp_tor_policy'..."
        semodule -r ttp_tor_policy
    fi
fi

# 3. File Removal
# Delete the binaries, assets, and state files.
echo "[TTP] Removing application files..."
rm -f /usr/local/bin/ttp
rm -rf /opt/ttp
rm -rf /var/lib/ttp  # This directory contains lock files and firewall backups.

echo "[TTP] Uninstallation complete. The system has been restored."