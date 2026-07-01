# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""DNS Management Module - Handles routing DNS queries through Tor.

This module implements a stateless, Kernel-level DNS redirection strategy
using a `mount --bind` overlay on `/etc/resolv.conf`.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any
from ttp.exceptions import DNSError

logger = logging.getLogger("ttp")

RESOLV_CONF = Path("/etc/resolv.conf")
RUNTIME_RESOLV = Path("/run/ttp/resolv.conf")


def detect_active_interface() -> str:
    """Detect the primary network interface using 'ip route'."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True,
        )
        # Output example: "default via 192.168.1.1 dev eth0 proto dhcp..."
        parts = result.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except (subprocess.CalledProcessError, IndexError):
        pass
    return "eth0"  # Sane fallback if detection fails


def _is_ttp_mount(target: str) -> bool:
    """Check if the mount point at *target* is a TTP DNS overlay mount."""
    try:
        with open("/proc/self/mountinfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 5:
                    mount_point = parts[4]
                    if mount_point == target:
                        if "ttp" in line:
                            return True
    except Exception:
        pass
    return False


def _is_mount_point(target: str) -> bool:
    """Check if *target* is an active mount point by inspecting ``/proc/mounts``."""
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == target:
                    return True
    except OSError:
        pass
    return False


def _clear_stale_mounts(target: str) -> None:
    """Iteratively unmount TTP overlay mounts on *target*."""
    for i in range(10):
        if not _is_ttp_mount(target):
            return
        logger.debug("Removing stale TTP mount layer %d on %s", i + 1, target)
        subprocess.run(
            ["umount", "-l", target],
            capture_output=True,
            text=True,
            check=False,
        )

    if _is_ttp_mount(target):
        logger.warning(
            "Could not fully clear stale TTP mounts on %s after 10 attempts", target
        )


def apply_dns(
    interface: str, disable_ipv6: bool = False, dns_port: int = 9054
) -> dict[str, Any]:
    """Apply Tor DNS settings using a Kernel-level overlay (mount --bind).

    If systemd-resolved is active, also writes a volatile drop-in configuration
    and restarts it.

    Returns a dictionary containing backup data for restoration.
    """
    resolved_active = False
    resolved_config_file = Path("/run/systemd/resolved.conf.d/ttp.conf")
    try:
        from ttp.tor_detect import is_ipv6_supported

        # Check systemd-resolved active state
        try:
            res = subprocess.run(
                ["systemctl", "is-active", "systemd-resolved"],
                capture_output=True,
                text=True,
                check=False,
            )
            resolved_active = res.stdout.strip() == "active"
        except Exception:
            resolved_active = False

        if resolved_active:
            # Create volatile drop-in config
            dns_servers = f"127.0.0.1:{dns_port}"
            if is_ipv6_supported() and not disable_ipv6:
                dns_servers += f" [::1]:{dns_port}"

            config_content = (
                "[Resolve]\n"
                f"DNS={dns_servers}\n"
                "FallbackDNS=\n"
                "Domains=~.\n"
                "DNSOverTLS=no\n"
                "MulticastDNS=no\n"
                "LLMNR=no\n"
                "Cache=no-negative\n"
            )

            resolved_config_file.parent.mkdir(parents=True, exist_ok=True)
            resolved_config_file.write_text(config_content, encoding="utf-8")

            # Reload/restart resolved
            subprocess.run(
                ["systemctl", "reload-or-restart", "systemd-resolved"],
                capture_output=True,
                text=True,
                check=True,
            )

            # Flush system cache
            subprocess.run(
                ["resolvectl", "flush-caches"],
                capture_output=True,
                text=True,
                check=False,
            )

        nameservers = "nameserver 127.0.0.1\n"
        if is_ipv6_supported() and not disable_ipv6:
            nameservers += "nameserver ::1\n"

        # 1. Write the Tor resolver to /run/ttp/resolv.conf (volatile)
        RUNTIME_RESOLV.parent.mkdir(parents=True, exist_ok=True)
        RUNTIME_RESOLV.write_text(
            f"# Generated by TTP\n{nameservers}", encoding="utf-8"
        )

        # 2. Symlink check: resolve the real target for mount --bind
        target = RESOLV_CONF
        if os.path.islink(str(RESOLV_CONF)):
            target = Path(os.path.realpath(str(RESOLV_CONF)))

        # 3. Clear any stale mount stacks (idempotency guard)
        _clear_stale_mounts(str(target))

        # 4. Overlay via mount --bind (non-destructive)
        subprocess.run(
            ["mount", "--bind", str(RUNTIME_RESOLV), str(target)],
            capture_output=True,
            text=True,
            check=True,
        )

        return {
            "mode": "overlay",
            "mount_target": str(target),
            "systemd_resolved": resolved_active,
        }
    except Exception as e:
        # Clean up any systemd-resolved drop-in if we failed during overlay setup
        if resolved_active:
            try:
                if resolved_config_file.exists():
                    resolved_config_file.unlink()
                subprocess.run(
                    ["systemctl", "reload-or-restart", "systemd-resolved"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                subprocess.run(
                    ["resolvectl", "flush-caches"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except Exception:
                pass

        if isinstance(e, subprocess.CalledProcessError):
            raise DNSError(f"Command failed: {e.cmd} -> {e.stderr.strip()}") from e
        raise DNSError(f"Failed to apply DNS configuration: {e}") from e


def restore_dns(backup: dict[str, Any] | None) -> None:
    """Restore original system DNS settings by unmounting the overlay.

    If systemd-resolved was active on startup, also removes the volatile
    drop-in configuration and restarts it.
    """
    if not backup:
        return

    # 1. Unmount TTP DNS overlay first to restore the base /etc/resolv.conf file
    mount_target = backup.get("mount_target", str(RESOLV_CONF))

    if _is_ttp_mount(mount_target):
        try:
            # Lazy unmount ensures immediate release even if busy
            subprocess.run(
                ["umount", "-l", mount_target],
                capture_output=True,
                text=True,
                check=True,
            )
            logger.info("Successfully unmounted DNS overlay on %s", mount_target)
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else str(e)
            logger.warning(
                "Failed to unmount DNS overlay on %s: %s", mount_target, err_msg
            )
    else:
        logger.debug("DNS target %s is not mounted, skipping unmount", mount_target)

    # 2. Handle systemd-resolved teardown second (so it reads the restored base resolv.conf)
    if backup.get("systemd_resolved"):
        resolved_config_file = Path("/run/systemd/resolved.conf.d/ttp.conf")
        try:
            if resolved_config_file.exists():
                resolved_config_file.unlink()
        except OSError as e:
            logger.warning("Failed to remove systemd-resolved drop-in: %s", e)

        try:
            subprocess.run(
                ["systemctl", "reload-or-restart", "systemd-resolved"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Failed to reload/restart systemd-resolved during teardown: %s",
                e.stderr.strip() if e.stderr else str(e),
            )
        except Exception as e:
            logger.warning(
                "Failed to reload/restart systemd-resolved during teardown: %s", e
            )

        try:
            subprocess.run(
                ["resolvectl", "flush-caches"],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as e:
            logger.debug("Failed to flush systemd-resolved caches: %s", e)

    # 3. Cleanup the ephemeral file to free tmpfs space
    try:
        if RUNTIME_RESOLV.exists():
            RUNTIME_RESOLV.unlink()
    except OSError as e:
        logger.debug("Failed to remove runtime resolv.conf: %s", e)
