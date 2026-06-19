#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Chaos Monkey Watchdog Stress Testing Script.

Simulates randomized system failure injections (Tor daemon crash, DNS unmount,
firewall rules flush, and network link flapping) and asserts that the TTP
watchdog auto-heals the system or applies the emergency killswitch, preventing
any cleartext network leaks.
"""

from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import time
import urllib.request

# Ensure we are running as root
if os.geteuid() != 0:
    print("[ERROR] Chaos Monkey must be run as root (sudo).", file=sys.stderr)
    sys.exit(1)

TEST_USER = "ttp-chaos-test"


def get_real_public_ip() -> str | None:
    """Detect host's real unproxied public IP before starting TTP."""
    try:
        req = urllib.request.Request(
            "https://api.ipify.org", headers={"User-Agent": "ttp-chaos-monkey"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            ip = resp.read().decode().strip()
            print(f"[INFO] Real public IP detected: {ip}")
            return ip
    except Exception as e:
        print(f"[WARNING] Could not detect real public IP: {e}")
        return None


def setup_test_user():
    """Create a clean temporary unprivileged user for traffic validation."""
    cleanup_test_user()
    print(f"[INFO] Creating temporary test user: {TEST_USER}")
    subprocess.run(["useradd", "-m", TEST_USER], check=True, capture_output=True)


def cleanup_test_user():
    """Delete the temporary test user and their home directory."""
    print(f"[INFO] Cleaning up test user: {TEST_USER}")
    subprocess.run(["userdel", "-r", TEST_USER], capture_output=True)


def get_active_interface() -> str | None:
    """Determine the active default gateway network interface."""
    try:
        res = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    return None


def run_connectivity_audit(real_ip: str | None) -> bool:
    """Verifies that no cleartext leak escapes to the WAN.

    Returns True if traffic is successfully blocked/torified,
    False if a cleartext leak is detected (i.e. we connect to WAN and see real_ip).
    """
    # Test command running under the unprivileged test user
    cmd = [
        "python3",
        "-c",
        "import urllib.request; "
        "req = urllib.request.Request('https://api.ipify.org', headers={'User-Agent': 'ttp-chaos-audit'}); "
        "print(urllib.request.urlopen(req, timeout=3).read().decode().strip())",
    ]

    try:
        # Run under the unprivileged test user to hit standard firewall chains
        res = subprocess.run(cmd, capture_output=True, text=True, user=TEST_USER)
        if res.returncode == 0:
            current_ip = res.stdout.strip()
            print(f"[AUDIT] Connectivity check succeeded. External IP: {current_ip}")
            if real_ip and current_ip == real_ip:
                print(
                    "[ALERT] CRITICAL NET LEAK DETECTED! Traffic bypassed Tor and reached WAN in cleartext!"
                )
                return False
            else:
                print("[AUDIT] Traffic is successfully proxied through Tor.")
                return True
        else:
            # If the request fails (e.g. timeout or rejected), that is safe (killswitch works)
            print(
                f"[AUDIT] Connectivity blocked/rejected (Expected during recovery or killswitch): {res.stderr.strip() or 'Timeout'}"
            )
            return True
    except Exception as e:
        print(f"[AUDIT] Audit connection failed: {e}")
        return True


def inject_kill_tor():
    print("[CHAOS] Injecting Failure: Terminating Tor process...")
    # Stop ttp-tor systemd service to trigger Tor failure
    subprocess.run(["systemctl", "stop", "ttp-tor"], check=True)


def inject_flush_firewall():
    print("[CHAOS] Injecting Failure: Flushing nftables 'inet ttp' ruleset...")
    subprocess.run(["nft", "flush", "table", "inet", "ttp"], check=True)


def inject_destroy_firewall():
    print("[CHAOS] Injecting Failure: Destroying nftables 'inet ttp' table entirely...")
    subprocess.run(["nft", "delete", "table", "inet", "ttp"], check=False)
    subprocess.run(["nft", "destroy", "table", "inet", "ttp"], check=False)


def inject_unmount_dns():
    print("[CHAOS] Injecting Failure: Unmounting /etc/resolv.conf overlay...")
    subprocess.run(["umount", "-l", "/etc/resolv.conf"], check=False)


def inject_link_flap(interface: str):
    print(
        f"[CHAOS] Injecting Failure: Flapping default routing interface '{interface}'..."
    )
    # Shuts down interface for 2 seconds then brings it back up to avoid permanent disconnection
    subprocess.run(["ip", "link", "set", interface, "down"], check=True)
    time.sleep(2)
    subprocess.run(["ip", "link", "set", interface, "up"], check=True)


def main():
    parser = argparse.ArgumentParser(description="Chaos Monkey Watchdog stress test")
    parser.add_argument(
        "--duration", type=int, default=60, help="Total execution duration in seconds"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=12,
        help="Time between failure injections in seconds",
    )
    args = parser.parse_args()

    real_ip = get_real_public_ip()
    interface = get_active_interface()
    if not interface:
        print("[ERROR] No active network interface found.", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] Active network interface: {interface}")

    setup_test_user()

    # 1. Start TTP
    print("[INFO] Bootstrapping TTP with watchdog...")
    res = subprocess.run(
        ["ttp", "start", "--watchdog", "--bootstrap-timeout", "300"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"[ERROR] Failed to start TTP: {res.stderr}", file=sys.stderr)
        cleanup_test_user()
        sys.exit(1)

    print("[INFO] TTP started successfully. Chaos Monkey loop starting...")
    start_time = time.time()
    last_injection = time.time()
    failures_injected = 0
    leaks_found = 0

    try:
        while time.time() - start_time < args.duration:
            # Perform a randomized injection at set intervals
            if time.time() - last_injection >= args.interval:
                failure_type = random.choice(
                    [
                        "kill_tor",
                        "flush_firewall",
                        "destroy_firewall",
                        "unmount_dns",
                        "link_flap",
                    ]
                )

                if failure_type == "kill_tor":
                    inject_kill_tor()
                elif failure_type == "flush_firewall":
                    inject_flush_firewall()
                elif failure_type == "destroy_firewall":
                    inject_destroy_firewall()
                elif failure_type == "unmount_dns":
                    inject_unmount_dns()
                elif failure_type == "link_flap":
                    inject_link_flap(interface)

                failures_injected += 1
                last_injection = time.time()

                # Sleep briefly to let the watchdog detect and react (15s watch interval + buffer)
                check_wait = 18
                print(f"[INFO] Waiting {check_wait} seconds for watchdog response...")
                time.sleep(check_wait)

                # Run network leak audits
                if not run_connectivity_audit(real_ip):
                    leaks_found += 1
                    break

            # Passive audit sleep
            time.sleep(1)

    except KeyboardInterrupt:
        print("[INFO] Stress test interrupted by user.")

    finally:
        print("[INFO] Cleaning up TTP session and environment...")
        subprocess.run(["ttp", "stop"], capture_output=True)
        cleanup_test_user()

    print("\n" + "=" * 50)
    print("Chaos Monkey Stress Test Summary:")
    print(f"  Failures Injected: {failures_injected}")
    print(f"  Leaks Detected:    {leaks_found}")
    print("=" * 50)

    if leaks_found > 0:
        print("[FAIL] Watchdog failed to prevent cleartext network leaks.")
        sys.exit(1)
    else:
        print("[PASS] Watchdog successfully protected the environment with zero leaks.")
        sys.exit(0)


if __name__ == "__main__":
    main()
