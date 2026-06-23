# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Offensive IP Leak Verification Test.

Verifies that:
1. The exit IP is routing through Tor (IsTor=True).
2. The current public IP does not match the real unproxied public IP of the host/environment.
"""

from __future__ import annotations

import json
import os
import urllib.request
import pytest


@pytest.mark.leak
def test_ip_leak_prevention():
    """Verify that current external IP is anonymous and differs from pre-proxy real IP."""
    # Obtain the real unproxied public IP passed from environment variable
    real_ip = os.environ.get("REAL_PUBLIC_IP")
    if not real_ip:
        pytest.skip(
            "REAL_PUBLIC_IP environment variable not set. Skipping IP leak test."
        )

    # Request the current public IP info from Tor check API
    req = urllib.request.Request(
        "https://check.torproject.org/api/ip",
        headers={"User-Agent": "ttp-leak-test"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        pytest.fail(f"Failed to fetch public IP from check.torproject.org: {e}")

    current_ip = data.get("IP", "unknown")
    is_tor = data.get("IsTor", False)

    # Assertions to ensure Tor is active and IP has changed
    assert is_tor, (
        f"Traffic is not routing through Tor! (IsTor is False). Exit IP: {current_ip}"
    )
    assert current_ip != real_ip, (
        f"IP LEAK DETECTED! Current public IP matches the unproxied IP: {real_ip}"
    )


@pytest.mark.leak
def test_ipv6_leak_prevention():
    """Verify that current external IPv6 is anonymous and differs from pre-proxy real IPv6."""
    from ttp.tor_detect import is_ipv6_supported

    if not is_ipv6_supported():
        pytest.skip(
            "IPv6 loopback not supported by the environment. Skipping IPv6 IP leak test."
        )

    real_ipv6 = os.environ.get("REAL_PUBLIC_IPV6")
    if not real_ipv6:
        pytest.skip(
            "REAL_PUBLIC_IPV6 environment variable not set. Skipping IPv6 IP leak test."
        )

    req = urllib.request.Request(
        "https://ipv6.icanhazip.com",
        headers={"User-Agent": "ttp-leak-test"},
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            current_ipv6 = resp.read().decode().strip()
    except Exception as e:
        pytest.fail(f"Failed to fetch public IPv6 from ipv6.icanhazip.com: {e}")

    assert current_ipv6, (
        "Failed to retrieve current public IPv6 address (returned empty)."
    )
    assert current_ipv6 != real_ipv6, (
        f"IPv6 LEAK DETECTED! Current public IPv6 matches the unproxied IPv6: {real_ipv6}"
    )
