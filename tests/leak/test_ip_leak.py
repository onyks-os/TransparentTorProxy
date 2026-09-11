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
import time
import urllib.request

import pytest

# The production verifier, `ttp.tor_control.verify_tor`, makes five attempts
# across several endpoints with a three-second backoff. These tests used to make
# a single request to a single endpoint, which left them strictly less resilient
# than the code they exist to verify: one TLS handshake dropped by an exit node
# failed the build where the product itself would have retried and succeeded.
# That is exactly what happened on 2026-09-11 - `SSL: UNEXPECTED_EOF_WHILE_READING`
# on `check.torproject.org`, on a commit whose identical tree had passed the same
# job eleven minutes earlier.
#
# The retry budget below deliberately mirrors verify_tor's. The endpoint list does
# not: a leak test must not ask the code under test whether the code under test
# works.
_ATTEMPTS = 5
_BACKOFF_SECONDS = 3


def _fetch(url: str, timeout: int) -> bytes:
    """Fetch ``url``, retrying transient transport failures.

    Re-raises the last exception if every attempt fails. A caller must read that
    as *no verdict*, never as evidence of a leak: an endpoint we cannot reach is
    just as consistent with TTP holding the network fail-closed, which is the
    outcome these tests exist to confirm.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "ttp-leak-test"})
    last_error: Exception | None = None

    for attempt in range(_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return bytes(resp.read())
        except Exception as exc:
            last_error = exc
            if attempt < _ATTEMPTS - 1:
                time.sleep(_BACKOFF_SECONDS)

    assert last_error is not None
    raise last_error


@pytest.mark.leak
def test_ip_leak_prevention():
    """Verify that current external IP is anonymous and differs from pre-proxy real IP."""
    # Obtain the real unproxied public IP passed from environment variable
    real_ip = os.environ.get("REAL_PUBLIC_IP")
    if not real_ip:
        pytest.skip("REAL_PUBLIC_IP environment variable not set. Skipping IP leak test.")

    # Request the current public IP info from Tor check API
    try:
        data = json.loads(_fetch("https://check.torproject.org/api/ip", timeout=10).decode())
    except Exception as e:
        pytest.fail(
            f"Could not reach check.torproject.org after {_ATTEMPTS} attempts: {e}. "
            "This is a transport failure, not a leak verdict: the test could not "
            "determine whether traffic is anonymised."
        )

    current_ip = data.get("IP", "unknown")
    is_tor = data.get("IsTor", False)

    # Assertions to ensure Tor is active and IP has changed
    assert is_tor, f"Traffic is not routing through Tor! (IsTor is False). Exit IP: {current_ip}"
    assert current_ip != real_ip, f"IP LEAK DETECTED! Current public IP matches the unproxied IP: {real_ip}"


@pytest.mark.leak
def test_ipv6_leak_prevention():
    """Verify that current external IPv6 is anonymous and differs from pre-proxy real IPv6."""
    from ttp.tor_detect import is_ipv6_supported

    if not is_ipv6_supported():
        pytest.skip("IPv6 loopback not supported by the environment. Skipping IPv6 IP leak test.")

    real_ipv6 = os.environ.get("REAL_PUBLIC_IPV6")
    if not real_ipv6:
        pytest.skip("REAL_PUBLIC_IPV6 environment variable not set. Skipping IPv6 IP leak test.")

    try:
        current_ipv6 = _fetch("https://ipv6.icanhazip.com", timeout=15).decode().strip()
    except Exception as e:
        pytest.fail(
            f"Could not reach ipv6.icanhazip.com after {_ATTEMPTS} attempts: {e}. "
            "This is a transport failure, not a leak verdict: the test could not "
            "determine whether IPv6 traffic is anonymised."
        )

    assert current_ipv6, "Failed to retrieve current public IPv6 address (returned empty)."
    assert current_ipv6 != real_ipv6, f"IPv6 LEAK DETECTED! Current public IPv6 matches the unproxied IPv6: {real_ipv6}"
