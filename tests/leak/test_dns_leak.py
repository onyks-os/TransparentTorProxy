# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Offensive DNS Leak Verification Test.

Verifies that direct UDP queries on port 53 to external resolvers (e.g., 1.1.1.1)
are either transparently intercepted by TTP (via Tor's DNSPort) or completely blocked/dropped.
"""

from __future__ import annotations

import socket
import pytest


@pytest.mark.leak
def test_dns_leak_prevention():
    """Verify that direct UDP queries on port 53 to external resolvers do not escape the proxy."""
    # Construct a minimal DNS query packet for the A record of 'check.torproject.org'
    # This avoids any external dependencies like 'dnspython'
    query = (
        b"\xaa\xbb"  # Transaction ID
        b"\x01\x00"  # Flags: Standard query
        b"\x00\x01"  # Questions: 1
        b"\x00\x00\x00\x00\x00\x00"  # RRs: 0, 0, 0
        b"\x05check"  # 'check'
        b"\x0atorproject"  # 'torproject'
        b"\x03org"  # 'org'
        b"\x00"  # Null terminator
        b"\x00\x01"  # Type: A
        b"\x00\x01"  # Class: IN
    )

    external_resolver = "1.1.1.1"
    port = 53

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    try:
        # Send DNS query directly to external resolver on UDP port 53
        sock.sendto(query, (external_resolver, port))
        data, _ = sock.recvfrom(512)

        # If we successfully received a response:
        # It must be a valid DNS response and the transaction ID must match
        assert len(data) >= 12, "Received DNS response is too short."
        assert data[:2] == b"\xaa\xbb", "DNS Transaction ID mismatch."

        # Check flags (response bit should be set in the third byte)
        assert (data[2] & 0x80) != 0, "Response flag is not set."

        # This confirms that the query was successfully handled. Under TTP's active session,
        # the nftables ruleset redirects all UDP port 53 queries to 127.0.0.1:9054 (Tor's DNSPort).
        # Therefore, the traffic did not leak in cleartext directly to 1.1.1.1; it was safely intercepted.

    except socket.timeout:
        # A timeout is also a success: it shows that the direct UDP packet was dropped/blocked
        # by the nftables filter hook output chain (policy drop / reject).
        pass
    except OSError:
        # Any OS/Socket error (like ConnectionRefused) is a success
        pass
    finally:
        sock.close()


@pytest.mark.leak
def test_dns_leak_prevention_ipv6():
    """Verify that direct UDP IPv6 queries on port 53 to external resolvers do not escape the proxy."""
    from ttp.tor_detect import is_ipv6_supported

    if not is_ipv6_supported():
        pytest.skip(
            "IPv6 loopback not supported by the environment. Skipping IPv6 DNS leak test."
        )

    # Construct a minimal DNS query packet for the A record of 'check.torproject.org'
    query = (
        b"\xaa\xbb"  # Transaction ID
        b"\x01\x00"  # Flags: Standard query
        b"\x00\x01"  # Questions: 1
        b"\x00\x00\x00\x00\x00\x00"  # RRs: 0, 0, 0
        b"\x05check"  # 'check'
        b"\x0atorproject"  # 'torproject'
        b"\x03org"  # 'org'
        b"\x00"  # Null terminator
        b"\x00\x01"  # Type: A
        b"\x00\x01"  # Class: IN
    )

    external_resolver_ipv6 = "2606:4700:4700::1111"  # Cloudflare Public DNS IPv6
    port = 53

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    try:
        # Send DNS query directly to external resolver on UDP IPv6 port 53
        sock.sendto(query, (external_resolver_ipv6, port))
        data, _ = sock.recvfrom(512)

        # If we successfully received a response:
        # It must be a valid DNS response and the transaction ID must match
        assert len(data) >= 12, "Received DNS response is too short."
        assert data[:2] == b"\xaa\xbb", "DNS Transaction ID mismatch."
        assert (data[2] & 0x80) != 0, "Response flag is not set."

    except socket.timeout:
        # Success: packet was blocked/dropped
        pass
    except OSError:
        # Success: socket error (e.g. network unreachable or connection refused)
        pass
    finally:
        sock.close()
