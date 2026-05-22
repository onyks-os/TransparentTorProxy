"""Offensive WebRTC/STUN Leak Verification Test.

Simulates WebRTC STUN network discovery by sending a raw UDP binding request
to a public STUN server. The test passes only if the query fails (times out or is refused),
proving that TTP's nftables firewall successfully drops outgoing non-Tor UDP traffic.
"""

from __future__ import annotations

import socket
import pytest


@pytest.mark.leak
def test_webrtc_stun_leak_prevention():
    """Verify that direct UDP STUN requests to public servers are blocked."""
    stun_host = "stun.l.google.com"
    stun_port = 19302

    # Resolve STUN host IP (this query is intercepted safely by Tor DNS)
    try:
        stun_ip = socket.gethostbyname(stun_host)
    except socket.gaierror as e:
        # If DNS resolution failed, let's skip or fail.
        # However, Tor DNSPort should successfully resolve it.
        pytest.fail(f"Failed to resolve STUN server hostname: {e}")

    # STUN binding request header (RFC 5389)
    # Type: 0x0001 (Binding Request)
    # Length: 0x0000 (No attributes)
    # Magic Cookie: 0x2112A442
    # Transaction ID: 12 random/zero bytes
    stun_packet = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + (b"\x00" * 12)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    try:
        # Attempt to send STUN request to resolved IP
        sock.sendto(stun_packet, (stun_ip, stun_port))
        
        # Try to receive a response
        data, _ = sock.recvfrom(512)
        
        # If we successfully received any packet back, it means UDP traffic
        # bypassed the firewall and leaked.
        pytest.fail(
            f"STUN LEAK DETECTED! Received STUN response from {stun_ip}:{stun_port}. "
            f"Traffic successfully bypassed the transparent proxy and nftables killswitch."
        )

    except socket.timeout:
        # Success: The packet was blocked and dropped by the firewall (no response)
        pass
    except OSError:
        # Success: The packet was rejected by the firewall (Connection Refused / ICMP Reject)
        pass
    finally:
        sock.close()
