# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Managed Tor's synthetic destinations, reserved ahead of LAN exemptions.

The IPv6 range uses the currently unassigned L=0 half of ULA, leaving locally
assigned fd00::/8 LANs available. These are mappings, never routed networks.
Keep Tor configuration and packet enforcement on the same specification.
"""

VIRTUAL_IPV4 = "10.192.0.0/10"
VIRTUAL_IPV6 = "fc00::/8"
