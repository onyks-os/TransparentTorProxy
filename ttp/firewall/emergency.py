# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Stateless Firewall Module - Emergency lockdown, killswitch, and socket slaughter mechanisms."""

import logging

from ttp.exceptions import FirewallError
from ttp.firewall.runner import _run_nft, _run_nft_string

logger = logging.getLogger("ttp")


def apply_teardown_lockdown(tor_uid: int | None = None) -> None:
    """Insert a lockdown drop rule at the top of the filter_out chain in table inet ttp.

    Ensures all non-loopback outbound traffic is dropped during graceful session teardown,
    while permitting the Tor daemon UID to close control connections cleanly.

    Args:
        tor_uid: Optional numeric UID of the Tor daemon process to exempt from lockdown.
    """
    rule = ["insert", "rule", "inet", "ttp", "filter_out"]
    if tor_uid is not None:
        rule += ["meta", "skuid", "!=", str(tor_uid)]
    rule += ["oifname", "!=", "lo", "drop"]

    try:
        _run_nft(rule)
        logger.warning("Teardown lockdown applied: outbound traffic locked.")
    except Exception as e:
        # Gracefully handle cases where the table or chain does not exist (e.g., already stopped)
        logger.debug("Could not apply teardown lockdown (table/chain may not exist): %s", e)


def apply_active_socket_slaughter() -> None:
    """Inject temporary reject rules at the top of the filter_out chain.

    Actively terminates pending local connections by sending immediate ICMP Port Unreachable
    for UDP sockets and TCP RST packets for open TCP streams.
    """
    try:
        # 1. Uccide le connessioni UDP pendenti (invia ICMP Port Unreachable al processo locale)
        _run_nft(
            [
                "insert",
                "rule",
                "inet",
                "ttp",
                "filter_out",
                "meta",
                "l4proto",
                "udp",
                "counter",
                "reject",
            ]
        )
        # 2. Uccide le connessioni TCP pendenti istantaneamente (invia RST al processo locale)
        _run_nft(
            [
                "insert",
                "rule",
                "inet",
                "ttp",
                "filter_out",
                "meta",
                "l4proto",
                "tcp",
                "counter",
                "reject",
                "with",
                "tcp",
                "reset",
            ]
        )
        logger.warning("Active socket slaughter rules applied: resetting pending connections.")
    except Exception as e:
        # Gracefully handle cases where the table or chain does not exist (e.g., already stopped)
        logger.debug("Could not apply active socket slaughter: %s", e)


def apply_emergency_killswitch() -> None:
    """Apply an emergency network killswitch.

    Replaces the 'inet ttp' table with an ultra-restrictive ruleset that drops
    all inbound, outbound, and forwarded network traffic on physical interfaces,
    permitting only local loopback communication.

    Raises:
        FirewallError: If table creation or killswitch ruleset injection fails.
    """
    ruleset = """
    table inet ttp {
        chain filter_out {
            type filter hook output priority filter; policy drop;
            oifname "lo" accept
        }
        chain filter_forward {
            type filter hook forward priority filter; policy drop;
        }
        chain filter_input {
            type filter hook input priority filter; policy drop;
            iifname "lo" accept
        }
    }
    """
    try:
        # 1. Create and sanitize the dedicated table
        _run_nft(["add", "table", "inet", "ttp"])
        _run_nft(["flush", "table", "inet", "ttp"])

        # 2. Total isolation: drop everything except loopback
        _run_nft_string(ruleset)
        logger.warning("Emergency killswitch applied: network traffic isolated.")
    except Exception as e:
        logger.error(f"Failed to apply emergency killswitch: {e}")
        if not isinstance(e, FirewallError):
            raise FirewallError(f"Failed to apply emergency killswitch: {e}") from e
        raise
