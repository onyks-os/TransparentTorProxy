# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Stateless Firewall Module - Emergency lockdown, killswitch, and socket slaughter mechanisms."""

import logging
import subprocess

from ttp.exceptions import FirewallError
from ttp.firewall.runner import _apply_table_atomically, _run_nft

logger = logging.getLogger("ttp")

# nft's wording when the target table or chain is simply not there. That is the
# expected, benign case for the teardown helpers below - the session was already
# stopped. Anything else is a real failure of a leak-prevention step and must be
# visible, not swallowed at debug level.
_MISSING_OBJECT_MARKERS = (
    "no such file or directory",
    "does not exist",
    "could not process rule",
)


def _log_teardown_failure(action: str, exc: Exception) -> None:
    """Log a teardown step failure, distinguishing 'already gone' from a real fault.

    A missing table or chain means the session was already torn down and is logged
    at debug level. Every other failure means a leak-prevention rule did not make it
    into the kernel, and is logged at warning level so it is not lost.

    Args:
        action: Human-readable name of the teardown step that failed.
        exc: The exception raised by the nft invocation.
    """
    stderr = ""
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""

    if any(marker in stderr.lower() for marker in _MISSING_OBJECT_MARKERS):
        logger.debug("%s skipped (table/chain does not exist): %s", action, exc)
    else:
        logger.warning(
            "%s FAILED: %s. Outbound traffic may not be locked down during teardown.",
            action,
            exc,
        )


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
        _log_teardown_failure("Teardown lockdown", e)


def apply_active_socket_slaughter() -> None:
    """Inject temporary reject rules at the top of the filter_out chain.

    Actively terminates pending local connections by sending immediate ICMP Port Unreachable
    for UDP sockets and TCP RST packets for open TCP streams.
    """
    try:
        # 1. Kill pending UDP connections (sends ICMP Port Unreachable to the local process)
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
        # 2. Kill pending TCP connections instantly (sends RST to the local process)
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
        _log_teardown_failure("Active socket slaughter", e)


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
        # Table reset and drop-all ruleset go in as one transaction. Flushing in a
        # separate nft call would briefly leave the table empty, which is an open
        # network at the exact moment integrity has already been lost.
        _apply_table_atomically(ruleset)
        logger.warning("Emergency killswitch applied: network traffic isolated.")
    except Exception as e:
        logger.error(f"Failed to apply emergency killswitch: {e}")
        if not isinstance(e, FirewallError):
            raise FirewallError(f"Failed to apply emergency killswitch: {e}") from e
        raise
