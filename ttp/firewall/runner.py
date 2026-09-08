# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Stateless Firewall Module - Low-level nftables execution engine."""

import logging
import pwd
import subprocess

from ttp.exceptions import FirewallError
from ttp.firewall.builder import _build_ruleset, _has_cgroup_bypass_support
from ttp.state import LOCK_DIR

logger = logging.getLogger("ttp")

# Path to the temporary ruleset file for better debugging (line numbers)
RULES_TEMP_PATH = LOCK_DIR / "ttp.rules"

# Prepended to every full-table replacement. Keeping the create+flush in the same
# nft script as the ruleset makes the swap a single kernel transaction: nft -f
# either commits the whole thing or nothing. Issuing them as separate `nft`
# invocations leaves a window where the table exists but is empty - no redirect
# and no drop - during which traffic egresses in cleartext.
_TABLE_RESET_PREAMBLE = "add table inet ttp\nflush table inet ttp\n"


def _apply_table_atomically(ruleset: str) -> None:
    """Replace the entire ``inet ttp`` table in one atomic nft transaction.

    Args:
        ruleset: The complete ``table inet ttp { ... }`` definition to install.

    Raises:
        FirewallError: If the transaction fails; the previous table is left intact.
    """
    _run_nft_string(_TABLE_RESET_PREAMBLE + ruleset.strip() + "\n")


def _run_nft(args: list[str]) -> None:
    """Execute an nft CLI command synchronously.

    Args:
        args: Command arguments to append to ``nft`` (e.g. ``["add", "table", "inet", "ttp"]``).

    Raises:
        subprocess.CalledProcessError: If the ``nft`` command exits with non-zero status.
    """
    subprocess.run(
        ["nft", *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )


def _run_nft_string(ruleset: str) -> None:
    """Inject a complex ruleset string directly into nft via a volatile temporary file.

    Args:
        ruleset: The complete nftables ruleset definition string.

    Raises:
        FirewallError: If writing to state or running ``nft -f`` fails.
    """
    try:
        # Ensure the state directory exists
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        # Write to temporary file to get better error messages with line numbers
        RULES_TEMP_PATH.write_text(ruleset.strip() + "\n", encoding="utf-8")

        subprocess.run(
            ["nft", "-f", str(RULES_TEMP_PATH)],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        error_msg = str(e)
        if hasattr(e, "stderr") and e.stderr:
            error_msg = e.stderr.strip()
        raise FirewallError(error_msg)


def apply_rules(
    tor_user: str,
    transport_port: int = 9041,
    dns_port: int = 9054,
    allow_root: bool = False,
    lan_bypass: bool = True,
    bypass_uids: list[int] | None = None,
    bypass_gids: list[int] | None = None,
    disable_ipv6: bool = False,
) -> None:
    """Create the dedicated 'inet ttp' table and inject redirection rules.

    Create Table -> Flush Table -> Apply Ruleset is submitted to nft as a single
    transaction, so the table is never observable in a half-applied state.
    If any step fails, triggers an automatic rollback (table destruction).

    Args:
        tor_user: Username or numeric UID string of the Tor daemon process.
        transport_port: Local TCP port for Tor TransPort redirection.
        dns_port: Local UDP/TCP port for Tor DNSPort redirection.
        allow_root: If True, allows processes running as root (UID 0) to bypass rules.
        lan_bypass: If True, excludes local LAN subnets from redirection.
        bypass_uids: Optional list of numeric UIDs exempted from redirection.
        bypass_gids: Optional list of numeric GIDs exempted from redirection.
        disable_ipv6: If True, forces dropping all IPv6 traffic regardless of host availability.

    Raises:
        FirewallError: If the tor_user is invalid or rule injection fails.
    """
    # Resolve numeric UID for the tor user to avoid nft resolution issues
    try:
        tor_uid = int(tor_user) if tor_user.isdigit() else pwd.getpwnam(tor_user).pw_uid
    except KeyError as e:
        raise FirewallError(f"Tor user '{tor_user}' not found on system.") from e

    from ttp.tor_detect import is_ipv6_supported

    ipv6_avail = is_ipv6_supported() and not disable_ipv6

    # Resolve systemd-resolved UID once, before building the ruleset
    resolved_uid: int | None = None
    for _user in ("systemd-resolve", "systemd-resolved"):
        try:
            resolved_uid = pwd.getpwnam(_user).pw_uid
            break
        except KeyError:
            continue

    ruleset = _build_ruleset(
        tor_uid=tor_uid,
        transport_port=transport_port,
        dns_port=dns_port,
        ipv6_avail=ipv6_avail,
        allow_root=allow_root,
        lan_bypass=lan_bypass,
        bypass_uids=bypass_uids,
        bypass_gids=bypass_gids,
        resolved_uid=resolved_uid,
        cgroup_bypass=_has_cgroup_bypass_support(),
    )

    try:
        _apply_table_atomically(ruleset)
        logger.info(f"Stateless rules applied. Tor user ({tor_user}, UID {tor_uid}) is exempt.")
    except Exception as e:
        logger.error(f"Firewall injection failed: {e}. Rolling back...")
        destroy_rules()
        if not isinstance(e, FirewallError):
            raise FirewallError(f"Failed to apply stateless rules: {e}") from e
        raise


def destroy_rules() -> bool:
    """Destroy the 'ttp' table and clean up firewall rules.

    This is the atomic cleanup operation. It flushes the table, destroys it,
    and verifies that the table is no longer present in kernel state.

    Returns:
        bool: True if the table was successfully destroyed or already gone.

    Raises:
        FirewallError: If table destruction fails and the table remains active.
    """
    # Flush the table first for absolute cleanup safety
    subprocess.run(
        ["nft", "flush", "table", "inet", "ttp"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    result = subprocess.run(
        ["nft", "destroy", "table", "inet", "ttp"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    # returncode 1 with table absent = already clean, not an error
    # to distinguish it, check if the table exists
    if result.returncode != 0:
        # Check: does the table still exist?
        check = subprocess.run(
            ["nft", "list", "table", "inet", "ttp"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if check.returncode != 0:
            # The table is gone - destroy "failed" because it was already clean
            return True
        # The table still exists - destroy actually failed
        err_msg = result.stderr.decode().strip() if result.stderr else "unknown error"
        logger.error(f"nft destroy failed: {err_msg}")
        raise FirewallError(f"Failed to destroy nftables ruleset: {err_msg}")

    RULES_TEMP_PATH.unlink(missing_ok=True)
    return True
