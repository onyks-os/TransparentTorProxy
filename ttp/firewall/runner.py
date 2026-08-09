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


def _run_nft(args: list[str]) -> None:
    """Helper to run nft commands."""
    subprocess.run(
        ["nft"] + args,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )


def _run_nft_string(ruleset: str) -> None:
    """Inject a complex ruleset string directly into nft via a temporary file."""
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
    """Create the 'ttp' table and inject redirection rules.

    Orchestrates the process: Create -> Flush -> Inject.
    If any step fails, it triggers an automatic rollback (destruction).
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
        # 1. Create and sanitize the dedicated table
        _run_nft(["add", "table", "inet", "ttp"])
        _run_nft(["flush", "table", "inet", "ttp"])
        _run_nft_string(ruleset)
        logger.info(
            f"Stateless rules applied. Tor user ({tor_user}, UID {tor_uid}) is exempt."
        )
    except Exception as e:
        logger.error(f"Firewall injection failed: {e}. Rolling back...")
        destroy_rules()
        if not isinstance(e, FirewallError):
            raise FirewallError(f"Failed to apply stateless rules: {e}") from e
        raise


def destroy_rules() -> bool:
    """Destroy the 'ttp' table and clean up firewall rules.

    This is the atomic cleanup operation. It attempts to destroy the table
    and verifies success.

    Returns:
        bool: True if the table was successfully destroyed or already gone, False otherwise.
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
