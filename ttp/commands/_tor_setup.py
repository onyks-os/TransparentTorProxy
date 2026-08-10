# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tor setup and UID resolution helpers for TTP CLI start command."""

from __future__ import annotations

import grp
import pwd
from pathlib import Path
from typing import Any

import typer

from ttp import tor_install
from ttp.commands._common import (
    _PREFIX,
    console,
    logger,
)
from ttp.commands._common import (
    print_error as _print_error,
)
from ttp.commands._common import (
    validate_bridge_line as _validate_bridge_line,
)
from ttp.exceptions import TorError


def _parse_bypass_users_groups(
    bypass_user: list[str] | None,
    bypass_group: list[str] | None,
) -> tuple[list[str], list[str], list[int], list[int]]:
    """Parse, validate and resolve bypass users and groups to system UIDs/GIDs."""
    users: list[str] = []
    if bypass_user:
        for u in bypass_user:
            users.extend([item.strip() for item in u.split(",") if item.strip()])

    groups: list[str] = []
    if bypass_group:
        for g in bypass_group:
            groups.extend([item.strip() for item in g.split(",") if item.strip()])

    bypass_uids: list[int] = []
    for u in users:
        try:
            if u.isdigit():
                uid = int(u)
                pwd.getpwuid(uid)
            else:
                uid = pwd.getpwnam(u).pw_uid
            bypass_uids.append(uid)
        except KeyError:
            _print_error("Invalid User", f"User '{u}' does not exist on this system.")
            raise typer.Exit(code=1)

    bypass_gids: list[int] = []
    for g in groups:
        try:
            if g.isdigit():
                gid = int(g)
                grp.getgrgid(gid)
            else:
                gid = grp.getgrnam(g).gr_gid
            bypass_gids.append(gid)
        except KeyError:
            _print_error("Invalid Group", f"Group '{g}' does not exist on this system.")
            raise typer.Exit(code=1)

    return users, groups, bypass_uids, bypass_gids


def _parse_bridges(
    bridge_file: Path | None,
    bridge: list[str] | None,
    use_bridges: bool,
) -> tuple[list[str], bool]:
    """Parse, validate and collect Tor bridge lines from file and/or CLI flags."""
    bridge_lines: list[str] = []

    if bridge_file:
        if not bridge_file.exists():
            _print_error("Bridge File Missing", f"File '{bridge_file}' not found.")
            raise typer.Exit(code=1)
        try:
            for line in bridge_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        _validate_bridge_line(line)
                        bridge_lines.append(line)
                    except ValueError as exc:
                        _print_error(
                            "Invalid Bridge Line",
                            f"Line '{line}' in file '{bridge_file}': {exc}",
                        )
                        raise typer.Exit(code=1)
        except OSError as exc:
            _print_error("Failed to read bridge file", str(exc))
            raise typer.Exit(code=1)

    if bridge:
        for b in bridge:
            b = b.strip()
            if b:
                try:
                    _validate_bridge_line(b)
                    bridge_lines.append(b)
                except ValueError as exc:
                    _print_error("Invalid Bridge Line", f"Bridge '{b}': {exc}")
                    raise typer.Exit(code=1)

    if use_bridges and not bridge_lines:
        _print_error(
            "No Bridges Provided",
            "Bridges are enabled but no bridge lines or bridge files were specified.",
        )
        raise typer.Exit(code=1)

    if bridge_lines:
        use_bridges = True

    return bridge_lines, use_bridges


def _resolve_external_tor_uid(
    transport_port: int,
    tor_uid_override: str | None,
) -> str:
    """Resolve the UID of an externally managed Tor daemon (BYOD mode).

    Applies a 4-step resolution strategy:
    1. Manual override (--tor-uid flag)
    2. Socket auto-detection (/proc/net/tcp inspection)
    3. Known usernames fallback ('tor', 'debian-tor')
    4. Fatal error if unresolved
    """
    resolved_uid: int | None = None

    # Step 1 — Manual override
    if tor_uid_override:
        if tor_uid_override.isdigit():
            resolved_uid = int(tor_uid_override)
        else:
            try:
                resolved_uid = pwd.getpwnam(tor_uid_override).pw_uid
            except KeyError:
                _print_error(
                    "Invalid Tor User",
                    f"The specified Tor user '{tor_uid_override}' does not exist on this system.",
                )
                raise typer.Exit(code=1)

    # Step 2 — Socket auto-detection
    if resolved_uid is None:
        from ttp.commands import start as start_mod

        detected_uid = start_mod._get_uid_from_port(transport_port)
        if detected_uid is not None:
            try:
                username = pwd.getpwuid(detected_uid).pw_name
                if "tor" in username.lower() and detected_uid != 0:
                    resolved_uid = detected_uid
                    logger.info(
                        "Auto-detected Tor process owner UID via ports: %s (user: %s)",
                        resolved_uid,
                        username,
                    )
                else:
                    logger.warning(
                        "Auto-detected Tor UID %d belongs to user '%s' which does not contain 'tor'. Ignoring.",
                        detected_uid,
                        username,
                    )
            except KeyError:
                logger.warning(
                    "Auto-detected Tor UID %d is not registered in pwd database. Ignoring.",
                    detected_uid,
                )

    # Step 3 — Known usernames fallback
    if resolved_uid is None:
        for fallback_user in ("tor", "debian-tor"):
            try:
                resolved_uid = pwd.getpwnam(fallback_user).pw_uid
                logger.info(
                    "Fallback resolved Tor UID to user '%s' (UID: %d)",
                    fallback_user,
                    resolved_uid,
                )
                break
            except KeyError:
                continue

    # Step 4 — Fatal error
    if resolved_uid is None:
        _print_error(
            "Tor UID Resolution Failed",
            "Unable to determine Tor's UID. Specify the UID manually via --tor-uid.",
        )
        raise typer.Exit(code=1)

    return str(resolved_uid)


def setup_managed_tor(
    transport_port: int,
    dns_port: int,
    bridge_lines: list[str],
    use_bridges: bool,
    no_ipv6: bool,
) -> dict[str, Any]:
    """Detect Tor, verify readiness, and start the managed Tor service."""
    console.print(f"{_PREFIX} Detecting Tor...", end=" ")
    try:
        info = tor_install.ensure_tor_ready(
            transport_port=transport_port,
            dns_port=dns_port,
            use_bridges=use_bridges,
            bridges=bridge_lines,
            disable_ipv6=no_ipv6,
        )
    except TorError as exc:
        logger.error("Tor detection/install failed: %s", exc)
        console.print("[bold red]failed.[/]")
        _print_error("Tor Startup Failed", str(exc))
        raise typer.Exit(code=1)

    version = info.get("version", "")
    tor_user = info.get("tor_user", "debian-tor")
    console.print(
        f"found (v{version}), managed via system service (user: {tor_user})."
        if version
        else f"found, managed via system service (user: {tor_user})."
    )

    if info.get("firewalld"):
        console.print(f"{_PREFIX} [bold yellow]Warning: firewalld is active.[/bold yellow]")
        console.print(
            "  [yellow]firewalld can interfere with TTP's nftables rules and cause connectivity issues.[/yellow]"
        )
        console.print(
            "  [yellow]If Tor fails to bootstrap, consider stopping it: sudo systemctl stop firewalld[/yellow]\n"
        )

    return info
