# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Tor setup and UID resolution helpers for TTP CLI start command."""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
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
from ttp.paths import resolve

#: Largest bridge file read. A real one is a few lines; this bounds what a
#: caller can make root buffer.
_MAX_BRIDGE_FILE_BYTES = 1 << 20


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


def _invoking_identity() -> tuple[int, int, str] | None:
    """The unprivileged caller behind this root process, if there is one.

    sudo sets SUDO_UID/SUDO_GID and pkexec sets PKEXEC_UID; neither can be
    chosen by the caller under a default sudoers (env_reset). ``None`` means
    either not root, or root with no one behind it - a root shell, systemd - in
    which case there is no less-privileged identity to read files as.
    """
    if os.geteuid() != 0:
        return None
    raw_uid = os.environ.get("SUDO_UID") or os.environ.get("PKEXEC_UID")
    if raw_uid is None:
        return None
    if not raw_uid.isdigit():
        raise OSError("the invoking user's id is not a number; refusing to read files on its behalf")
    uid = int(raw_uid)
    if uid == 0:
        return None
    try:
        entry = pwd.getpwuid(uid)
        name, default_gid = entry.pw_name, entry.pw_gid
    except KeyError:
        name, default_gid = str(uid), uid
    raw_gid = os.environ.get("SUDO_GID") if os.environ.get("SUDO_UID") else None
    gid = int(raw_gid) if raw_gid and raw_gid.isdigit() else default_gid
    return uid, gid, name


def _read_as_invoking_user(path: Path) -> str:
    """Read *path* with the privileges of whoever invoked ttp through sudo/pkexec.

    `ttp start` runs as root, so opening a caller-supplied path directly let
    `sudo ttp` read files the caller could not - which matters wherever sudo is
    granted for ttp alone (GHSA-wc5v-93m5-3vc6). The read happens in a child
    running as the caller, with the caller's groups, so the kernel applies the
    caller's permissions, and root never opens the path at all.
    """
    identity = _invoking_identity()
    if identity is None:
        if not path.exists():
            raise FileNotFoundError(f"File '{path}' not found.")
        data = path.read_bytes()
    else:
        uid, gid, name = identity
        try:
            groups = os.getgrouplist(name, gid)
        except (KeyError, OSError):
            groups = [gid]
        proc = subprocess.run(
            [resolve("cat"), "--", str(path)],
            user=uid,
            group=gid,
            extra_groups=groups,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            # cat's own message: the path and the errno, never file content.
            reason = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["unreadable"]
            raise OSError(f"'{path}' cannot be read as {name}: {reason[0]}")
        data = proc.stdout
    if len(data) > _MAX_BRIDGE_FILE_BYTES:
        raise OSError(f"'{path}' is larger than {_MAX_BRIDGE_FILE_BYTES} bytes; not a bridge file")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise OSError(f"'{path}' is not UTF-8 text") from e


def _parse_bridges(
    bridge_file: Path | None,
    bridge: list[str] | None,
    use_bridges: bool,
) -> tuple[list[str], bool]:
    """Parse, validate and collect Tor bridge lines from file and/or CLI flags."""
    bridge_lines: list[str] = []

    if bridge_file:
        try:
            text = _read_as_invoking_user(bridge_file)
        except FileNotFoundError:
            _print_error("Bridge File Missing", f"File '{bridge_file}' not found.")
            raise typer.Exit(code=1)
        except OSError as exc:
            _print_error("Failed to read bridge file", str(exc))
            raise typer.Exit(code=1)
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                _validate_bridge_line(line)
            except ValueError:
                # The line number, never the line: its content is the caller's
                # file, and an error message must not become a way to print it.
                _print_error(
                    "Invalid Bridge Line",
                    f"Line {number} of '{bridge_file}' is not a valid bridge line. "
                    "Expected '<ip>:<port>' or '<transport> <ip>:<port>'.",
                )
                raise typer.Exit(code=1)
            bridge_lines.append(line)

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


# Exact names, never a substring test: "tor" is contained in many ordinary
# account names -- victor, actor, contractor, mentor, factory, history -- and
# the UID matched here receives a full cleartext exemption in both the NAT
# redirect chain and the fail-closed filter chain.
_KNOWN_TOR_USERNAMES = frozenset({"tor", "debian-tor", "toranon", "_tor"})


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
                if username.lower() in _KNOWN_TOR_USERNAMES and detected_uid != 0:
                    resolved_uid = detected_uid
                    logger.info(
                        "Auto-detected Tor process owner UID via ports: %s (user: %s)",
                        resolved_uid,
                        username,
                    )
                else:
                    logger.warning(
                        "Auto-detected Tor UID %d belongs to user '%s', which is not a known Tor "
                        "account name. Ignoring; pass --tor-uid to override explicitly.",
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
