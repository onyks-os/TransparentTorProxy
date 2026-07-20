from __future__ import annotations

import grp
import pwd
from pathlib import Path
from typing import Optional

import typer

from ttp import dns, firewall, state, tor_install
from ttp.commands._common import (
    _PREFIX,
    cli_state,
    console,
    get_uid_from_port as _get_uid_from_port,
    is_port_in_use as _is_port_in_use,
    is_port_listening_tcp as _is_port_listening_tcp,
    is_port_listening_udp as _is_port_listening_udp,
    logger,
    print_error as _print_error,
    require_root as _require_root,
    require_systemd,
    validate_bridge_line as _validate_bridge_line,
    verify_tor as _verify_tor,
)
from ttp.commands.lifecycle import register_signal_handlers
from ttp.exceptions import DNSError, FirewallError, StateError, TorError


# ---------------------------------------------------------------------------
# Private helpers extracted from start_command for testability
# ---------------------------------------------------------------------------


def _parse_bypass_users_groups(
    bypass_user: list[str] | None,
    bypass_group: list[str] | None,
) -> tuple[list[str], list[str], list[int], list[int]]:
    """Parse, validate and resolve bypass users and groups to system UIDs/GIDs.

    Parameters
    ----------
    bypass_user:
        Raw CLI ``--bypass-user`` values (may include comma-separated names).
    bypass_group:
        Raw CLI ``--bypass-group`` values (may include comma-separated names).

    Returns
    -------
    tuple[list[str], list[str], list[int], list[int]]
        ``(users, groups, bypass_uids, bypass_gids)``

    Raises
    ------
    typer.Exit
        If any user or group does not exist on the system.
    """
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
    """Parse, validate and collect Tor bridge lines from file and/or CLI flags.

    Parameters
    ----------
    bridge_file:
        Path to a file containing bridge lines (one per line, ``#`` comments
        are ignored).
    bridge:
        Individual bridge lines provided via ``--bridge`` flags.
    use_bridges:
        Whether ``--use-bridges`` was specified on the CLI.

    Returns
    -------
    tuple[list[str], bool]
        ``(bridge_lines, use_bridges)`` — the collected bridge lines and the
        resolved value of *use_bridges* (True if any lines were found).

    Raises
    ------
    typer.Exit
        On missing file, unreadable file, or invalid bridge line format.
    """
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

    1. **Manual override** — ``--tor-uid`` CLI flag (name or numeric UID).
    2. **Socket auto-detection** — inspect ``/proc/net/tcp`` for the process
       bound to *transport_port*; accept only if the username contains ``"tor"``
       and is not root.
    3. **Known usernames fallback** — scan ``/etc/passwd`` for ``"tor"`` or
       ``"debian-tor"``.
    4. **Fatal error** — none of the above succeeded; caller must exit.

    Parameters
    ----------
    transport_port:
        The TCP port Tor's TransPort is expected to be bound on.
    tor_uid_override:
        Optional raw value of the ``--tor-uid`` CLI flag.

    Returns
    -------
    str
        The resolved UID as a string (numeric, e.g. ``"1001"``).

    Raises
    ------
    typer.Exit
        If the manual override references a non-existent user, or if UID
        resolution fails entirely.
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
        detected_uid = _get_uid_from_port(transport_port)
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
                        "Auto-detected Tor UID %d belongs to user '%s' which is not root but does not contain 'tor'. Ignoring.",
                        detected_uid,
                        username,
                    )
            except KeyError:
                logger.warning(
                    "Auto-detected Tor UID %d is not registered in the pwd database. Ignoring.",
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


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def start_command(
    interface: Optional[str] = typer.Option(
        None,
        "--interface",
        "-i",
        help="Network interface to configure DNS on (auto-detected if omitted).",
    ),
    bootstrap_timeout: int = typer.Option(
        180,
        "--bootstrap-timeout",
        help="Timeout in seconds to wait for Tor to bootstrap.",
    ),
    transport_port: int = typer.Option(
        9041,
        "--transport-port",
        "-t",
        help="Port for Tor's TransPort redirect.",
    ),
    dns_port: int = typer.Option(
        9054,
        "--dns-port",
        "-d",
        help="Port for Tor's DNSPort redirect.",
    ),
    allow_root: bool = typer.Option(
        False,
        "--allow-root",
        help="Allow root processes to bypass Tor routing (not recommended, increases leak risk).",
    ),
    no_lan_bypass: bool = typer.Option(
        False,
        "--no-lan-bypass",
        help="Do not bypass Tor routing for local subnets (RFC 1918 & Link-Local).",
    ),
    watchdog: bool = typer.Option(
        False,
        "--watchdog",
        "-w",
        help="Start the background watchdog daemon to monitor session integrity.",
    ),
    bypass_user: Optional[list[str]] = typer.Option(
        None,
        "--bypass-user",
        help="System user(s) to bypass Tor routing.",
    ),
    bypass_group: Optional[list[str]] = typer.Option(
        None,
        "--bypass-group",
        help="System group(s) to bypass Tor routing.",
    ),
    use_bridges: bool = typer.Option(
        False,
        "--use-bridges",
        help="Globally enable Tor bridges support.",
    ),
    bridge_file: Optional[Path] = typer.Option(
        None,
        "--bridge-file",
        help="Path to a file containing Tor bridge lines.",
    ),
    bridge: Optional[list[str]] = typer.Option(
        None,
        "--bridge",
        help="Individual Tor bridge line. Can be specified multiple times.",
    ),
    external_daemon: bool = typer.Option(
        False,
        "--external-daemon",
        help="Run TTP in BYOD mode, delegating Tor lifecycle management to the host.",
    ),
    tor_uid: Optional[str] = typer.Option(
        None,
        "--tor-uid",
        help="Specify the numeric UID or username of the Tor process manually in BYOD mode.",
    ),
    no_ipv6: bool = typer.Option(
        False,
        "--no-ipv6",
        help="Force disable all IPv6 traffic (drops outgoing IPv6 to prevent leaks).",
    ),
) -> None:
    """Start the transparent Tor proxy session."""
    _require_root()

    require_systemd()

    if external_daemon and watchdog:
        _print_error(
            "Configuration Conflict",
            "Watchdog daemon cannot be used in external-daemon mode as it relies on systemd.",
        )
        raise typer.Exit(code=1)

    # --- Input parsing & validation ---

    users, groups, bypass_uids, bypass_gids = _parse_bypass_users_groups(
        bypass_user, bypass_group
    )
    cli_state.bypass_users = users
    cli_state.bypass_groups = groups

    bridge_lines, use_bridges = _parse_bridges(bridge_file, bridge, use_bridges)

    # Ports validation
    if not (1024 <= transport_port <= 65535):
        _print_error(
            "Invalid Port",
            f"TransPort {transport_port} must be between 1024 and 65535.",
        )
        raise typer.Exit(code=1)

    if not (1024 <= dns_port <= 65535):
        _print_error(
            "Invalid Port", f"DNSPort {dns_port} must be between 1024 and 65535."
        )
        raise typer.Exit(code=1)

    if transport_port == dns_port:
        _print_error(
            "Port Conflict",
            f"TransPort and DNSPort cannot be the same ({transport_port}).",
        )
        raise typer.Exit(code=1)

    # Pre-flight check if ports are already in use
    if not external_daemon:
        for port, name in [(transport_port, "TransPort"), (dns_port, "DNSPort")]:
            if _is_port_in_use(port):
                _print_error(
                    "Port In Use",
                    f"The {name} port {port} is already in use by another process.",
                )
                raise typer.Exit(code=1)
    else:
        # BYOD Mode: Passive healthcheck that Tor is listening on these ports
        if not _is_port_listening_tcp(transport_port) or not _is_port_listening_udp(
            dns_port
        ):
            _print_error(
                "Tor Not Running",
                f"Tor is not running on the requested TransPort ({transport_port}) or DNSPort ({dns_port}).\n"
                "Please start your Tor daemon before running TTP.",
            )
            raise typer.Exit(code=1)

    register_signal_handlers()

    from ttp.tor_detect import is_ipv6_supported

    ipv6_supported = is_ipv6_supported()
    if no_ipv6:
        if not ipv6_supported:
            console.print(
                f"{_PREFIX} [bold yellow]Warning: IPv6 is not supported by the system. "
                "The --no-ipv6 flag is superfluous.[/bold yellow]"
            )
        else:
            console.print(
                f"{_PREFIX} IPv6 traffic will be dropped to prevent leaks (disabled via --no-ipv6), "
                "even though the system supports IPv6."
            )

    lock = state.read_lock()
    if lock:
        if state.is_orphan():
            console.print(
                f"{_PREFIX} [yellow]Orphaned session detected (PID {lock.get('pid')}). "
                f"Auto-recovering...[/]"
            )
            state.attempt_recovery(firewall.destroy_rules, dns.restore_dns)
            console.print(f"{_PREFIX} Recovery complete. Starting new session...")
        else:
            _print_error(
                "Concurrency Error",
                f"Another TTP process (PID {lock['pid']}) is currently running.",
            )
            raise typer.Exit(code=1)

    if allow_root:
        console.print(
            f"{_PREFIX} [bold red]WARNING: --allow-root is enabled. "
            "All root-owned processes (e.g., systemd services, cron, package managers) "
            "will bypass Tor and transmit in CLEARTEXT! Use with caution.[/bold red]"
        )

    # --- Step 0a: Pre-flight — verify /run has enough space for tmpfs I/O ---
    try:
        state.check_tmpfs_space()
    except StateError as exc:
        _print_error("Pre-flight Failed", str(exc))
        raise typer.Exit(code=1)

    # --- Step 0b: SELinux optimization (for Fedora/RHEL) ---
    # Ensures the kernel policy allows Tor to bind to our ports.
    # Runs once and has zero overhead on subsequent calls.
    tor_install.setup_selinux_if_needed()

    # --- Step 1: Detect / install Tor ---
    info = {}
    if external_daemon:
        tor_user = _resolve_external_tor_uid(transport_port, tor_uid)
        console.print(
            f"{_PREFIX} Tor daemon detected operating under UID: {tor_user} (BYOD Mode)."
        )
    else:
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
        console.print(
            f"{_PREFIX} [bold yellow]Warning: firewalld is active.[/bold yellow]"
        )
        console.print(
            "  [yellow]firewalld can interfere with TTP's nftables rules and cause connectivity issues.[/yellow]"
        )
        console.print(
            "  [yellow]If Tor fails to bootstrap, consider stopping it: sudo systemctl stop firewalld[/yellow]\n"
        )

    lan_bypass = not no_lan_bypass

    # --- Step 2: Apply stateless firewall rules ---
    try:
        kwargs_fw = {}
        if bypass_uids:
            kwargs_fw["bypass_uids"] = bypass_uids
        if bypass_gids:
            kwargs_fw["bypass_gids"] = bypass_gids

        firewall.apply_rules(
            tor_user=tor_user,
            transport_port=transport_port,
            dns_port=dns_port,
            allow_root=allow_root,
            lan_bypass=lan_bypass,
            disable_ipv6=no_ipv6,
            **kwargs_fw,
        )
    except FirewallError as exc:
        _print_error("Firewall Setup Failed", str(exc))
        if not external_daemon:
            tor_install.stop_tor_service()
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    console.print(f"{_PREFIX} Stateless nftables rules applied (Table: inet ttp).")

    # --- Step 3: Modify DNS ---
    if interface is None:
        interface = dns.detect_active_interface()
    try:
        dns_backup = dns.apply_dns(interface, disable_ipv6=no_ipv6, dns_port=dns_port)
    except DNSError as exc:
        logger.error("DNS setup failed: %s", exc)
        _print_error("DNS Setup Failed", str(exc))
        if not external_daemon:
            tor_install.stop_tor_service()
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    except Exception as exc:
        logger.error("Unexpected DNS error: %s", exc)
        _print_error(
            "DNS Setup Failed", "An unexpected error occurred during DNS configuration."
        )
        if not external_daemon:
            tor_install.stop_tor_service()
        firewall.destroy_rules()
        raise typer.Exit(code=1)
    logger.info("Session started: interface=%s", interface)
    console.print(f"{_PREFIX} DNS set via overlay on interface {interface}.")

    # --- Step 4: Write lock file ---
    try:
        tor_uid_val: int | None = None
        try:
            if tor_user.isdigit():
                tor_uid_val = int(tor_user)
            else:
                tor_uid_val = pwd.getpwnam(tor_user).pw_uid
        except Exception:
            pass

        kwargs_lock: dict = {}
        if users:
            kwargs_lock["bypass_users"] = users
        if groups:
            kwargs_lock["bypass_groups"] = groups
        if use_bridges:
            kwargs_lock["use_bridges"] = use_bridges
        if bridge_file:
            kwargs_lock["bridge_file"] = str(bridge_file)
        if bridge_lines:
            kwargs_lock["bridges"] = bridge_lines

        state.write_lock(
            dns_backup=dns_backup,
            transport_port=transport_port,
            dns_port=dns_port,
            allow_root=allow_root,
            lan_bypass=lan_bypass,
            interface=interface,
            external_daemon=external_daemon,
            no_ipv6=no_ipv6,
            tor_uid=tor_uid_val,
            **kwargs_lock,
        )
    except StateError as exc:
        logger.error("Failed to write lock: %s", exc)
        _print_error("Session Tracking Failed", str(exc))
        # Emergency cleanup since we can't track this session
        if not external_daemon:
            tor_install.stop_tor_service()
        firewall.destroy_rules()
        dns.restore_dns(dns_backup)
        raise typer.Exit(code=1)

    # --- Step 5: Verify Tor is working ---
    is_tor, exit_ip = _verify_tor(timeout=bootstrap_timeout)
    if is_tor:
        console.print(f"{_PREFIX} [bold green]Session active. Exit IP: {exit_ip}[/]")
    else:
        console.print(
            f"{_PREFIX} [bold yellow]Session active but Tor verification failed.[/]"
        )
        console.print(
            f"{_PREFIX} [yellow]Traffic may NOT be routed through Tor. "
            f"Check Tor service and try 'ttp stop' then 'ttp start'.[/]"
        )
        if exit_ip != "unknown":
            console.print(f"{_PREFIX} [yellow]Detected IP: {exit_ip}[/]")

    if watchdog:
        console.print(f"{_PREFIX} Starting session watchdog daemon...")
        from ttp import watchdog as wd

        try:
            wd.start_watchdog()
        except Exception as e:
            _print_error("Watchdog Error", f"Failed to start session watchdog: {e}")

    console.print(f"{_PREFIX} Use 'ttp stop' to terminate. 'ttp refresh' to change IP.")

    # One-time discrete message to encourage GitHub stars.
    if state.should_show_star_message():
        console.print(
            "\n[dim]Thanks for using TTP! Starring the repo on GitHub helps the project grow.[/]"
        )
        state.mark_star_message_shown()
