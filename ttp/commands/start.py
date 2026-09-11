from __future__ import annotations

import pwd
from pathlib import Path
from typing import Optional

import typer

from ttp import dns, firewall, state, tor_install
from ttp.commands._common import (
    _PREFIX,
    EXIT_UNVERIFIED,
    cli_state,
    console,
    logger,
    require_systemd,
)
from ttp.commands._common import (
    get_uid_from_port as _get_uid_from_port,
)
from ttp.commands._common import (
    is_port_in_use as _is_port_in_use,
)
from ttp.commands._common import (
    is_port_listening_tcp as _is_port_listening_tcp,
)
from ttp.commands._common import (
    is_port_listening_udp as _is_port_listening_udp,
)
from ttp.commands._common import (
    print_error as _print_error,
)
from ttp.commands._common import (
    require_root as _require_root,
)
from ttp.commands._common import (
    verify_tor as _verify_tor,
)
from ttp.commands._preflight import (
    check_session_state,
    preflight_checks,
    validate_ports,
)
from ttp.commands._tor_setup import (
    _parse_bridges,
    _parse_bypass_users_groups,
    _resolve_external_tor_uid,
    setup_managed_tor,
)
from ttp.commands.lifecycle import register_signal_handlers
from ttp.exceptions import DNSError, FirewallError, StateError

__all__ = [
    "_get_uid_from_port",
    "_is_port_in_use",
    "_is_port_listening_tcp",
    "_is_port_listening_udp",
    "_parse_bridges",
    "_parse_bypass_users_groups",
    "_resolve_external_tor_uid",
    "start_command",
]

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
    users, groups, bypass_uids, bypass_gids = _parse_bypass_users_groups(bypass_user, bypass_group)
    cli_state.bypass_users = users
    cli_state.bypass_groups = groups

    bridge_lines, use_bridges = _parse_bridges(bridge_file, bridge, use_bridges)
    validate_ports(transport_port, dns_port, external_daemon)
    register_signal_handlers()

    from ttp import tor_detect

    ipv6_supported = tor_detect.is_ipv6_supported()
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

    check_session_state()

    if allow_root:
        console.print(
            f"{_PREFIX} [bold red]WARNING: --allow-root is enabled. "
            "All root-owned processes (e.g., systemd services, cron, package managers) "
            "will bypass Tor and transmit in CLEARTEXT! Use with caution.[/bold red]"
        )

    preflight_checks()

    # --- Step 1: Detect / install Tor ---
    info = {}
    if external_daemon:
        tor_user = _resolve_external_tor_uid(transport_port, tor_uid)
        console.print(f"{_PREFIX} Tor daemon detected operating under UID: {tor_user} (BYOD Mode).")
    else:
        info = setup_managed_tor(
            transport_port=transport_port,
            dns_port=dns_port,
            bridge_lines=bridge_lines,
            use_bridges=use_bridges,
            no_ipv6=no_ipv6,
        )
        tor_user = info.get("tor_user", "debian-tor")

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
        _print_error("DNS Setup Failed", "An unexpected error occurred during DNS configuration.")
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
            tor_uid_val = int(tor_user) if tor_user.isdigit() else pwd.getpwnam(tor_user).pw_uid
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
        if not external_daemon:
            tor_install.stop_tor_service()
        firewall.destroy_rules()
        dns.restore_dns(dns_backup)
        raise typer.Exit(code=1)

    # --- Step 5: Verify Tor is working ---
    #
    # Reaching this point means the firewall rules, the DNS overlay and the lock
    # file are all in place, so a failure here does not leak: everything that is
    # not explicitly bypassed is held fail-closed against a Tor that is not
    # answering. The session is therefore left standing rather than torn down -
    # but it is not a success either, and the exit code has to say so.
    is_tor, exit_ip = _verify_tor(timeout=bootstrap_timeout)
    if is_tor:
        console.print(f"{_PREFIX} [bold green]Session active. Exit IP: {exit_ip}[/]")
    else:
        console.print(f"{_PREFIX} [bold yellow]Session active but Tor verification failed.[/]")
        console.print(
            f"{_PREFIX} [yellow]Traffic is NOT reaching Tor and is being held fail-closed: "
            f"everything except explicitly bypassed traffic is blocked. "
            f"Check the Tor service, or run 'ttp stop' to restore the network.[/]"
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

    # Raised after the watchdog has been given its chance to start: a session
    # that is up but unverified is exactly the one that benefits from being
    # watched.
    if not is_tor:
        raise typer.Exit(code=EXIT_UNVERIFIED)

    if state.should_show_star_message():
        console.print("\n[dim]Thanks for using TTP! Starring the repo on GitHub helps the project grow.[/]")
        state.mark_star_message_shown()
