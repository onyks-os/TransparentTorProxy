from __future__ import annotations

import pwd
from pathlib import Path
from typing import Optional

import typer

from ttp import dns, firewall, state, tor_install
from ttp.commands._common import (
    _PREFIX,
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
    require_dnssec_compatibility,
    require_watchdog_dependency,
    validate_ports,
)
from ttp.commands._tor_setup import (
    _parse_bridges,
    _parse_bypass_users_groups,
    _resolve_external_tor_uid,
    setup_managed_tor,
)
from ttp.commands.lifecycle import register_signal_handlers
from ttp.evidence import Diagnostic, ExitCode, Result, VerificationState
from ttp.exceptions import DNSError, FirewallError, StateError
from ttp.runtime_records import session_store
from ttp.session_safety import STOP_ADVICE, emergency_latched, request_emergency
from ttp.settings import SettingsError, load_settings

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
    watchdog: Optional[bool] = typer.Option(
        None,
        "--watchdog/--no-watchdog",
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
    notifications: Optional[bool] = typer.Option(
        None,
        "--notifications/--no-notifications",
        help="Enable optional desktop notifications for the initiating user.",
    ),
    notification_user: Optional[str] = typer.Option(
        None, "--notification-user", help="Explicit non-root desktop recipient (required for direct root invocation)."
    ),
) -> None:
    """Start the transparent Tor proxy session."""
    _require_root()
    require_systemd()

    try:
        selected = load_settings().select(watchdog=watchdog, notifications=notifications)
    except SettingsError as exc:
        _print_error("Invalid Configuration", str(exc))
        raise typer.Exit(code=1)
    watchdog = selected.settings.watchdog.enabled
    result = Result()
    target = None
    if notification_user and not selected.settings.notifications.enabled:
        _print_error(
            "Notification Selection", "--notification-user requires --notifications or notifications.enabled=true"
        )
        raise typer.Exit(code=2)
    if selected.settings.notifications.enabled:
        from ttp.notifications.service import recipient

        try:
            target = recipient(notification_user)
        except Exception as exc:
            _print_error("Notifications Unavailable", str(exc))
            result = result.add(
                Diagnostic(
                    ExitCode.NOTIFICATION_FAILED,
                    "notifications.recipient_unavailable",
                    "notifications",
                    "start",
                    "Desktop recipient could not be selected",
                )
            )

    if external_daemon and watchdog:
        _print_error(
            "Configuration Conflict",
            "Watchdog daemon cannot be used in external-daemon mode as it relies on systemd.",
        )
        raise typer.Exit(code=1)

    if watchdog:
        require_watchdog_dependency()

    # --- Input parsing & validation ---
    users, groups, bypass_uids, bypass_gids = _parse_bypass_users_groups(bypass_user, bypass_group)
    cli_state.bypass_users = users
    cli_state.bypass_groups = groups

    bridge_lines, use_bridges = _parse_bridges(bridge_file, bridge, use_bridges)
    validate_ports(transport_port, dns_port, external_daemon)
    require_dnssec_compatibility()
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
    # Record storage is prepared before changing the network, including on
    # installations without a dedicated watchdog account.
    try:
        state.ensure_runtime_dir()
        session_store().prepare()
    except (OSError, StateError) as exc:
        _print_error("Session Evidence Unavailable", str(exc))
        raise typer.Exit(code=1)

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
            # Taken now, with the rules and the DNS overlay in place: the table
            # the watchdog must find for the rest of the session (#80).
            table_fingerprint=firewall.table_fingerprint(),
            watchdog_requested=watchdog,
            settings=selected.settings.snapshot(),
            settings_origins=selected.origins,
            notification_target=target,
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

    # Supervision is ready before spending the external verification budget.
    lock = state.read_lock(strict=True)
    if lock is None:
        _print_error("Session Tracking Failed", "Session intent disappeared after setup; containment is unconfirmed.")
        raise typer.Exit(code=int(ExitCode.CONTAINMENT_UNCONFIRMED))
    if target is not None:
        from ttp.notifications.service import start_agent

        try:
            start_agent(lock, target)
        except Exception as exc:
            _print_error("Notifications Unavailable", str(exc))
            result = result.add(
                Diagnostic(
                    ExitCode.NOTIFICATION_FAILED,
                    "notifications.agent_start_failed",
                    "notifications",
                    "start",
                    "Desktop agent did not become ready",
                )
            )
    watchdog_failed = False
    if watchdog:
        console.print(f"{_PREFIX} Waiting for required watchdog readiness...")
        from ttp import watchdog as wd

        try:
            wd.start_watchdog()
        except Exception as exc:
            watchdog_failed = True
            cause = Diagnostic(
                ExitCode.WATCHDOG_UNAVAILABLE,
                "watchdog.start_failed",
                "watchdog",
                "start",
                "Required watchdog did not become ready",
            )
            result = Result(result.diagnostics + request_emergency(lock, cause).diagnostics)
            _print_error("Required Watchdog Unavailable", str(exc))

    if not watchdog_failed:
        verification = _verify_tor(
            timeout=bootstrap_timeout, verification_timeout=selected.settings.verification.timeout, lock=lock
        )
        from ttp.session_report import record_verification

        result = Result(result.diagnostics + record_verification(lock, verification).diagnostics)
        if verification.state is VerificationState.NEGATIVE:
            logger.error("tor.valid_negative: emergency containment requested")
        elif verification.confirmed:
            console.print(f"{_PREFIX} Tor routing confirmed at this observation. Exit IP: {verification.ip}")
        else:
            _print_error(
                "Tor Verification Inconclusive",
                "This result does not prove Tor traffic is absent or that the network is isolated. "
                "The session remains configured; inspect 'ttp status' and 'ttp check'.",
            )

    # A watchdog can detect a fault while the external probe is running.
    try:
        if emergency_latched(lock):
            result = Result(
                result.diagnostics
                + request_emergency(
                    lock,
                    Diagnostic(
                        ExitCode.ERROR,
                        "session.emergency_latched",
                        "session",
                        "start",
                        "Emergency remains latched until explicit termination",
                    ),
                    repair=True,
                ).diagnostics
            )
    except StateError:
        result = result.add(
            Diagnostic(
                ExitCode.CONTAINMENT_UNCONFIRMED,
                "session.evidence_invalid",
                "session",
                "start",
                "Cannot inspect emergency evidence",
            )
        )
    if selected.settings.notifications.enabled:
        from ttp.notifications.service import emit

        event = "started"
        if result.exit_code == ExitCode.CONTAINMENT_UNCONFIRMED:
            event = "containment_unconfirmed"
        elif result.exit_code == ExitCode.EMERGENCY_VERIFIED:
            event = "emergency_verified"
        elif any(item.active and item.code == ExitCode.UNVERIFIED for item in result.diagnostics):
            event = "inconclusive"
        result = Result(result.diagnostics + emit(lock, event).diagnostics)
    if result.exit_code in (ExitCode.EMERGENCY_VERIFIED, ExitCode.CONTAINMENT_UNCONFIRMED):
        message = (
            "Emergency rules verified in the kernel."
            if result.exit_code == ExitCode.EMERGENCY_VERIFIED
            else "CONTAINMENT UNCONFIRMED: isolation could not be established."
        )
        _print_error("Session Emergency", f"{message} {STOP_ADVICE}")
    if result.exit_code:
        for diagnostic in result.diagnostics:
            if diagnostic.active:
                logger.error("%s: %s", diagnostic.reason, diagnostic.message)
                _print_error(diagnostic.reason, diagnostic.message)
        raise typer.Exit(code=int(result.exit_code))

    console.print(f"{_PREFIX} [bold green]Session active; selected startup requirements satisfied.[/]")
    if not watchdog:
        console.print(f"{_PREFIX} Watchdog not selected: no continuous fault detection or asynchronous fault alerts.")
    console.print(f"{_PREFIX} Use 'ttp stop' to terminate. 'ttp refresh' to change IP.")
    if state.should_show_star_message():
        console.print("\n[dim]Thanks for using TTP! Starring the repo on GitHub helps the project grow.[/]")
        state.mark_star_message_shown()
