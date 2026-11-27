# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Session lifecycle: graceful stop and signal handling."""

from __future__ import annotations

import functools
import signal
import subprocess
import time
from collections.abc import Callable
from typing import Any

from ttp import dns, firewall, state, tor_install
from ttp.commands._common import (
    _PREFIX,
    console,
    get_uid_from_port,
    logger,
)
from ttp.paths import resolve_optional


def close_redirected_or_retain(lock: dict | None) -> None:
    """Close redirected TCP sockets while the rules still hold them; else keep the rules.

    A socket of a connection redirected to the TransPort can outlive Tor and
    retransmit to its original destination once the rules are gone. The 300 ms
    reject window above only catches sockets that happen to transmit in it.
    Exits with code 8 (containment unconfirmed) before any rule, conntrack
    entry, DNS change or lock is removed, so `ttp stop` can be run again.
    """
    from ttp.firewall.redirected import RedirectedSocketsRemain

    port = lock.get("transport_port", 9041) if lock else 9041
    if type(port) is not int or not 0 < port < 65536:
        port = 9041
    console.print(f"{_PREFIX} Closing redirected connections before removing rules...")
    try:
        closed = firewall.close_redirected_sockets(port)
    except RedirectedSocketsRemain as exc:
        import typer

        from ttp.commands._common import print_error

        print_error("Teardown Retained", str(exc))
        raise typer.Exit(code=8)
    if closed:
        logger.info("Closed %d redirected TCP connection(s) before teardown.", closed)


def do_stop() -> None:
    """Internal stop logic - shared by ``stop`` command and signal handler."""
    lock = state.read_lock()
    if lock is None:
        return

    if lock.get("session_id"):
        from ttp.session_safety import STOP_ADVICE, mark_stopping

        console.print(f"{_PREFIX} {STOP_ADVICE}")
        mark_stopping(lock)

    is_external = lock.get("external_daemon", False)

    if not is_external:
        console.print(f"{_PREFIX} Stopping watchdog daemon...")
        # The import is inside the try on purpose. Teardown must never depend on
        # the watchdog package importing: when it raised here, a host without
        # the watchdog's dependency could not run `ttp stop` at all.
        try:
            from ttp import watchdog as wd

            wd.stop_watchdog()
        except Exception as e:
            logger.warning("Could not stop the watchdog, continuing teardown: %s", e)

    import pwd

    # The lock is session state, not a trusted integer source: anything that is
    # not a plain non-negative integer falls through to the real lookups below
    # rather than being formatted into a root nft command.
    raw_uid = lock.get("tor_uid")
    try:
        tor_uid = int(raw_uid) if raw_uid is not None else None
        if tor_uid is not None and tor_uid < 0:
            tor_uid = None
    except (TypeError, ValueError):
        logger.warning("Ignoring non-integer tor_uid %r from the session lock.", raw_uid)
        tor_uid = None
    if tor_uid is None:
        transport_port = lock.get("transport_port", 9041)
        tor_uid = get_uid_from_port(transport_port)
        if tor_uid is None:
            for fallback_user in ("tor", "debian-tor"):
                try:
                    tor_uid = pwd.getpwnam(fallback_user).pw_uid
                    break
                except KeyError:
                    continue

    console.print(f"{_PREFIX} Applying teardown lockdown...")
    firewall.apply_teardown_lockdown(tor_uid)

    if not is_external:
        console.print(f"{_PREFIX} Gracefully shutting down Tor circuits...")
        from ttp import tor_control

        tor_control.graceful_shutdown(timeout=10)

        console.print(f"{_PREFIX} Stopping Tor service...")
        tor_install.stop_tor_service()
        tor_install.unlabel_ports_selinux(
            lock.get("transport_port", 9041),
            lock.get("dns_port", 9054),
        )

    console.print(f"{_PREFIX} Executing active socket slaughter (Zero-Leak teardown)...")
    firewall.apply_active_socket_slaughter()
    console.print(f"{_PREFIX} Waiting 300ms for pending connections to crash...")
    time.sleep(0.3)
    close_redirected_or_retain(lock)

    conntrack_path = resolve_optional("conntrack")
    if conntrack_path:
        console.print(f"{_PREFIX} Flushing connection tracking table...")
        try:
            subprocess.run(
                [conntrack_path, "-F"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Failed to flush conntrack table: %s",
                e.stderr.strip() if e.stderr else str(e),
            )
    else:
        logger.debug("conntrack binary not found, skipping flush.")

    console.print(f"{_PREFIX} Removing nftables rules...")
    try:
        firewall.destroy_rules()

        console.print(f"{_PREFIX} Restoring DNS...")
        try:
            dns.restore_dns(lock.get("dns_backup"))
        except Exception as e:
            logger.error("DNS restoration failed, continuing teardown: %s", e)
        if lock.get("vpn"):
            from ttp.vpn import VPNError
            from ttp.vpn_guard import release_after_stop

            try:
                release_after_stop()
            except VPNError as exc:
                import typer

                from ttp.commands._common import print_error

                print_error("VPN Protection Retained", str(exc))
                raise typer.Exit(code=8)
    finally:
        # The lock must not outlive the nftables table. A lock whose session is
        # already torn down blocks the next `ttp start` behind a concurrency
        # error while the host routes in cleartext, and makes `ttp status`
        # report a session that no longer exists. attempt_recovery() has used
        # this same try/finally shape all along.
        state.delete_lock()
    console.print(f"{_PREFIX} [bold red]Session terminated. Traffic in cleartext.[/]")
    from ttp.commands._common import print_error
    from ttp.notifications.service import finish_notifications

    result = finish_notifications(lock)
    if result.exit_code:
        import typer

        for diagnostic in result.diagnostics:
            print_error(diagnostic.reason, diagnostic.message)
        raise typer.Exit(code=int(result.exit_code))


def restore_without_session() -> dict | None:
    """Restore the network without trusting a session record: ``stop --restore-only``.

    Everything is derived from the host, not from the lock: the managed Tor is
    stopped, redirected connections are closed while the rules still hold them
    (or the rules are retained, exit 8), the table is destroyed, the DNS overlay
    is unmounted and a retained VPN guard is released. Also undoes a ``ttp
    start`` interrupted before it recorded its session. Returns the lock it
    found, if any, so the caller can finish its notifications.
    """
    import typer

    from ttp import tor_control
    from ttp.runtime_records import session_store

    # Explicit restoration also works after lost/corrupt session intent.
    # Persist it before stopping services, including their ExecStopPost.
    state.ensure_runtime_dir()
    store = session_store()
    store.prepare()
    with store.transition():
        state.write_stop_marker("*")
    console.print(f"{_PREFIX} Forcing network restoration (restore-only)...")

    # Stop watchdog first. The import is inside the try: restoration must not
    # depend on the watchdog package importing (see do_stop).
    try:
        from ttp import watchdog as wd

        wd.stop_watchdog()
    except Exception as e:
        logger.warning("Could not stop the watchdog, continuing restoration: %s", e)

    # Graceful shutdown even in restore-only mode
    tor_control.graceful_shutdown(timeout=10)
    tor_install.stop_tor_service()
    close_redirected_or_retain(state.read_lock())
    firewall.destroy_rules()

    lock = state.read_lock()
    if lock:
        tor_install.unlabel_ports_selinux(
            lock.get("transport_port", 9041),
            lock.get("dns_port", 9054),
        )
        dns.restore_dns(lock.get("dns_backup"))
    else:
        dns.restore_dns(None)

    from ttp.vpn_guard import INTENT

    if (lock and lock.get("vpn")) or INTENT.exists():
        from ttp.vpn import VPNError
        from ttp.vpn_guard import release_after_stop

        try:
            release_after_stop()
        except VPNError as exc:
            from ttp.commands._common import print_error

            print_error("VPN Protection Retained", str(exc))
            raise typer.Exit(code=8)
    state.delete_lock()
    console.print(f"{_PREFIX} [bold red]Network restored. Traffic in cleartext.[/]")
    return lock


class StartInterrupted(BaseException):
    """SIGINT/SIGTERM arrived during ``ttp start``.

    A ``BaseException``, so no ``except Exception`` in the start path can
    swallow it, and raised rather than handled in the signal handler: the
    handler runs between two bytecodes of whatever start was doing, possibly
    while an ``nft`` or ``systemctl`` child is still running. Undoing the
    start there could destroy the table before that child loaded it. Raised,
    the in-flight call unwinds first (``subprocess.run`` kills and reaps its
    child), and :func:`interruptible_start` undoes what was done.
    """

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def signal_handler(signum: int, frame) -> None:
    """SIGINT/SIGTERM during ``ttp start``: unwind it, see :class:`StartInterrupted`."""
    raise StartInterrupted(signum)


def register_signal_handlers() -> None:
    """Register SIGINT/SIGTERM handlers for safe session cleanup."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def finish_interrupted_start() -> int:
    """Undo an interrupted ``ttp start`` and return its exit code.

    An interrupted start never exits 0: no session was established, and a
    script that trusted 0 would run in cleartext.

    - Before the session was recorded (no lock), what start changed is undone
      as ``stop --restore-only`` would: nothing is left that ``ttp stop`` and
      ``ttp status`` cannot see. Exit 1. A retained VPN guard stays, exit 10.
    - After it was recorded, the session is stopped, exit 1, unless emergency
      containment is latched (or cannot be read): then it is retained, exit 8.
    """
    # A second Ctrl-C must not interrupt the undo itself.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    import typer

    from ttp.commands._common import print_error

    lock = state.read_lock()
    if lock is None:
        from ttp.vpn_guard import INTENT

        if INTENT.exists():
            print_error(
                "VPN Protection Retained", "Interrupted startup; use ttp stop --restore-only for explicit recovery."
            )
            return 10
        console.print(f"\n{_PREFIX} Start interrupted before the session was recorded; undoing its changes...")
        try:
            restore_without_session()
        except typer.Exit as exc:
            return int(exc.exit_code)
        return 1
    if lock.get("session_id"):
        from ttp.session_safety import STOP_ADVICE, emergency_latched

        try:
            latched = emergency_latched(lock)
        except Exception:
            latched = True
        if latched:
            print_error("Session Retained", STOP_ADVICE)
            return 8
    console.print(f"\n{_PREFIX} Start interrupted; stopping the session...")
    try:
        do_stop()
    except typer.Exit as exc:
        return int(exc.exit_code) or 1
    return 1


def interruptible_start(command: Callable[..., None]) -> Callable[..., None]:
    """Turn a :class:`StartInterrupted` inside *command* into an undone start."""

    @functools.wraps(command)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        import typer

        try:
            command(*args, **kwargs)
        except StartInterrupted:
            raise typer.Exit(code=finish_interrupted_start()) from None

    return wrapper
