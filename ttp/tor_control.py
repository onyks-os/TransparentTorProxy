"""Tor daemon control and circuit verification.

This module is the "voice" of TTP. It communicates directly with the
Tor daemon using the Stem library. It handles authentication,
bootstrap monitoring, circuit rotation (Signal.NEWNYM), and external
API verification to confirm that traffic is actually being routed
through Tor.

KEY RESPONSIBILITIES:
1. Connect to Tor via Unix Socket or TCP ControlPort.
2. Monitor bootstrap progress until 100%.
3. Request new exit IPs (circuits).
4. Verify the current exit IP via multiple endpoints for resilience.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.request
from typing import Callable, Optional
from ttp.exceptions import TorError

# Verification endpoints ordered by priority.
# The Tor Project's API is authoritative (returns IsTor), the others are
# generic IP reflectors used as fallbacks when the primary is unreachable.
VERIFY_ENDPOINTS = [
    "https://check.torproject.org/api/ip",
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
]

try:
    from stem.control import Controller
    from stem import Signal
except ImportError:
    Controller = None
    Signal = None

# TTP instance control socket (never fall back to system Tor — see get_controller).
_TTP_CONTROL_SOCKET = "/run/tor/ttp/control.sock"


def get_exit_ip() -> str:
    """Fetch the current Tor exit IP, trying multiple endpoints for resilience.

    Uses ``urllib.request`` from the stdlib so we don't need to add
    ``requests`` as a dependency.
    """
    for endpoint in VERIFY_ENDPOINTS:
        try:
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "ttp"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                # check.torproject.org uses "IP", ipify uses "ip", ifconfig.me uses "ip_addr"
                ip = data.get("IP") or data.get("ip") or data.get("ip_addr")
                if ip:
                    return ip
        except Exception:
            continue
    return "unknown"


def get_controller():
    """Connect to the dedicated ``ttp-tor`` control interface only.

    Uses exclusively ``ControlSocket /run/tor/ttp/control.sock`` so
    bootstrap queries, NEWNYM, and shutdown signals always target TTP's
    isolated instance — never ``tor.service`` or TCP ControlPort.
    Returns an authenticated :class:`stem.control.Controller` or ``None``.
    """
    if Controller is None:
        return None

    if not os.path.exists(_TTP_CONTROL_SOCKET):
        return None

    try:
        ctrl = Controller.from_socket_file(_TTP_CONTROL_SOCKET)
        ctrl.authenticate()
        return ctrl
    except (socket.error, Exception):
        return None


def wait_for_bootstrap(
    progress_callback: Optional[Callable[[int], None]] = None, timeout: int = 180
) -> bool:
    """Wait for Tor to reach 100% bootstrap status via ControlPort.

    Parameters
    ----------
    progress_callback:
        Optional callable that takes an integer (0-100) representing
        the bootstrap percentage.
    """
    # 1. Wait for the control interface to be available (up to 60s).
    controller = None
    bootstrap_conn_timeout = 60
    for _ in range(bootstrap_conn_timeout // 2):
        controller = get_controller()
        if controller is not None:
            break
        time.sleep(2)

    if not controller:
        raise TorError(f"Could not connect to Tor control interface after {bootstrap_conn_timeout}s.")

    # 2. Monitor bootstrap progress.
    with controller:
        for _ in range(timeout):  # Use the provided timeout (default 90)
            status = controller.get_info("status/bootstrap-phase")
            match = re.search(r"PROGRESS=(\d+)", status)
            progress_val = int(match.group(1)) if match else 0

            if progress_callback:
                progress_callback(progress_val)

            if "PROGRESS=100" in status:
                return True

            time.sleep(1)

        raise TorError("Tor bootstrap timed out.")


def verify_tor() -> tuple[bool, str]:
    """Verify that traffic is actually routed through Tor.

    Tries multiple endpoints for resilience. The Tor Project's API is
    authoritative (it returns ``IsTor``); the fallback endpoints only
    confirm we can reach the internet through *some* exit node.

    Returns
    -------
    tuple[bool, str]
        ``(is_tor, exit_ip)`` - whether we confirmed Tor routing,
        and the exit IP address.
    """
    for attempt in range(1, 6):  # 5 attempts
        for endpoint in VERIFY_ENDPOINTS:
            try:
                req = urllib.request.Request(
                    endpoint,
                    headers={"User-Agent": "ttp"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())

                    # The Tor Project API is the only one that returns IsTor.
                    if "IsTor" in data:
                        return data.get("IsTor", False), data.get("IP", "unknown")

                    # Fallback endpoints: we got a response, so traffic is routed
                    # through *something*. We can't confirm it's Tor, but we have an IP.
                    ip = data.get("ip") or data.get("ip_addr") or "unknown"
                    return True, ip
            except Exception:
                continue
        time.sleep(3)

    return False, "unknown"


def request_new_circuit() -> tuple[bool, str]:
    """Request a new Tor circuit (new exit IP) and wait for it to change.

    Returns
    -------
    tuple[bool, str]
        ``(ip_changed, current_ip)``
    """
    old_ip = get_exit_ip()

    ctrl = get_controller()
    if ctrl is None:
        raise TorError(
            "Cannot connect to Tor control interface. Check that Tor is running."
        )

    with ctrl:
        ctrl.signal(Signal.NEWNYM)

    new_ip = old_ip

    # Poll for IP change instead of fixed sleep
    for _ in range(12):  # max ~60s
        time.sleep(5)
        new_ip = get_exit_ip()
        if new_ip != old_ip and new_ip != "unknown":
            return True, new_ip

    return False, new_ip


def graceful_shutdown(timeout: int = 10) -> bool:
    """Send ``SHUTDOWN`` signal to Tor for clean circuit teardown.

    This MUST be called **before** firewall teardown to avoid leaking
    cleartext RST packets on the physical interface.  Tor will close
    all circuits cryptographically, then exit.

    Parameters
    ----------
    timeout:
        Maximum seconds to wait for Tor to finish closing circuits.

    Returns
    -------
    bool
        ``True`` if the shutdown signal was sent successfully.
    """
    if Signal is None:
        return False

    ctrl = get_controller()
    if ctrl is None:
        return False

    try:
        with ctrl:
            ctrl.signal(Signal.SHUTDOWN)

        # Wait for Tor to finish closing circuits
        for _ in range(timeout):
            ctrl_check = get_controller()
            if ctrl_check is None:
                return True
            try:
                ctrl_check.close()
            except Exception:
                pass
            time.sleep(1)
        return True
    except Exception:
        return False

