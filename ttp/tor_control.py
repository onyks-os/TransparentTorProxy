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

# Debian ControlSocket path (set in tor-service-defaults-torrc).
_CONTROL_SOCKET = "/run/tor/control"


def get_exit_ip() -> str:
    """Fetch the current Tor exit IP, trying multiple endpoints for resilience.

    Uses ``urllib.request`` from the stdlib so we don't need to add
    ``requests`` as a dependency.
    """
    for endpoint in VERIFY_ENDPOINTS:
        try:
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "ttp/0.1"},
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
    """Connect to Tor's control interface.

    Tries the Unix ControlSocket first (``/run/tor/control``, the
    Debian default), then falls back to TCP ControlPort 9051.
    Returns an **authenticated** :class:`stem.control.Controller` or
    ``None``.
    """
    if Controller is None:
        return None

    # 1. Unix socket (Debian default — always available).
    if os.path.exists(_CONTROL_SOCKET):
        try:
            ctrl = Controller.from_socket_file(_CONTROL_SOCKET)
            ctrl.authenticate()
            return ctrl
        except (socket.error, Exception):
            pass

    # 2. TCP ControlPort (if configured in torrc).
    try:
        ctrl = Controller.from_port(port=9051)
        ctrl.authenticate()
        return ctrl
    except (socket.error, Exception):
        pass

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
    # 1. Wait for the control interface to be available.
    controller = None
    for _ in range(30):
        controller = get_controller()
        if controller is not None:
            break
        time.sleep(1)

    if not controller:
        raise TorError("Could not connect to Tor control interface after 30s.")

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
        ``(is_tor, exit_ip)`` — whether we confirmed Tor routing,
        and the exit IP address.
    """
    for attempt in range(1, 6):  # 5 attempts
        for endpoint in VERIFY_ENDPOINTS:
            try:
                req = urllib.request.Request(
                    endpoint,
                    headers={"User-Agent": "ttp/0.1"},
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
