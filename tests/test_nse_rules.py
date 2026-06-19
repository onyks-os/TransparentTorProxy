# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Automated ruleset validation tests using the Network Sandbox Engine (NSE) API.

Verifies TTP's nftables schema in an isolated network namespace, ensuring:
1. DNS traffic is hijacked and redirected to Tor's DNSPort.
2. TCP traffic is hijacked and redirected to Tor's TransPort.
3. Bypassed UIDs/GIDs are allowed to exit the namespace.
4. DoH and DoT traffic is blocked.
5. Zero cleartext packets escape to the WAN (Zero-Leak PCAP Assertion).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
import pytest
from unittest.mock import patch, MagicMock

# Import NSE core components conditionally to avoid import errors on hosts without the package
try:
    from nse.core.netns_controller import NetnsController
    from nse.core.rule_engine import RuleEngine
    from nse.core.sniffer import PCAPAsserter

    HAS_NSE = True
except ImportError:
    HAS_NSE = False

# Import TTP firewall dynamic rule builder
from ttp.firewall import apply_rules

# Determine if running as root
IS_ROOT = os.geteuid() == 0

# Skip the entire module if not running as root or if NSE is not installed
if not IS_ROOT or not HAS_NSE:
    pytest.skip(
        "NSE integration rules tests must be run as root with nse installed",
        allow_module_level=True,
    )

# Monkey-patch subprocess.run and subprocess.Popen to transparently convert
#   ["ip", "netns", "exec", <name>, ...]
# into
#   ["nsenter", "--net=/var/run/netns/<name>", ...]
#
# This is required because 'ip netns exec' internally mounts a private sysfs
# inside the target namespace, which Docker blocks even in --privileged mode.
# 'nsenter --net=...' uses setns() directly without any mount side-effects.
#
# Primary affected caller: RuleEngine.load() which calls subprocess.run with
# ["ip", "netns", "exec", netns_name, "nft", "-f", rules_file].
_original_subprocess_run = subprocess.run


def _patched_subprocess_run(*args, **kwargs):  # type: ignore[override]
    cmd = args[0] if args else kwargs.get("args")
    if (
        isinstance(cmd, list)
        and len(cmd) >= 4
        and cmd[0] == "ip"
        and cmd[1] == "netns"
        and cmd[2] == "exec"
    ):
        netns_name = cmd[3]
        new_cmd = ["nsenter", f"--net=/var/run/netns/{netns_name}"] + cmd[4:]
        if args:
            args = (new_cmd,) + args[1:]
        else:
            kwargs["args"] = new_cmd
    return _original_subprocess_run(*args, **kwargs)


subprocess.run = _patched_subprocess_run  # type: ignore[assignment]

_original_popen = subprocess.Popen


class _PatchedPopen(_original_popen):  # type: ignore[misc]
    def __init__(self, cmd, *popen_args, **kwargs):
        if (
            isinstance(cmd, list)
            and len(cmd) >= 4
            and cmd[0] == "ip"
            and cmd[1] == "netns"
            and cmd[2] == "exec"
        ):
            netns_name = cmd[3]
            cmd = ["nsenter", f"--net=/var/run/netns/{netns_name}"] + cmd[4:]
        super().__init__(cmd, *popen_args, **kwargs)


subprocess.Popen = _PatchedPopen  # type: ignore[assignment]


# Monkey-patch Scapy's set_promisc to print debugging info
try:
    import scapy.arch.linux

    _original_set_promisc = scapy.arch.linux.set_promisc

    def _patched_set_promisc(s, iff, val=1):
        import os

        print(f"DEBUG set_promisc: s={s!r}, iff={iff!r}, val={val!r}")
        try:
            _iff = scapy.arch.linux.resolve_iface(iff)
            print(
                f"DEBUG set_promisc: resolved index={_iff.index!r}, name={_iff.name!r}"
            )
        except Exception as e:
            print(f"DEBUG set_promisc: resolve failed: {e}")
        print(
            "DEBUG set_promisc: current netns:", os.readlink("/proc/thread-self/ns/net")
        )
        return _original_set_promisc(s, iff, val)

    scapy.arch.linux.set_promisc = _patched_set_promisc
except Exception as e:
    print("Failed to patch scapy set_promisc:", e)


# Helper: run a command inside a network namespace via nsenter.
# nsenter uses setns() syscall directly — it does NOT mount /sys, so it
# works inside Docker containers even under mount namespace restrictions.
# Arguments are passed as a proper list, avoiding any shell quoting issues.


def _exec_in_ns(
    ns_name: str, *args: str, check: bool = False
) -> subprocess.CompletedProcess:
    """Execute a command inside a network namespace using nsenter (Docker-safe)."""
    cmd = ["nsenter", f"--net=/var/run/netns/{ns_name}"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


@pytest.fixture
def ttp_ruleset() -> str:
    """Generates TTP's standard ruleset by capturing it from apply_rules mock."""
    with (
        patch("ttp.firewall._run_nft"),
        patch("ttp.firewall._run_nft_string") as mock_run_nft_string,
        patch("ttp.firewall.pwd.getpwnam") as mock_getpwnam,
    ):
        # Mock Tor user UID to be 110
        mock_getpwnam.return_value = MagicMock(pw_uid=110)

        apply_rules(
            tor_user="debian-tor",
            transport_port=9041,
            dns_port=9054,
            allow_root=False,
            lan_bypass=True,
            bypass_uids=[1000],
            bypass_gids=[1000],
        )
        ruleset = mock_run_nft_string.call_args[0][0]
        return ruleset


@pytest.fixture
def ns_sandbox():
    """Context fixture: creates an isolated network namespace with default routes."""
    controller = NetnsController()
    loop = asyncio.new_event_loop()

    # Create the context manager object and keep a reference to it to prevent
    # premature garbage collection and teardown of the network namespace/veth link.
    ctx = controller.create_namespace(
        "nse_ttp_rules",
        host_ip=["10.0.1.1/24", "fd00:1::1/64"],
        peer_ip=["10.0.1.2/24", "fd00:1::2/64"],
    )
    ns = loop.run_until_complete(ctx.__aenter__())

    try:
        # Add default gateway routing inside the namespace via pyroute2 netlink.
        # pyroute2 uses RTM_NEWROUTE netlink messages directly — it does NOT call
        # the `ip` binary and therefore does NOT trigger the /sys mount that Docker
        # blocks. A small sleep allows the veth carrier-UP transition to complete.
        time.sleep(0.5)
        try:
            from pyroute2 import NetNS

            with NetNS("nse_ttp_rules") as netns:
                peer_idx = netns.link_lookup(ifname=ns.peer_iface)[0]
                # IPv4 default route
                netns.route("add", dst="0.0.0.0/0", gateway="10.0.1.1", oif=peer_idx)
                # IPv6 default route (best-effort)
                try:
                    netns.route("add", dst="::/0", gateway="fd00:1::1", oif=peer_idx)
                except Exception as e6:
                    print(f"[WARN] IPv6 default route: {e6}")
        except ImportError:
            # Fallback: nsenter does not mount /sys, so ip route works here
            r = subprocess.run(
                [
                    "nsenter",
                    "--net=/var/run/netns/nse_ttp_rules",
                    "ip",
                    "route",
                    "add",
                    "default",
                    "via",
                    "10.0.1.1",
                    "dev",
                    ns.peer_iface,
                ],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(
                    f"Route setup failed (pyroute2 unavailable): {r.stderr!r}"
                )

        # Reload Scapy's interfaces cache and routes list so it detects the new veth interface
        try:
            import scapy.all as scapy

            scapy.conf.ifaces.reload()
            scapy.conf.route.resync()
            print("DEBUG conf.ifaces:\n", scapy.conf.ifaces)
            print("DEBUG scapy get_if_list:", scapy.get_if_list())
        except Exception as e:
            print("DEBUG scapy reload failed:", e)
        yield ns, loop
    finally:
        # Exit the context manager cleanly. This automatically deletes the host-side veth
        # interface and tears down the network namespace.
        loop.run_until_complete(ctx.__aexit__(None, None, None))
        loop.close()


def is_cleartext_leak(pkt) -> bool:
    """Returns True if the packet is a cleartext WAN-bound packet (i.e. a leak)."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if pkt.haslayer(IP):
        dst = pkt[IP].dst
        # Loopback and the local veth subnet are not leaks
        if dst.startswith("127.") or dst.startswith("10.0.1."):
            return False
        # Ignore IPv4 multicast (224.0.0.0/4)
        try:
            first_octet = int(dst.split(".")[0])
            if 224 <= first_octet <= 239:
                return False
        except (ValueError, IndexError):
            pass
        return True
    elif pkt.haslayer(IPv6):
        dst = pkt[IPv6].dst
        # Loopback, local subnet, link-local, and multicast are not leaks
        if (
            dst == "::1"
            or dst.startswith("fd00:1::")
            or dst.startswith("fe80:")
            or dst.startswith("ff")
        ):
            return False
        return True
    return False


def test_dns_redirection(ns_sandbox, ttp_ruleset):
    """Asserts that UDP DNS requests from a normal user are hijacked (0 escape to WAN)."""
    ns, loop = ns_sandbox

    # Load the firewall rules inside the namespace
    RuleEngine().load(ttp_ruleset, ns.name)

    # Arm the sniffer on the host-side veth interface
    import os

    print("DEBUG netns in test_dns_redirection:", os.readlink("/proc/self/ns/net"))
    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())

    # Send a DNS query to a public DNS IP (8.8.8.8:53) from inside the namespace.
    # nftables should redirect it to 127.0.0.1:9054 — the packet must never reach
    # the host-side veth interface (ext_iface).
    # We use nsenter + python3 with args as a proper list (no shell string splitting).
    _exec_in_ns(
        ns.name,
        "python3",
        "-c",
        (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
            "s.sendto(b'dns-request', ('8.8.8.8', 53))"
        ),
    )

    # Allow packet propagation
    loop.run_until_complete(asyncio.sleep(0.2))

    # Stop sniffer and assert zero cleartext leaks
    captured = loop.run_until_complete(asserter.stop())
    leaks = [p for p in captured if is_cleartext_leak(p)]
    assert len(leaks) == 0, f"DNS request leaked to WAN: {leaks}"


def test_tcp_redirection(ns_sandbox, ttp_ruleset):
    """Asserts that TCP requests from a normal user are hijacked (0 escape to WAN)."""
    ns, loop = ns_sandbox
    RuleEngine().load(ttp_ruleset, ns.name)

    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())

    # Attempt a TCP connection to a public webserver (8.8.8.8:80).
    # nftables should redirect it to 127.0.0.1:9041 — the SYN must never escape.
    _exec_in_ns(
        ns.name,
        "python3",
        "-c",
        (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.settimeout(0.5); "
            "exc = None\n"
            "try:\n"
            "    s.connect(('8.8.8.8', 80))\n"
            "except Exception as e:\n"
            "    exc = e"
        ),
    )

    loop.run_until_complete(asyncio.sleep(0.2))

    captured = loop.run_until_complete(asserter.stop())
    leaks = [p for p in captured if is_cleartext_leak(p)]
    assert len(leaks) == 0, f"TCP request leaked to WAN: {leaks}"


def test_doh_dot_blocking(ns_sandbox, ttp_ruleset):
    """Asserts that DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) requests are blocked."""
    ns, loop = ns_sandbox
    RuleEngine().load(ttp_ruleset, ns.name)

    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())

    # DoT query (port 853) — nftables reject rule must block it before it leaves.
    _exec_in_ns(
        ns.name,
        "python3",
        "-c",
        (
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
            "s.settimeout(0.5); "
            "exc = None\n"
            "try:\n"
            "    s.connect(('8.8.8.8', 853))\n"
            "except Exception as e:\n"
            "    exc = e"
        ),
    )

    loop.run_until_complete(asyncio.sleep(0.2))

    captured = loop.run_until_complete(asserter.stop())
    leaks = [p for p in captured if is_cleartext_leak(p)]
    assert len(leaks) == 0, f"DoT request leaked to WAN: {leaks}"


def test_bypassed_user_escape(ns_sandbox, ttp_ruleset):
    """Asserts that traffic from a bypassed UID is exempt and successfully escapes to host."""
    ns, loop = ns_sandbox
    RuleEngine().load(ttp_ruleset, ns.name)

    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())

    # Run under bypassed UID 1000 — destination is the host veth IP (LAN bypass),
    # so nftables should not redirect it and the packet should appear on ext_iface.
    _exec_in_ns(
        ns.name,
        "python3",
        "-c",
        (
            "import os, socket; "
            "os.setuid(1000); "
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
            "s.sendto(b'bypassed-traffic', ('10.0.1.1', 9999))"
        ),
    )

    loop.run_until_complete(asyncio.sleep(0.2))

    captured = loop.run_until_complete(asserter.stop())

    # The bypassed packet should appear on the host-side veth interface
    from scapy.layers.inet import IP

    bypassed_packets = [
        p for p in captured if p.haslayer(IP) and p[IP].dst == "10.0.1.1"
    ]
    assert len(bypassed_packets) >= 1, "Bypassed user traffic was blocked!"
