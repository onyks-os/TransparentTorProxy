# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Zero-leak verification of TTP's nftables ruleset, using the Network Sandbox Engine.

TTP's strongest claim is that no cleartext packet escapes to the WAN. This module
is the evidence for it, so it is written to be evidence rather than reassurance.

Why every test runs twice
-------------------------

``assert len(leaks) == 0`` is true when the firewall works. It is *also* true
when the sniffer never started, when the interface name is wrong, when the BPF
filter excludes the traffic, or when the stimulus never left the process. An
assertion that passes for four wrong reasons and one right one is not a test.

So each containment test runs the same stimulus twice:

1. **Positive control** - with the ruleset flushed, the packet MUST be seen on
   the host-side veth. This proves the instrument works, this run, on this
   machine, for this exact traffic.
2. **The assertion** - with TTP's ruleset loaded, the packet must NOT be seen.

A failing control fails the test. "The sniffer saw nothing" can no longer be
mistaken for "the firewall blocked it".

Determinism
-----------

The sandbox installs permanent neighbour entries for the host veth addresses.
Without them the first packet of a run triggers an ARP/NDP resolution and is
dropped by the kernel while it waits - which the sniffer's ``not arp`` filter
hides, making the positive control fail intermittently for a reason that has
nothing to do with the firewall.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from collections.abc import Callable, Iterator
from unittest.mock import MagicMock, patch

import pytest

# Import TTP firewall dynamic rule builder
from ttp.firewall import apply_rules

# The `nse` extra is optional, so a plain dev install legitimately has no NSE and
# these tests skip. But a *silent* skip is how a suite stops running without
# anyone noticing - and `nse` is a short, generic import name that an unrelated
# PyPI package can shadow, turning "NSE is installed" into an ImportError that
# looks identical to "NSE is absent". `make test-nse` sets TTP_REQUIRE_NSE=1, so
# in the gate a missing or shadowed NSE is a hard error rather than a skip.
REQUIRE_NSE = os.environ.get("TTP_REQUIRE_NSE") == "1"

try:
    import nse
    from nse.core.netns_controller import NetnsController
    from nse.core.rule_engine import RuleEngine
    from nse.core.scapy_injector import _get_mac_address
    from nse.core.sniffer import PCAPAsserter

    NSE_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - environment-dependent
    NSE_IMPORT_ERROR = str(exc)

IS_ROOT = os.geteuid() == 0

#: Below this, the NSE runner could report PASSED having observed nothing and the
#: trace monitor could stop reading mid-run without saying so. Verdicts from an
#: older engine are not evidence, so refuse to produce them.
MIN_NSE_VERSION = (2, 1, 0)


def _nse_version() -> tuple[int, ...]:
    return tuple(int(part) for part in nse.__version__.split(".")[:3])


if NSE_IMPORT_ERROR is not None:
    message = f"NSE is not importable ({NSE_IMPORT_ERROR}); install `.[nse]`"
    if REQUIRE_NSE:
        raise RuntimeError(
            f"TTP_REQUIRE_NSE=1 but {message}. Refusing to skip the suite that proves the zero-leak claim."
        )
    pytest.skip(message, allow_module_level=True)

if not IS_ROOT:
    if REQUIRE_NSE:
        raise RuntimeError(
            "TTP_REQUIRE_NSE=1 but this process is not root. The NSE ruleset "
            "tests need network namespace privileges; run `sudo -E make test-nse`."
        )
    pytest.skip("NSE ruleset tests must be run as root", allow_module_level=True)

if _nse_version() < MIN_NSE_VERSION:
    raise RuntimeError(
        f"network-sandbox-engine {nse.__version__} is installed, but TTP requires "
        f">= {'.'.join(map(str, MIN_NSE_VERSION))}. Earlier versions could report a "
        f"clean result from an oracle that observed nothing, which would make this "
        f"suite green against an instrument that was not measuring."
    )

pytestmark = pytest.mark.nse

# Monkey-patch subprocess.run and subprocess.Popen to transparently convert
#   ["ip", "netns", "exec", <name>, ...]
# into
#   ["nsenter", "--net=/var/run/netns/<name>", ...]
#
# This is required because 'ip netns exec' internally mounts a private sysfs
# inside the target namespace, which Docker blocks even in --privileged mode.
# 'nsenter --net=...' uses setns() directly without any mount side-effects.
_original_subprocess_run = subprocess.run


def _patched_subprocess_run(*args, **kwargs):  # type: ignore[override]
    cmd = args[0] if args else kwargs.get("args")
    if isinstance(cmd, list) and len(cmd) >= 4 and cmd[0] == "ip" and cmd[1] == "netns" and cmd[2] == "exec":
        netns_name = cmd[3]
        new_cmd = ["nsenter", f"--net=/var/run/netns/{netns_name}", *cmd[4:]]
        if args:
            args = (new_cmd, *args[1:])
        else:
            kwargs["args"] = new_cmd
    return _original_subprocess_run(*args, **kwargs)


subprocess.run = _patched_subprocess_run  # type: ignore[assignment]

_original_popen = subprocess.Popen


class _PatchedPopen(_original_popen):  # type: ignore[misc]
    def __init__(self, cmd, *popen_args, **kwargs):
        if isinstance(cmd, list) and len(cmd) >= 4 and cmd[0] == "ip" and cmd[1] == "netns" and cmd[2] == "exec":
            netns_name = cmd[3]
            cmd = ["nsenter", f"--net=/var/run/netns/{netns_name}", *cmd[4:]]
        super().__init__(cmd, *popen_args, **kwargs)


subprocess.Popen = _PatchedPopen  # type: ignore[assignment]


HOST_V4 = "10.0.1.1"
HOST_V6 = "fd00:1::1"
PEER_V4 = "10.0.1.2"
PEER_V6 = "fd00:1::2"

#: Any address outside the veth subnet stands in for "the WAN".
WAN_V4 = "8.8.8.8"
WAN_V6 = "2001:4860:4860::8888"


def _exec_in_ns(ns_name: str, *args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Execute a command inside a network namespace using nsenter (Docker-safe)."""
    cmd = ["nsenter", f"--net=/var/run/netns/{ns_name}", *list(args)]
    return _original_subprocess_run(cmd, capture_output=True, text=True, check=check)


def _python_in_ns(ns_name: str, script: str, uid: int | None = None) -> None:
    """Run a short Python program inside the namespace, optionally as another user."""
    prelude = f"import os; os.setuid({uid});\n" if uid is not None else ""
    _exec_in_ns(ns_name, "python3", "-c", prelude + script)


# ---------------------------------------------------------------------------
# Stimuli — each is a packet TTP promises never leaves the machine in cleartext
# ---------------------------------------------------------------------------


def udp_to(host: str, port: int, uid: int | None = None) -> Callable[[str], None]:
    """A UDP datagram to *host*:*port*."""

    def stimulus(ns_name: str) -> None:
        family = "AF_INET6" if ":" in host else "AF_INET"
        _python_in_ns(
            ns_name,
            "import socket\n"
            f"s = socket.socket(socket.{family}, socket.SOCK_DGRAM)\n"
            f"s.sendto(b'ttp-leak-probe', ({host!r}, {port}))\n",
            uid=uid,
        )

    return stimulus


def tcp_to(host: str, port: int, uid: int | None = None) -> Callable[[str], None]:
    """A TCP connection attempt to *host*:*port* (the SYN is what matters)."""

    def stimulus(ns_name: str) -> None:
        family = "AF_INET6" if ":" in host else "AF_INET"
        _python_in_ns(
            ns_name,
            "import socket, contextlib\n"
            f"s = socket.socket(socket.{family}, socket.SOCK_STREAM)\n"
            "s.settimeout(0.5)\n"
            "with contextlib.suppress(OSError):\n"
            f"    s.connect(({host!r}, {port}))\n",
            uid=uid,
        )

    return stimulus


def icmp_to(host: str) -> Callable[[str], None]:
    """An ICMP echo request, i.e. traffic Tor cannot carry at all."""

    def stimulus(ns_name: str) -> None:
        flag = "-6" if ":" in host else "-4"
        _exec_in_ns(ns_name, "ping", flag, "-c", "1", "-W", "1", host)

    return stimulus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ttp_ruleset() -> str:
    """TTP's real ruleset, captured from the builder rather than hand-written."""
    with (
        patch("ttp.firewall.runner._run_nft"),
        patch("ttp.firewall.runner._run_nft_string") as mock_run_nft_string,
        patch("ttp.firewall.runner.pwd.getpwnam") as mock_getpwnam,
    ):
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
        return mock_run_nft_string.call_args[0][0]


@pytest.fixture
def ns_sandbox() -> Iterator[tuple[object, asyncio.AbstractEventLoop]]:
    """An isolated namespace with default routes and pre-resolved neighbours."""
    controller = NetnsController()
    loop = asyncio.new_event_loop()

    ctx = controller.create_namespace(
        "nse_ttp_rules",
        host_ip=[f"{HOST_V4}/24", f"{HOST_V6}/64"],
        peer_ip=[f"{PEER_V4}/24", f"{PEER_V6}/64"],
    )
    ns = loop.run_until_complete(ctx.__aenter__())

    try:
        # Let the veth carrier come up before configuring routes on it.
        time.sleep(0.5)
        _configure_namespace(ns)
        _reload_scapy_interfaces()
        yield ns, loop
    finally:
        loop.run_until_complete(ctx.__aexit__(None, None, None))
        loop.close()


def _configure_namespace(ns) -> None:  # type: ignore[no-untyped-def]
    """Default routes plus permanent neighbour entries, so no packet waits on ARP."""
    host_mac = _get_mac_address(ns.ext_iface)

    # Permanent neighbour entries. Without them the kernel holds the first packet
    # of each stimulus while it resolves the gateway, and the positive control
    # sees nothing for a reason unrelated to the firewall.
    for addr, family in ((HOST_V4, "-4"), (HOST_V6, "-6")):
        _exec_in_ns(
            ns.name,
            "ip",
            family,
            "neigh",
            "replace",
            addr,
            "lladdr",
            host_mac,
            "nud",
            "permanent",
            "dev",
            ns.peer_iface,
        )

    result = _exec_in_ns(ns.name, "ip", "route", "replace", "default", "via", HOST_V4, "dev", ns.peer_iface)
    if result.returncode != 0:
        raise RuntimeError(f"IPv4 default route setup failed: {result.stderr!r}")

    # IPv6 is best-effort: a runner without IPv6 must not fail the IPv4 tests.
    _exec_in_ns(ns.name, "ip", "-6", "route", "replace", "default", "via", HOST_V6, "dev", ns.peer_iface)


def _reload_scapy_interfaces() -> None:
    """Make Scapy notice the veth that appeared after it was imported."""
    import scapy.all as scapy

    scapy.conf.ifaces.reload()
    scapy.conf.route.resync()


def has_ipv6(ns) -> bool:  # type: ignore[no-untyped-def]
    """True when the namespace has a usable IPv6 default route."""
    result = _exec_in_ns(ns.name, "ip", "-6", "route", "show", "default")
    return result.returncode == 0 and bool(result.stdout.strip())


# ---------------------------------------------------------------------------
# The instrument
# ---------------------------------------------------------------------------


def is_cleartext_leak(pkt) -> bool:  # type: ignore[no-untyped-def]
    """True if *pkt* is a WAN-bound cleartext packet, i.e. a leak."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if pkt.haslayer(IP):
        dst = pkt[IP].dst
        if dst.startswith(("127.", "10.0.1.")):
            return False
        try:
            first_octet = int(dst.split(".")[0])
            if 224 <= first_octet <= 239:  # multicast
                return False
        except (ValueError, IndexError):
            pass
        return True
    if pkt.haslayer(IPv6):
        dst = pkt[IPv6].dst
        return not (dst == "::1" or dst.startswith(("fd00:1::", "fe80:", "ff")))
    return False


def observe(ns, loop, stimulus, settle: float = 0.4) -> list:  # type: ignore[no-untyped-def]
    """Run *stimulus* with the sniffer armed on the host veth; return what it saw."""
    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())
    # Give AsyncSniffer's thread time to attach before generating traffic.
    loop.run_until_complete(asyncio.sleep(0.2))
    stimulus(ns.name)
    loop.run_until_complete(asyncio.sleep(settle))
    return loop.run_until_complete(asserter.stop())


def assert_contained(ns, loop, ruleset: str, stimulus, description: str) -> None:  # type: ignore[no-untyped-def]
    """
    Assert that TTP contains *stimulus*, having first proved the test can see it.

    Step 1 flushes the ruleset and requires the packet to reach the wire. If it
    does not, the harness is not measuring and the zero-leak assertion in step 2
    would pass for the wrong reason, so the test fails there instead.
    """
    engine = RuleEngine()

    engine.flush(ns.name)
    control = observe(ns, loop, stimulus)
    control_leaks = [p for p in control if is_cleartext_leak(p)]
    assert control_leaks, (
        f"POSITIVE CONTROL FAILED for {description}: with the firewall flushed, the "
        f"sniffer on {ns.ext_iface} observed no cleartext packet "
        f"({len(control)} packet(s) captured in total). The instrument is not "
        f"measuring, so the zero-leak assertion below would pass for the wrong "
        f"reason. Fix the harness before trusting any result in this file."
    )

    engine.load(ruleset, ns.name)
    observed = observe(ns, loop, stimulus)
    leaks = [p.summary() for p in observed if is_cleartext_leak(p)]
    assert not leaks, f"{description} LEAKED to the WAN despite TTP's ruleset: {leaks}"


# ---------------------------------------------------------------------------
# Containment tests
# ---------------------------------------------------------------------------


def test_dns_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """Plain DNS must be redirected to Tor's DNSPort, never reaching the WAN."""
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, udp_to(WAN_V4, 53), "UDP DNS to 8.8.8.8:53")


def test_dns_over_tcp_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """TCP/53 is a DNS path too, and the ruleset redirects it separately."""
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, tcp_to(WAN_V4, 53), "TCP DNS to 8.8.8.8:53")


def test_tcp_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """Ordinary web traffic must be redirected to Tor's TransPort."""
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, tcp_to(WAN_V4, 80), "TCP to 8.8.8.8:80")


def test_dot_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """DNS-over-TLS on 853 is rejected outright rather than proxied."""
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, tcp_to(WAN_V4, 853), "DoT to 8.8.8.8:853")


def test_quic_doh_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """
    QUIC DoH is the gap NAT cannot close: UDP/443 is not redirected to Tor, so
    the reject rule in filter_out is the only thing stopping it. 8.8.8.8 is in
    the ruleset's DoH address set.
    """
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, udp_to(WAN_V4, 443), "QUIC DoH to 8.8.8.8:443")


def test_icmp_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """Tor cannot carry ICMP, so it must be rejected rather than passed through."""
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, icmp_to(WAN_V4), "ICMP echo to 8.8.8.8")


def test_arbitrary_udp_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """The catch-all reject: UDP that is neither DNS nor QUiC DoH still must not leave."""
    ns, loop = ns_sandbox
    assert_contained(ns, loop, ttp_ruleset, udp_to(WAN_V4, 4242), "UDP to 8.8.8.8:4242")


def test_ipv6_is_not_allowed_to_escape(ns_sandbox, ttp_ruleset) -> None:
    """IPv6 is the classic leak path when a proxy only reasons about IPv4."""
    ns, loop = ns_sandbox
    if not has_ipv6(ns):
        pytest.skip("no IPv6 default route in this sandbox")
    assert_contained(ns, loop, ttp_ruleset, tcp_to(WAN_V6, 80), "IPv6 TCP to the WAN")


# ---------------------------------------------------------------------------
# The other direction: bypassed traffic must still work
# ---------------------------------------------------------------------------


def test_bypassed_user_traffic_still_reaches_the_lan(ns_sandbox, ttp_ruleset) -> None:
    """
    A firewall that blocks everything passes every containment test above. This
    is the test that says TTP is a proxy and not a brick: traffic from a
    bypassed UID to a LAN address must still get out.
    """
    ns, loop = ns_sandbox
    RuleEngine().load(ttp_ruleset, ns.name)

    captured = observe(ns, loop, udp_to(HOST_V4, 9999, uid=1000), settle=0.5)

    from scapy.layers.inet import IP

    passed_through = [p for p in captured if p.haslayer(IP) and p[IP].dst == HOST_V4]
    assert passed_through, (
        f"bypassed UID 1000 could not reach {HOST_V4}: TTP blocked traffic it is "
        f"configured to exempt. {len(captured)} packet(s) captured."
    )


def test_a_flushed_ruleset_leaks_everything(ns_sandbox) -> None:
    """
    The control, asserted on its own.

    If this test ever fails, every zero-leak assertion in this file is
    meaningless regardless of whether they pass, because the harness cannot
    observe a leak at all. It is deliberately the loudest failure in the module.
    """
    ns, loop = ns_sandbox
    RuleEngine().flush(ns.name)

    captured = observe(ns, loop, udp_to(WAN_V4, 53))
    leaks = [p for p in captured if is_cleartext_leak(p)]
    assert leaks, (
        f"the harness cannot observe a leak even with NO firewall loaded. "
        f"Captured {len(captured)} packet(s) on {ns.ext_iface}. Every other "
        f"assertion in this module is vacuous until this passes."
    )
