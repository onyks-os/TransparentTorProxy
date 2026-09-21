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
import contextlib
import os
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from unittest.mock import MagicMock, patch

import pytest

# The classifier needs neither nse nor root, so it lives outside this module
# and is unit-tested on its own.
from tests.nse_classifier import canary_seen, is_cleartext_leak

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
    from nse.core.mock_listener import start_mock_listener
    from nse.core.netns_controller import NetnsController
    from nse.core.rule_engine import RuleEngine
    from nse.core.scapy_injector import _get_mac_address
    from nse.core.sniffer import PCAPAsserter
    from nse.core.trace_harvester import HarvestState, TraceHarvester

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

pytestmark = [pytest.mark.nse, pytest.mark.real_binary_lookup]

# Monkey-patch subprocess.run and subprocess.Popen to transparently convert
#   [resolve("ip"), "netns", "exec", <name>, ...]
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
    """
    Run a short Python program inside the namespace, optionally as another user.

    A stimulus that fails to *run* produces no packet, and a positive control
    that sees no packet reports a broken harness - true, but it does not say
    why. Raising here names the cause at the point it happens.

    A stimulus whose send is *refused* is a different thing entirely: with
    TTP's rules loaded, nftables answers a rejected packet with EPERM on the
    local socket, which is the firewall working. Each script therefore
    suppresses OSError around the send, so a non-zero exit means the probe
    could not run at all - no interpreter, a broken script - and never means
    the traffic was blocked.
    """
    prelude = f"import os; os.setuid({uid});\n" if uid is not None else ""
    result = _exec_in_ns(ns_name, "python3", "-c", prelude + script)
    if result.returncode != 0:
        raise RuntimeError(f"stimulus failed to run inside {ns_name}: {result.stderr.strip() or result.stdout.strip()}")


# ---------------------------------------------------------------------------
# Stimuli — each is a packet TTP promises never leaves the machine in cleartext
# ---------------------------------------------------------------------------


def udp_to(host: str, port: int, uid: int | None = None) -> Callable[[str], None]:
    """A UDP datagram to *host*:*port*."""

    def stimulus(ns_name: str) -> None:
        family = "AF_INET6" if ":" in host else "AF_INET"
        _python_in_ns(
            ns_name,
            "import socket, contextlib\n"
            f"s = socket.socket(socket.{family}, socket.SOCK_DGRAM)\n"
            "with contextlib.suppress(OSError):\n"
            f"    s.sendto(b'ttp-leak-probe', ({host!r}, {port}))\n",
            uid=uid,
        )

    return stimulus


def udp_roundtrip_to(host: str, port: int, uid: int | None = None) -> Callable[[str], None]:
    """A UDP datagram that also *waits* for the answer.

    ``udp_to`` proves egress only, which is weaker than the claim the bypass
    test makes: "must still get out" implies something is reachable. A bypass
    rule that lets packets out but breaks the return path satisfies egress and
    is still a broken proxy.
    """

    def stimulus(ns_name: str) -> None:
        family = "AF_INET6" if ":" in host else "AF_INET"
        _python_in_ns(
            ns_name,
            "import socket, contextlib\n"
            f"s = socket.socket(socket.{family}, socket.SOCK_DGRAM)\n"
            "s.settimeout(2.0)\n"
            "with contextlib.suppress(OSError):\n"
            f"    s.sendto(b'ttp-roundtrip-probe', ({host!r}, {port}))\n"
            "    s.recvfrom(64)\n",
            uid=uid,
        )

    return stimulus


@contextlib.contextmanager
def host_udp_echo(bind_ip: str, port: int) -> Iterator[None]:
    """A UDP echo server on the host side of the veth, for the duration."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, port))
    sock.settimeout(0.2)
    stop = threading.Event()

    def _serve() -> None:
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(64)
            except (TimeoutError, OSError):
                continue
            with contextlib.suppress(OSError):
                sock.sendto(b"ack:" + data[:16], peer)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()


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
    """
    An ICMP echo request, i.e. traffic Tor cannot carry at all.

    Built on a raw socket rather than by calling ``ping``. This used to shell
    out, and the Debian test image does not ship iputils-ping: the command
    failed silently, no packet was generated, and the positive control failed
    with "the instrument is not measuring" - which was true, and which is
    exactly what it is there to catch. Every other stimulus in this file already
    speaks to the kernel directly; this one now does too, so the suite depends
    on nothing but python3 inside the namespace.
    """

    def stimulus(ns_name: str) -> None:
        if ":" in host:
            # The kernel computes the checksum for raw ICMPv6 sockets.
            _python_in_ns(
                ns_name,
                "import socket, contextlib\n"
                "s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)\n"
                "echo = b'\\x80\\x00\\x00\\x00\\x00\\x01\\x00\\x01' + b'ttp-leak-probe'\n"
                "with contextlib.suppress(OSError):\n"
                f"    s.sendto(echo, ({host!r}, 0))\n",
            )
            return
        # For IPv4 it does not, so the probe computes its own.
        _python_in_ns(
            ns_name,
            "import socket, struct, contextlib\n"
            "def csum(data):\n"
            "    if len(data) % 2:\n"
            "        data += b'\\x00'\n"
            "    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))\n"
            "    total = (total >> 16) + (total & 0xffff)\n"
            "    total += total >> 16\n"
            "    return ~total & 0xffff\n"
            "payload = b'ttp-leak-probe'\n"
            "echo = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + payload\n"
            "echo = struct.pack('!BBHHH', 8, 0, csum(echo), 1, 1) + payload\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n"
            "with contextlib.suppress(OSError):\n"
            f"    s.sendto(echo, ({host!r}, 0))\n",
        )

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


#: The canary is UDP to the veth peer from a bypassed UID: traffic TTP is
#: configured to permit, so it is not itself a leak, and ``is_cleartext_leak``
#: already excludes 10.0.1.* so it cannot be miscounted as one.
CANARY_PORT = 9999


def canary_stimulus():  # type: ignore[no-untyped-def]
    """The stimulus whose arrival proves the capture window was open."""
    return udp_to(HOST_V4, CANARY_PORT, uid=1000)


def observe(ns, loop, stimulus, settle: float = 0.4) -> list:  # type: ignore[no-untyped-def]
    """Run *stimulus* with the sniffer armed on the host veth; return what it saw."""
    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())
    # Give AsyncSniffer's thread time to attach before generating traffic.
    loop.run_until_complete(asyncio.sleep(0.2))
    stimulus(ns.name)
    loop.run_until_complete(asyncio.sleep(settle))
    return loop.run_until_complete(asserter.stop())


def observe_with_canary(ns, loop, stimulus, settle: float = 0.4) -> list:  # type: ignore[no-untyped-def]
    """Fire *stimulus*, then the canary, inside **one** capture session.

    The positive control in ``assert_contained`` runs in its own capture, so it
    proves the instrument worked a moment ago and the containment assertion
    assumes it still does. A sniffer that failed to attach for the second
    capture -- a slow scheduler, a socket error swallowed inside AsyncSniffer's
    thread, the veth renumbered by the intervening rule load -- captures zero
    packets, which reads as containment.

    The canary closes that. It is emitted *after* the leak stimulus and inside
    the same session, so observing it proves the capture window was open across
    the whole of the leak stimulus rather than merely at some earlier time.
    """
    asserter = PCAPAsserter(iface=ns.ext_iface)
    loop.run_until_complete(asserter.start())
    loop.run_until_complete(asyncio.sleep(0.2))
    stimulus(ns.name)
    canary_stimulus()(ns.name)
    loop.run_until_complete(asyncio.sleep(settle))
    return loop.run_until_complete(asserter.stop())


#: Enables tracing for locally generated packets. See observe_trace.
_TRACE_LOCAL_EGRESS = """
table inet ttp_trace {
    chain out {
        type filter hook output priority -350; policy accept;
        meta nftrace set 1
    }
}
"""


def observe_trace(ns, loop, stimulus, settle: float = 1.0):  # type: ignore[no-untyped-def]
    """Run *stimulus* under ``nft monitor trace`` and return what the kernel said.

    Every other assertion in this file is about an **absence**: no cleartext
    packet appeared on the wire. An absence has many causes, and the canary
    only proves the *instrument* was working -- not *which rule* acted. A trace
    names the rule, so "the packet was DNAT'd to Tor's DNSPort" replaces
    "nothing showed up".

    Returns ``(saw_readiness_event, terminal_state, events)``. The first is the
    proof the monitor was really subscribed to the kernel's netlink group
    before the stimulus ran: ``wait_ready`` alone only proves this process is
    reading. Readiness traffic is discarded, so the events returned are the
    stimulus's own.
    """
    harvester = TraceHarvester()
    events: list = []

    # NSE's trace-init ruleset enables tracing in a *prerouting* chain, and a
    # locally generated packet never traverses prerouting -- it goes out
    # through output/postrouting. Without this, the only rule that ever
    # matches is nse's own `meta nftrace set 1`, from incoming traffic, and
    # every assertion about TTP's rules fails for a reason that has nothing to
    # do with TTP. Priority -350 puts it ahead of TTP's nat output (-150), so
    # the flag is set before any of TTP's chains are evaluated.
    _engine().load(_TRACE_LOCAL_EGRESS, ns.name)

    async def _run():  # type: ignore[no-untyped-def]
        queue: asyncio.Queue = asyncio.Queue()
        await harvester.start(
            netns_name=ns.name,
            queue=queue,
            timeout=20.0,
            use_nsenter=True,
            on_event=events.append,
        )
        try:
            await harvester.wait_ready(timeout=2.0)

            # Readiness: keep poking with the canary until a trace event comes
            # back. Until one does, the monitor may not be attached and any
            # silence that follows means nothing.
            ready = False
            for _ in range(5):
                harvester.arm_event_signal()
                harvester.extend_deadline(10.0)
                canary_stimulus()(ns.name)
                if await harvester.wait_for_event(timeout=1.0):
                    ready = True
                    break

            events.clear()  # the canary is the instrument, not the subject
            harvester.arm_event_signal()
            harvester.extend_deadline(10.0)
            stimulus(ns.name)
            await asyncio.sleep(settle)
        finally:
            state = await harvester.aclose()
        return ready, state

    ready, state = loop.run_until_complete(_run())
    return ready, state, list(events)


def assert_trace_usable(ready: bool, state, description: str) -> None:  # type: ignore[no-untyped-def]
    """Refuse to read a trace that the harvester cannot vouch for."""
    assert ready, (
        f"HARNESS FAILED for {description}: no trace event was ever observed "
        f"for the readiness canary, so `nft monitor trace` was not attached to "
        f"the kernel and the absence of a match below would mean nothing."
    )
    assert state in (HarvestState.CLEAN_EOF, HarvestState.STOPPED), (
        f"HARNESS FAILED for {description}: the trace monitor ended in state "
        f"{state!r} rather than a clean stop, so the event stream is truncated "
        f"and a missing match cannot be distinguished from a lost one."
    )


def _engine():
    """
    A RuleEngine that enters the namespace with ``nsenter``, not ``ip netns exec``.

    They differ in a way that matters here. ``ip netns exec`` unshares the mount
    namespace and remounts ``/sys`` so that ``/sys/class/net`` reflects the new
    namespace - which detaches every submount underneath it, ``/sys/fs/cgroup``
    included. TTP's ruleset carries

        socket cgroupv2 level 1 "ttp-bypass.slice" accept

    and nftables resolves that path at load time, so under ``ip netns exec`` the
    whole ruleset is rejected with "cgroupv2 path fails: No such file or
    directory" - not because the rule is wrong, but because the loader cannot
    see the cgroup hierarchy any more.

    ``nsenter --net`` changes only the network namespace, leaving mounts alone,
    which is also how TTP itself loads these rules in production.
    """
    return RuleEngine(use_nsenter=True)


def assert_contained(ns, loop, ruleset: str, stimulus, description: str) -> None:  # type: ignore[no-untyped-def]
    """
    Assert that TTP contains *stimulus*, having first proved the test can see it.

    Step 1 flushes the ruleset and requires the packet to reach the wire. If it
    does not, the harness is not measuring and the zero-leak assertion in step 2
    would pass for the wrong reason, so the test fails there instead.
    """
    engine = _engine()

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
    observed = observe_with_canary(ns, loop, stimulus)

    # The canary rides in this capture, not the previous one, so it speaks for
    # the window the assertion below is about. Check it first: "no leak" and
    # "no packets at all" look identical, and only one of them is containment.
    assert canary_seen(observed, HOST_V4, CANARY_PORT), (
        f"HARNESS FAILED for {description}: the canary ({HOST_V4}:{CANARY_PORT} "
        f"from a bypassed UID, which TTP is configured to permit) was not "
        f"observed in the same capture as the assertion "
        f"({len(observed)} packet(s) captured in total). The sniffer was not "
        f"measuring during this window, so the zero-leak assertion below would "
        f"pass for the wrong reason."
    )

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
# Attribution: which rule acted, not merely that nothing escaped
# ---------------------------------------------------------------------------


def _matched_rules(events) -> list[str]:  # type: ignore[no-untyped-def]
    """Rule texts from the trace, in the order the kernel reported them."""
    return [e.rule_text for e in events if e.type == "match" and e.rule_text and "nftrace" not in e.rule_text]


def test_dns_is_attributed_to_the_redirect_rule(ns_sandbox, ttp_ruleset) -> None:
    """The DNS query must be seen being DNAT'd, not merely seen not escaping.

    "No cleartext packet on the wire" is also what a missing route, a downed
    interface or a dropped packet look like. The trace says the redirect is
    what acted.
    """
    ns, loop = ns_sandbox
    _engine().load(ttp_ruleset, ns.name)

    ready, state, events = observe_trace(ns, loop, udp_to(WAN_V4, 53))
    assert_trace_usable(ready, state, "UDP DNS to 8.8.8.8:53")

    matched = _matched_rules(events)
    assert any("dnat" in text and "9054" in text for text in matched), (
        f"the DNS query was not attributed to the DNSPort redirect. Rules that matched: {matched or 'none'}"
    )


def test_tcp_is_attributed_to_the_transport_redirect(ns_sandbox, ttp_ruleset) -> None:
    """Ordinary web traffic must be seen entering Tor's TransPort."""
    ns, loop = ns_sandbox
    _engine().load(ttp_ruleset, ns.name)

    ready, state, events = observe_trace(ns, loop, tcp_to(WAN_V4, 80))
    assert_trace_usable(ready, state, "TCP to 8.8.8.8:80")

    matched = _matched_rules(events)
    assert any("dnat" in text and "9041" in text for text in matched), (
        f"the TCP connection was not attributed to the TransPort redirect. Rules that matched: {matched or 'none'}"
    )


def test_icmp_is_attributed_to_a_reject(ns_sandbox, ttp_ruleset) -> None:
    """Tor cannot carry ICMP, so the guillotine is what should stop it.

    This is the case where attribution matters most: an ICMP echo produces no
    redirect and no accept, so "nothing on the wire" is indistinguishable from
    "the stimulus never ran" -- which is the failure `icmp_to` hit once before,
    when it shelled out to a `ping` binary the test image did not ship.
    """
    ns, loop = ns_sandbox
    _engine().load(ttp_ruleset, ns.name)

    ready, state, events = observe_trace(ns, loop, icmp_to(WAN_V4))
    assert_trace_usable(ready, state, "ICMP echo to 8.8.8.8")

    # The rule text, not the verdict field: nft reports a reject by naming the
    # rule that matched, and leaves `verdict` as CONTINUE/ACCEPT/DROP for the
    # chain traversal around it.
    #
    # Two accepted forms, because the catch-all carries a named counter since
    # the counters landed and an exact match on "reject" broke the moment it
    # did. `cleartext_rejected` names that one rule and nothing else: the DoT
    # and DoH rejects carry `dot_rejected` and `doh_rejected`, so neither can
    # satisfy this assertion in the catch-all's place.
    matched = _matched_rules(events)
    assert any(text.strip() == "reject" or "cleartext_rejected" in text for text in matched), (
        f"the ICMP echo was not attributed to the catch-all reject. Rules that matched: {matched or 'none'}"
    )


# ---------------------------------------------------------------------------
# Competing rulesets
#
# Every other test here runs against a pristine nftables state: a fresh
# namespace with TTP's table and nothing else. No real machine looks like that
# -- a Fedora host has firewalld, an Ubuntu one ufw, anything with containers
# has Docker's chains -- and they all install base chains into the same hooks.
#
# #29 states the threat as "a competing chain at a lower priority number runs
# first and can accept a packet before TTP's chain ever sees it". These tests
# are what decides whether that is true. In nftables a verdict of `accept` is
# scoped to the chain that issued it: the packet continues to the next base
# chain at the same hook, and only `drop` is terminal across the hook. If that
# holds, a foreign `accept` cannot bypass TTP and the threat is narrower than
# stated. If it does not hold, these fail and the bypass is real.
#
# The fixtures are deliberately accept-only. A foreign ruleset that dropped
# would break the positive control and the canary, and the failure would read
# as a broken harness rather than as the answer to the question.
# ---------------------------------------------------------------------------

COMPETING_RULESETS = {
    # The direct form of the claim: an output base chain evaluated *before*
    # TTP's filter_out (priority filter = 0), accepting unconditionally.
    "accept_all_at_lower_priority": """
    table inet competitor {
        chain out {
            type filter hook output priority -300; policy accept;
            counter accept
        }
    }
    """,
    # Docker's shape: its own nat table with prerouting and output chains, at
    # the same dstnat priority TTP's redirect uses.
    "docker_like": """
    table ip docker_like {
        chain prerouting {
            type nat hook prerouting priority dstnat; policy accept;
            fib daddr type local counter accept
        }
        chain output {
            type nat hook output priority dstnat; policy accept;
            ip daddr != 127.0.0.0/8 fib daddr type local counter accept
        }
        chain postrouting {
            type nat hook postrouting priority srcnat; policy accept;
            counter accept
        }
    }
    """,
    # ufw/firewalld's shape: an inet filter table with its own output chain at
    # the standard filter priority, i.e. the same one TTP uses.
    "ufw_like": """
    table inet ufw_like {
        chain output {
            type filter hook output priority filter; policy accept;
            counter accept
        }
    }
    """,
}


@pytest.mark.parametrize("competitor", sorted(COMPETING_RULESETS))
def test_containment_holds_alongside_a_competing_ruleset(ns_sandbox, ttp_ruleset, competitor: str) -> None:
    """TTP must still contain cleartext with someone else's rules loaded too.

    The zero-leak claim is made about hosts, and hosts have other firewalls.
    Asserting it only against a pristine table makes the claim narrower than
    the README's, in a way no test name reveals.
    """
    ns, loop = ns_sandbox
    engine = _engine()

    engine.flush(ns.name)
    control = observe(ns, loop, udp_to(WAN_V4, 53))
    assert [p for p in control if is_cleartext_leak(p)], (
        f"POSITIVE CONTROL FAILED for {competitor}: with everything flushed the "
        f"sniffer saw no cleartext packet, so the assertion below would pass "
        f"for the wrong reason."
    )

    # Foreign rules first, TTP's second: the order an operator's host produces.
    engine.load(COMPETING_RULESETS[competitor], ns.name)
    engine.load(ttp_ruleset, ns.name)

    observed = observe_with_canary(ns, loop, udp_to(WAN_V4, 53))
    assert canary_seen(observed, HOST_V4, CANARY_PORT), (
        f"HARNESS FAILED for {competitor}: the canary was not observed in the "
        f"same capture as the assertion ({len(observed)} packet(s) captured)."
    )

    leaks = [p.summary() for p in observed if is_cleartext_leak(p)]
    assert not leaks, (
        f"DNS escaped to the WAN with the '{competitor}' ruleset loaded "
        f"alongside TTP's: {leaks}. A foreign base chain changed the outcome, "
        f"so TTP's containment is conditional on being the only firewall."
    )


# ---------------------------------------------------------------------------
# filter_forward: the forwarding plane
#
# Every other test in this file injects *from* the sandbox namespace, which
# only ever traverses `output`. The forward hook was reached by nothing, so
# `policy drop` in filter_forward -- a stated invariant, with a stated threat
# model of a VM or container routing through the host to escape the proxy --
# was asserted by no test at all.
#
# This builds the three-namespace shape that hook needs: host -> router ->
# server, with TTP's ruleset loaded on the *router*.
# ---------------------------------------------------------------------------

GATEWAY_ROUTER_NS = "nse_ttp_router"
GATEWAY_SERVER_NS = "nse_ttp_server"
GATEWAY_SERVER_V4 = "10.0.2.2"
GATEWAY_PORT = 9999


@pytest.fixture
def gateway_sandbox() -> Iterator[object]:
    """host <-> router <-> server, with a listener answering in the server."""
    controller = NetnsController()
    listener = None
    try:
        controller.create_gateway_topology(
            router_ns=GATEWAY_ROUTER_NS,
            server_ns=GATEWAY_SERVER_NS,
            veth_host="veth_ttp_gw",
            veth_router_host="veth_ttp_rh",
            veth_router_server="veth_ttp_rs",
            veth_server="veth_ttp_sv",
        )
        # Let the veth carriers come up before anything tries to route over them.
        time.sleep(0.5)
        listener = start_mock_listener(GATEWAY_SERVER_NS, "tcp", GATEWAY_PORT, host="0.0.0.0", use_nsenter=True)
        time.sleep(0.5)
        yield controller
    finally:
        if listener is not None:
            listener.terminate()
            with contextlib.suppress(Exception):
                listener.wait(timeout=5)
        with contextlib.suppress(Exception):
            controller.destroy_netns(GATEWAY_SERVER_NS)
        with contextlib.suppress(Exception):
            controller.destroy_netns(GATEWAY_ROUTER_NS)
        # The host-side veth and its transit route go with the pair.
        _original_subprocess_run(
            ["ip", "link", "del", "veth_ttp_gw"],
            capture_output=True,
            check=False,
            timeout=10,
        )


def _can_reach_the_server(timeout: float = 3.0) -> bool:
    """True if a TCP connection completes through the router."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((GATEWAY_SERVER_V4, GATEWAY_PORT))
        except OSError:
            return False
        return True


def test_forwarded_traffic_is_dropped(gateway_sandbox, ttp_ruleset) -> None:
    """A packet routed *through* the host must not reach the far side.

    This is the Docker/VM escape: a guest whose default route is the host can
    reach the WAN without ever traversing `output`, so none of the redirect or
    reject rules apply to it. filter_forward's `policy drop` is the only thing
    that stops it.

    Positive control first, as everywhere else in this file: with the router's
    ruleset flushed the connection must complete, or the topology -- not the
    firewall -- is what the assertion below would be measuring.
    """
    engine = _engine()

    engine.flush(GATEWAY_ROUTER_NS)
    assert _can_reach_the_server(), (
        "POSITIVE CONTROL FAILED: with the router's firewall flushed, a TCP "
        f"connection to {GATEWAY_SERVER_V4}:{GATEWAY_PORT} did not complete. "
        "Forwarding or the listener is broken, so the drop assertion below "
        "would pass for the wrong reason."
    )

    engine.load(ttp_ruleset, GATEWAY_ROUTER_NS)
    assert not _can_reach_the_server(), (
        f"Traffic forwarded through the host reached {GATEWAY_SERVER_V4}:"
        f"{GATEWAY_PORT} despite TTP's ruleset. filter_forward's policy drop "
        "is not containing the forwarding plane, which is the path a VM or "
        "container uses to escape the proxy."
    )


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
    _engine().load(ttp_ruleset, ns.name)

    captured = observe(ns, loop, udp_to(HOST_V4, 9999, uid=1000), settle=0.5)

    from scapy.layers.inet import IP

    passed_through = [p for p in captured if p.haslayer(IP) and p[IP].dst == HOST_V4]
    assert passed_through, (
        f"bypassed UID 1000 could not reach {HOST_V4}: TTP blocked traffic it is "
        f"configured to exempt. {len(captured)} packet(s) captured."
    )


def test_bypassed_user_traffic_gets_an_answer_back(ns_sandbox, ttp_ruleset) -> None:
    """Egress is not reachability: the reply has to come back too.

    The test above asserts a packet left. A bypass rule that lets packets out
    but breaks the return path satisfies that and is still a broken proxy --
    and nothing was listening, so nothing could ever have answered. This puts
    a real echo server on the host side of the veth and asserts the round trip.
    """
    ns, loop = ns_sandbox
    _engine().load(ttp_ruleset, ns.name)

    from scapy.layers.inet import IP, UDP

    with host_udp_echo(HOST_V4, CANARY_PORT):
        captured = observe(ns, loop, udp_roundtrip_to(HOST_V4, CANARY_PORT, uid=1000), settle=2.5)

    outbound = [
        p
        for p in captured
        if p.haslayer(IP) and p[IP].dst == HOST_V4 and p.haslayer(UDP) and p[UDP].dport == CANARY_PORT
    ]
    assert outbound, (
        f"bypassed UID 1000 could not reach {HOST_V4}:{CANARY_PORT}: TTP blocked "
        f"traffic it is configured to exempt. {len(captured)} packet(s) captured."
    )

    replies = [
        p
        for p in captured
        if p.haslayer(IP) and p[IP].src == HOST_V4 and p.haslayer(UDP) and p[UDP].sport == CANARY_PORT
    ]
    assert replies, (
        f"the request reached {HOST_V4}:{CANARY_PORT} but no reply came back. "
        f"The bypass is one-way: traffic leaves and the return path is blocked, "
        f"which is a broken proxy rather than an exempted one. "
        f"{len(captured)} packet(s) captured, {len(outbound)} outbound."
    )


def test_a_flushed_ruleset_leaks_everything(ns_sandbox) -> None:
    """
    The control, asserted on its own.

    If this test ever fails, every zero-leak assertion in this file is
    meaningless regardless of whether they pass, because the harness cannot
    observe a leak at all. It is deliberately the loudest failure in the module.
    """
    ns, loop = ns_sandbox
    _engine().flush(ns.name)

    captured = observe(ns, loop, udp_to(WAN_V4, 53))
    leaks = [p for p in captured if is_cleartext_leak(p)]
    assert leaks, (
        f"the harness cannot observe a leak even with NO firewall loaded. "
        f"Captured {len(captured)} packet(s) on {ns.ext_iface}. Every other "
        f"assertion in this module is vacuous until this passes."
    )
