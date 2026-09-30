#!/usr/bin/env python3
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Chaos Monkey Watchdog Stress Testing Script.

Injects system failures (Tor daemon crash, DNS unmount, firewall flush,
firewall destroy, network link flap) and asserts that the TTP watchdog
auto-heals the system or applies the emergency killswitch, preventing any
cleartext network leaks.

Why the sweep is not random
---------------------------

It used to be. ``random.choice`` at every interval meant a 60s run at 12s
intervals exercised roughly four of the five faults, picked by chance, and no
two runs covered the same ground. A regression in the unlucky fault shipped,
and "the chaos monkey passed" said more about luck than about the watchdog.

The run now sweeps every fault in ``INJECTIONS`` once, in order, and
``--injection`` reproduces a single one. ``--duration`` is a cap rather than a
schedule: a sweep that runs out of budget has left faults untried, and
``verdict`` refuses to call that a pass - the same rule the audit oracle
follows, one level up.

Why the audit has three answers
-------------------------------

The audit used to return a bool, and every path that could not measure returned
``True`` - "no leak". A failed subprocess, a raised exception, and a missing
baseline IP all reported the same thing as a genuinely contained host. The
summary then printed "Watchdog successfully protected the environment with zero
leaks" on the strength of measurements that never happened.

The missing baseline was the sharpest case. ``get_real_public_ip`` returns
``None`` when it cannot reach the detection service, and the leak test is
``current_ip == real_ip``. With ``real_ip`` at ``None`` that comparison is false
for every possible answer, so a real cleartext leak was scored as "successfully
proxied through Tor". The run could not fail.

So the audit now reports :class:`AuditResult`, and ``INCONCLUSIVE`` is a
failure of the run, not a pass. The child process is also made to exit ``0``
whether the request succeeds or is blocked, which leaves a non-zero exit meaning
only one thing: the harness itself broke. That is what separates "the killswitch
worked" from "the audit never ran", which a bare exit code cannot.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from enum import Enum
from pathlib import Path

# Ensure the virtual environment's bin directory is at the front of PATH,
# so that the development version of "ttp" is executed rather than any system-wide one.
project_root = Path(__file__).resolve().parent.parent
dev_bin_dir = project_root / "venv" / "bin"
path_dirs = []
if dev_bin_dir.exists():
    path_dirs.append(str(dev_bin_dir))
sys_bin = Path(sys.executable).parent
if sys_bin.exists():
    path_dirs.append(str(sys_bin))

for d in reversed(path_dirs):
    if d not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{d}{os.pathsep}{os.environ.get('PATH', '')}"

TEST_USER = "ttp-chaos-test"
#: Bypassed at `ttp start`, so its audit must see this host's own address. It is
#: the positive control for TEST_USER's audit, in the same pass (see judge_pass).
CANARY_USER = "ttp-chaos-canary"


class AuditResult(str, Enum):
    """What one audit proved. ``INCONCLUSIVE`` is red, not green."""

    CONTAINED = "contained"
    LEAK = "leak"
    INCONCLUSIVE = "inconclusive"


def require_root() -> None:
    """Refuse to run unprivileged.

    Kept out of module scope so the module can be imported and unit-tested; at
    import time this was an unconditional ``sys.exit`` that no test could get
    past, which is why none of the logic below had any coverage.
    """
    if os.geteuid() != 0:
        print("[ERROR] Chaos Monkey must be run as root (sudo).", file=sys.stderr)
        sys.exit(1)


def get_real_public_ip() -> str | None:
    """Detect host's real unproxied public IP before starting TTP."""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "ttp-chaos-monkey"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            ip = resp.read().decode().strip()
            print(f"[INFO] Real public IP detected: {ip}")
            return ip
    except Exception as e:
        print(f"[WARNING] Could not detect real public IP: {e}")
        return None


def setup_test_user():
    """Create the audited user and the canary, both unprivileged and fresh."""
    cleanup_test_user()
    for user in (TEST_USER, CANARY_USER):
        print(f"[INFO] Creating temporary test user: {user}")
        subprocess.run(["useradd", "-m", user], check=True, capture_output=True)


def cleanup_test_user():
    """Delete both temporary users and their home directories."""
    for user in (TEST_USER, CANARY_USER):
        print(f"[INFO] Cleaning up test user: {user}")
        subprocess.run(["userdel", "-r", user], capture_output=True)


def ttp_start_command(bypass: bool = True) -> list[str]:
    """The session under test: watchdog on, the canary bypassed unless *bypass* is off; TEST_USER never."""
    argv = ["ttp", "start", "--watchdog", "--bootstrap-timeout", "300"]
    return [*argv, "--bypass-user", CANARY_USER] if bypass else argv


def is_killswitch_table(nft_listing: str) -> bool:
    """True if `nft list table inet ttp` shows the emergency killswitch.

    Only apply_emergency_killswitch() installs an input chain in `inet ttp`, so
    its presence is what distinguishes "everything is blocked on purpose" from a
    session table - read from the kernel, not inferred from the watchdog's logs.
    """
    return "chain filter_input" in nft_listing


def killswitch_engaged() -> bool:
    res = subprocess.run(["nft", "list", "table", "inet", "ttp"], capture_output=True, text=True)
    return res.returncode == 0 and is_killswitch_table(res.stdout)


def judge_pass_without_canary(containment: AuditResult, control: AuditResult) -> tuple[AuditResult, str]:
    """What a pass proved when no user is bypassed.

    A bypass adds a rule the watchdog checks for, so the canary changes the
    session it observes: with it configured, a flushed table was caught for a
    reason a normal session does not have (#80). Without it, the positive
    control is *control*: the audited user's own audit taken before `ttp start`,
    which must have seen this host. Weaker than a same-pass canary - it shows the
    audit could see a leak on this host shortly before, not at this moment.
    """
    if containment is AuditResult.LEAK:
        return AuditResult.LEAK, "the audited user reached the WAN as this host"
    if containment is AuditResult.INCONCLUSIVE:
        return AuditResult.INCONCLUSIVE, "the audited user's check could not measure"
    if control is AuditResult.LEAK:
        return AuditResult.CONTAINED, "held, and before this session the same audit saw this host"
    return AuditResult.INCONCLUSIVE, "before the session the audit did not see this host, so it could not show a leak"


def watchdog_stays_active(timeout: float = 20.0) -> bool:
    """True once ttp-watchdog.service is active, and still active 3 s later.

    `ttp start --watchdog` only prints an error when the watchdog fails, and a
    unit that dies at once (226/NAMESPACE, when its sandbox could not be built)
    shows "activating" or even "active" between restarts. Without this check
    the sweep ran with no watchdog at all and reported the first fault only
    the watchdog can contain as a leak - true, but not the defect.
    """
    deadline = time.monotonic() + timeout
    confirmed_at: float | None = None
    while time.monotonic() < deadline:
        state = subprocess.run(
            ["systemctl", "is-active", "ttp-watchdog"], capture_output=True, text=True
        ).stdout.strip()
        if state != "active":
            confirmed_at = None
        elif confirmed_at is None:
            confirmed_at = time.monotonic()
        elif time.monotonic() - confirmed_at >= 3:
            return True
        time.sleep(1)
    return False


def start_session(real_ip: str, targets: tuple[str, str], bypass: bool) -> AuditResult:
    """Start a session and return the positive control its audits are judged against.

    With the canary, it is the canary's audits after `ttp start`; without it, the
    audited user's own audits before. Both TCP and UDP must have seen this host,
    since each is a channel a leak could be reported on. Raises if the session
    does not start: a trial with no session under it would measure nothing.
    """
    control = AuditResult.INCONCLUSIVE
    if not bypass:
        control = all_leaked(*audit_both(real_ip, TEST_USER, targets, "control"))
    res = subprocess.run(ttp_start_command(bypass), capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"ttp start failed ({res.returncode}): {res.stderr.strip()}")
    if not watchdog_stays_active():
        raise RuntimeError(
            "ttp-watchdog.service is not running after `ttp start --watchdog`; "
            "a sweep without it would measure the ruleset alone"
        )
    if bypass:
        control = all_leaked(*audit_both(real_ip, CANARY_USER, targets, "canary"))
    return control


def judge_pass(containment: AuditResult, canary: AuditResult, killswitch: bool) -> tuple[AuditResult, str]:
    """Combine one pass's two audits into what the pass proved.

    A leak on the audited user is a leak whatever else happened. Otherwise the
    pass is CONTAINED only if the canary - traffic TTP lets out - came back as a
    leak in the same pass, which shows this audit could report one right now;
    or if the killswitch is engaged, since it blocks bypassed traffic by design
    and a blocked canary is then the expected answer. Anything else is a pass
    whose "no leak" could not have been anything else.
    """
    if containment is AuditResult.LEAK:
        return AuditResult.LEAK, "the audited user reached the WAN as this host"
    if containment is AuditResult.INCONCLUSIVE:
        return AuditResult.INCONCLUSIVE, "the audited user's check could not measure"
    if canary is AuditResult.LEAK:
        return AuditResult.CONTAINED, "held, and the canary proved in the same pass that a leak would have shown"
    if canary is AuditResult.CONTAINED and killswitch:
        return AuditResult.CONTAINED, "held under the emergency killswitch, which blocks the canary too by design"
    if canary is AuditResult.CONTAINED:
        return (
            AuditResult.INCONCLUSIVE,
            "the bypassed canary was blocked with no killswitch engaged: this audit could not see a leak",
        )
    return AuditResult.INCONCLUSIVE, "the canary's check could not measure"


def get_active_interface() -> str | None:
    """Determine the active default gateway network interface."""
    try:
        res = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    return None


#: The IP echo the audits ask. Its address is resolved once, before `ttp start`
#: (resolve_audit_target), and the child connects to that address with TLS
#: verified against this name. Resolving it in the child went through TTP's DNS,
#: i.e. through Tor, so with Tor down every audit - the bypassed canary's
#: included - failed on the name, and "contained" measured DNS, not the firewall.
AUDIT_HOST = "api.ipify.org"

#: Run in the child so that a blocked request and a successful one both exit 0.
#: A non-zero exit then means the harness broke, which is a different fact from
#: "the killswitch held" and must not be scored as one. argv: <address> <name>.
_AUDIT_SCRIPT = (
    "import socket, ssl, sys\n"
    "addr, name = sys.argv[1], sys.argv[2]\n"
    "try:\n"
    "    with socket.create_connection((addr, 443), timeout=3) as raw:\n"
    "        with ssl.create_default_context().wrap_socket(raw, server_hostname=name) as tls:\n"
    "            tls.sendall(('GET / HTTP/1.0\\r\\nHost: ' + name + '\\r\\n"
    "User-Agent: ttp-chaos-audit\\r\\n\\r\\n').encode())\n"
    "            reply = b''\n"
    "            while chunk := tls.recv(4096):\n"
    "                reply += chunk\n"
    "    print('OK ' + reply.split(b'\\r\\n\\r\\n', 1)[-1].decode().strip())\n"
    "except OSError as exc:\n"
    "    print('NETFAIL ' + type(exc).__name__)\n"
)


#: A STUN server answers a binding request with the address the datagram came
#: from, which makes it the UDP counterpart of the IP echo. The TCP audit alone
#: cannot see a UDP leak: TTP's `nat output` sends TCP to Tor whatever
#: filter_out does, so a fault that only opens filter_out - an inserted accept,
#: a deleted catch-all - lets UDP out while every TCP audit still reads "held".
STUN_HOSTS = ("stun.l.google.com", "stun1.l.google.com", "stun.cloudflare.com")
STUN_PORT = 19302

#: argv: <address> <port>. Prints "OK <mapped address>" or "NETFAIL <error>",
#: the same shapes as _AUDIT_SCRIPT, so classify_audit reads both.
_UDP_AUDIT_SCRIPT = (
    "import socket, struct, sys\n"
    "addr, port = sys.argv[1], int(sys.argv[2])\n"
    "request = b'\\x00\\x01\\x00\\x00\\x21\\x12\\xa4\\x42' + bytes(12)\n"
    "try:\n"
    "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "    s.settimeout(3)\n"
    "    s.sendto(request, (addr, port))\n"
    "    data, _ = s.recvfrom(2048)\n"
    "    i, mapped = 20, None\n"
    "    while i + 4 <= len(data) and mapped is None:\n"
    "        kind, size = struct.unpack('!HH', data[i:i + 4])\n"
    "        value = data[i + 4:i + 4 + size]\n"
    "        if kind == 0x0020 and len(value) >= 8 and value[1] == 1:\n"
    "            mapped = socket.inet_ntoa(bytes(b ^ m for b, m in zip(value[4:8], b'\\x21\\x12\\xa4\\x42')))\n"
    "        i += 4 + size + (-size % 4)\n"
    "    print('OK ' + (mapped or 'no-mapped-address'))\n"
    "except OSError as exc:\n"
    "    print('NETFAIL ' + type(exc).__name__)\n"
)


def resolve_stun_target() -> str | None:
    """The IPv4 address of the first STUN server that resolves, before TTP owns DNS."""
    for host in STUN_HOSTS:
        try:
            infos = socket.getaddrinfo(host, STUN_PORT, socket.AF_INET, socket.SOCK_DGRAM)
        except OSError:
            continue
        if infos:
            return str(infos[0][4][0])
    print(f"[WARNING] None of {', '.join(STUN_HOSTS)} resolved")
    return None


def resolve_audit_target() -> str | None:
    """The IPv4 address of AUDIT_HOST, looked up before TTP owns this host's DNS."""
    try:
        infos = socket.getaddrinfo(AUDIT_HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        print(f"[WARNING] Could not resolve {AUDIT_HOST}: {exc}")
        return None
    return str(infos[0][4][0]) if infos else None


def classify_audit(real_ip: str | None, returncode: int, stdout: str) -> tuple[AuditResult, str]:
    """Decide what one audit run proved, from its output alone."""
    if real_ip is None:
        return (
            AuditResult.INCONCLUSIVE,
            "no baseline public IP was detected, so no answer can be compared against one",
        )
    if returncode != 0:
        return (
            AuditResult.INCONCLUSIVE,
            f"the audit child exited {returncode} without reporting: it did not run",
        )

    head, _, rest = stdout.strip().partition(" ")
    if head == "NETFAIL":
        return AuditResult.CONTAINED, f"the request was refused or dropped ({rest or 'unknown'})"
    if head != "OK":
        return AuditResult.INCONCLUSIVE, f"unrecognised audit output {stdout.strip()!r}"

    current_ip = rest.strip()
    try:
        ipaddress.ip_address(current_ip)
    except ValueError:
        return AuditResult.INCONCLUSIVE, f"the service answered with something that is not an IP: {current_ip!r}"

    if current_ip == real_ip:
        return AuditResult.LEAK, f"the WAN saw this host's own address {current_ip}, so traffic bypassed Tor"
    return AuditResult.CONTAINED, f"the WAN saw {current_ip}, not this host's {real_ip}"


def _report(result: AuditResult, reason: str, user: str, role: str, proto: str) -> None:
    if role in ("canary", "control"):
        # A positive control is expected to reach the WAN: that is its job.
        tag = role.upper()
        label = {
            AuditResult.LEAK: f"[{tag}] reached the WAN as this host, as it should",
            AuditResult.CONTAINED: f"[{tag}] blocked",
            AuditResult.INCONCLUSIVE: f"[{tag}] could not measure",
        }[result]
    else:
        label = {
            AuditResult.CONTAINED: "[AUDIT] CONTAINED",
            AuditResult.LEAK: "[ALERT] CRITICAL NET LEAK DETECTED",
            AuditResult.INCONCLUSIVE: "[ALERT] AUDIT INCONCLUSIVE",
        }[result]
    print(f"{label} ({user}, {proto}): {reason}")


def _run_child(real_ip: str, user: str, argv: list[str]) -> tuple[AuditResult, str]:
    try:
        res = subprocess.run(["python3", "-c", *argv], capture_output=True, text=True, user=user)
    except OSError as exc:
        return AuditResult.INCONCLUSIVE, f"the audit could not be launched at all: {exc!r}"
    return classify_audit(real_ip, res.returncode, res.stdout)


def run_connectivity_audit(
    real_ip: str | None, user: str = TEST_USER, target: str | None = None, role: str = "audited"
) -> AuditResult:
    """Ask, over TCP, what the WAN sees as *user*; report honestly when the question went unanswered."""
    if real_ip is None:
        result, reason = classify_audit(real_ip, 0, "")
    elif target is None:
        result, reason = AuditResult.INCONCLUSIVE, f"no address for {AUDIT_HOST} was resolved before the session"
    else:
        result, reason = _run_child(real_ip, user, [_AUDIT_SCRIPT, target, AUDIT_HOST])
    _report(result, reason, user, role, "tcp")
    return result


def run_udp_audit(real_ip: str | None, user: str, stun: str | None, role: str = "audited") -> AuditResult:
    """Ask a STUN server, over UDP, what address *user*'s datagram came from."""
    if real_ip is None:
        result, reason = classify_audit(real_ip, 0, "")
    elif stun is None:
        result, reason = AuditResult.INCONCLUSIVE, "no STUN server was resolved before the session"
    else:
        result, reason = _run_child(real_ip, user, [_UDP_AUDIT_SCRIPT, stun, str(STUN_PORT)])
    _report(result, reason, user, role, "udp")
    return result


def worst(*results: AuditResult) -> AuditResult:
    """The audited user's verdict over several channels: one leak is a leak."""
    if AuditResult.LEAK in results:
        return AuditResult.LEAK
    if AuditResult.INCONCLUSIVE in results:
        return AuditResult.INCONCLUSIVE
    return AuditResult.CONTAINED


def all_leaked(*results: AuditResult) -> AuditResult:
    """A positive control over several channels: every channel must have seen this host."""
    if all(r is AuditResult.LEAK for r in results):
        return AuditResult.LEAK
    if AuditResult.INCONCLUSIVE in results:
        return AuditResult.INCONCLUSIVE
    return AuditResult.CONTAINED


def audit_both(real_ip: str, user: str, targets: tuple[str, str], role: str) -> tuple[AuditResult, AuditResult]:
    """The TCP and the UDP audit for *user*; targets is (echo address, STUN address)."""
    return (
        run_connectivity_audit(real_ip, user, targets[0], role),
        run_udp_audit(real_ip, user, targets[1], role),
    )


def inject_kill_tor():
    print("[CHAOS] Injecting Failure: Terminating Tor process...")
    # Stop ttp-tor systemd service to trigger Tor failure
    subprocess.run(["systemctl", "stop", "ttp-tor"], check=True)


def parse_main_pid(systemctl_output: str) -> int | None:
    """The unit's MainPID, or None when there is no process to signal.

    systemd writes ``MainPID=0`` for a unit that is not running, and that zero
    reaching ``kill`` would signal every process in the caller's group instead
    of Tor. Anything that is not a plain positive integer is therefore read as
    "no PID" rather than passed along.
    """
    for line in systemctl_output.splitlines():
        key, _, value = line.partition("=")
        if key.strip() != "MainPID":
            continue
        try:
            pid = int(value.strip())
        except ValueError:
            return None
        return pid if pid > 0 else None
    return None


def inject_sigkill_tor():
    """Kill Tor with SIGKILL, without telling systemd.

    ``inject_kill_tor`` stops the unit, which is orderly: systemd is the one
    ending it, the unit goes ``inactive``, and Tor is given a chance to exit.
    A SIGKILL is the failure that actually happens to people - an OOM kill, a
    crash - and it leaves a different state behind. The unit lands in
    ``failed`` rather than ``inactive``, and ``ttp-tor`` is ``Restart=no``, so
    nothing brings Tor back. That is a different signal for the watchdog to
    notice, and #30 lists it as untested.

    Raises:
        RuntimeError: If the unit reports no running process. A fault that
            silently did nothing would still be counted as a fault that was
            injected, which is the same defect as an audit that cannot measure
            reporting success.
    """
    print("[CHAOS] Injecting Failure: SIGKILL to the Tor process, behind systemd's back...")
    shown = subprocess.run(
        ["systemctl", "show", "ttp-tor", "-p", "MainPID"],
        capture_output=True,
        text=True,
        check=False,
    )
    pid = parse_main_pid(shown.stdout)
    if pid is None:
        raise RuntimeError(f"cannot SIGKILL Tor: no running Tor process to signal ({shown.stdout.strip()!r})")
    subprocess.run(["kill", "-KILL", str(pid)], check=True)


def inject_insert_accept():
    """An `accept` at the top of filter_out: the table keeps every chain and stops rejecting."""
    print("[CHAOS] Injecting Failure: accept inserted at the top of filter_out...")
    subprocess.run(["nft", "insert", "rule", "inet", "ttp", "filter_out", "accept"], check=True)


def last_rule_handle(listing: str) -> int | None:
    """Handle of the last rule in an `nft -a list chain` listing; the chain's own handle is skipped."""
    handle = None
    for line in listing.splitlines():
        match = re.search(r"#\s*handle (\d+)\s*$", line)
        if match and not line.lstrip().startswith("chain "):
            handle = int(match.group(1))
    return handle


def inject_delete_last_filter_rule():
    """Delete filter_out's last rule - on a session table, the catch-all reject.

    Raises:
        RuntimeError: If the chain has no rule, rather than count a fault that did nothing.
    """
    print("[CHAOS] Injecting Failure: deleting the last rule of filter_out...")
    listing = subprocess.run(
        ["nft", "-a", "list", "chain", "inet", "ttp", "filter_out"],
        capture_output=True,
        text=True,
        check=False,
    )
    handle = last_rule_handle(listing.stdout)
    if handle is None:
        raise RuntimeError(f"cannot delete a rule: filter_out has none ({listing.stdout.strip()!r})")
    subprocess.run(["nft", "delete", "rule", "inet", "ttp", "filter_out", "handle", str(handle)], check=True)


def inject_flush_firewall():
    print("[CHAOS] Injecting Failure: Flushing nftables 'inet ttp' ruleset...")
    subprocess.run(["nft", "flush", "table", "inet", "ttp"], check=True)


def inject_destroy_firewall():
    print("[CHAOS] Injecting Failure: Destroying nftables 'inet ttp' table entirely...")
    subprocess.run(["nft", "delete", "table", "inet", "ttp"], check=False)
    subprocess.run(["nft", "destroy", "table", "inet", "ttp"], check=False)


def inject_unmount_dns():
    print("[CHAOS] Injecting Failure: Unmounting /etc/resolv.conf overlay...")
    subprocess.run(["umount", "-l", "/etc/resolv.conf"], check=False)


def inject_link_flap(interface: str):
    print(f"[CHAOS] Injecting Failure: Flapping default routing interface '{interface}'...")
    # Shuts down interface for 2 seconds then brings it back up to avoid permanent disconnection
    subprocess.run(["ip", "link", "set", interface, "down"], check=True)
    time.sleep(2)
    subprocess.run(["ip", "link", "set", interface, "up"], check=True)


#: Every fault a run can inject, in the order the sweep runs them. The dispatch
#: reads from here, so a fault added to this table is a fault the sweep runs -
#: the previous `random.choice` list and its `if/elif` chain could drift apart,
#: and a fault present in one and missing from the other was silently never
#: injected. Each entry takes the active interface; most ignore it.
INJECTIONS: dict[str, Callable[[str], None]] = {
    "kill_tor": lambda interface: inject_kill_tor(),
    "sigkill_tor": lambda interface: inject_sigkill_tor(),
    "insert_accept": lambda interface: inject_insert_accept(),
    "delete_last_filter_rule": lambda interface: inject_delete_last_filter_rule(),
    "flush_firewall": lambda interface: inject_flush_firewall(),
    "destroy_firewall": lambda interface: inject_destroy_firewall(),
    "unmount_dns": lambda interface: inject_unmount_dns(),
    "link_flap": inject_link_flap,
}


def plan_injections(selected: str | None = None) -> list[str]:
    """The exact sequence of faults this run will inject.

    The loop used to pick with ``random.choice`` at every interval, so a 60s
    run at 12s intervals exercised roughly four of the five faults, chosen by
    chance. A regression in the unlucky one shipped, and no two runs covered
    the same ground - which makes "the chaos monkey passed" a statement about
    luck rather than about the watchdog.

    Args:
        selected: One fault name, to reproduce a single failure. ``None``
            sweeps all of them, once each.

    Raises:
        ValueError: If *selected* names no known fault. A typo that planned an
            empty run would otherwise report a clean sweep having injected
            nothing at all.
    """
    if selected is None:
        return list(INJECTIONS)
    if selected not in INJECTIONS:
        raise ValueError(f"unknown injection {selected!r}; known: {', '.join(INJECTIONS)}")
    return [selected]


def verdict(planned: int, executed: int, leaks: int, inconclusive: int) -> tuple[int, str]:
    """Decide what a finished run proved, and with what exit code.

    Ordered by how little the run is allowed to claim. A leak is the finding
    the script exists for; an audit that could not measure has produced no
    evidence either way and must not read as a clean run; and a sweep that did
    not finish has left faults untried, which is the same defect one level up -
    reporting success for ground that was never covered.
    """
    if leaks > 0:
        return 1, "[FAIL] Watchdog failed to prevent cleartext network leaks."
    if inconclusive > 0:
        return 1, (
            f"[FAIL] {inconclusive} of {executed} audit(s) could not measure. "
            "This run proves nothing about whether the watchdog held."
        )
    if executed == 0:
        return 1, "[FAIL] No failure was ever injected, so the watchdog was never tested."
    if executed < planned:
        return 1, (
            f"[FAIL] The sweep did not finish: {executed} of {planned} planned "
            "injection(s) ran before the duration budget expired. The faults that "
            "were never injected are untested, so this run cannot report success. "
            "Raise --duration or use --injection to run one at a time."
        )
    return 0, f"[PASS] All {executed} planned injection(s) ran and the watchdog held with zero leaks."


def main():
    parser = argparse.ArgumentParser(description="Chaos Monkey Watchdog stress test")
    parser.add_argument(
        "--duration",
        type=int,
        default=420,
        help=(
            "Upper bound on the run, in seconds. Not a schedule: the sweep ends when every "
            "planned injection has run, and a budget that expires first is reported as an "
            "incomplete sweep rather than a pass."
        ),
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=12,
        help="Time between failure injections in seconds",
    )
    parser.add_argument(
        "--injection",
        choices=sorted(INJECTIONS),
        default=None,
        help="Inject only this fault, to reproduce one failure. Default: sweep all of them once.",
    )
    parser.add_argument(
        "--reset-between",
        action="store_true",
        help=(
            "Start a fresh session before every fault, so each one meets a healthy session. "
            "Default: one session for the whole sweep, so later faults meet what earlier ones left."
        ),
    )
    parser.add_argument(
        "--no-bypass",
        action="store_true",
        help=(
            "Configure no bypassed user. The canary's bypass rule is itself something the watchdog "
            "checks, so it changes the session under test; without it the positive control is the "
            "audited user's own audit before each `ttp start`."
        ),
    )
    args = parser.parse_args()
    bypass = not args.no_bypass

    try:
        plan = plan_injections(args.injection)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] Planned sweep ({len(plan)}): {', '.join(plan)}")

    require_root()

    real_ip = get_real_public_ip()
    if real_ip is None:
        # Without a baseline the leak test is `current_ip == None`, which is
        # false for every possible answer. The run would report zero leaks
        # whatever happened, so there is nothing to gain by starting it.
        print(
            "[ERROR] Could not detect this host's real public IP. The leak check "
            "compares against it, so without it the run cannot fail and would "
            "report success no matter what the watchdog did.",
            file=sys.stderr,
        )
        sys.exit(1)

    target, stun = resolve_audit_target(), resolve_stun_target()
    if target is None or stun is None:
        print("[ERROR] The audit targets did not resolve before the session; no audit could run.", file=sys.stderr)
        sys.exit(1)
    targets = (target, stun)
    print(f"[INFO] Audits: TCP to {AUDIT_HOST} at {target}, UDP to STUN at {stun}, resolved before the session")

    interface = get_active_interface()
    if not interface:
        print("[ERROR] No active network interface found.", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] Active network interface: {interface}")

    setup_test_user()

    # 1. Start TTP
    mode = "independent trials" if args.reset_between else "one session for the whole sweep"
    print(f"[INFO] Bootstrapping TTP with watchdog ({mode}, {'canary bypassed' if bypass else 'no bypass'})...")
    try:
        control = start_session(real_ip, targets, bypass)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        cleanup_test_user()
        sys.exit(1)

    # Before any fault: the positive control must have seen this host. If it did
    # not, no audit in this run can report a leak, and there is nothing to sweep for.
    if control is not AuditResult.LEAK:
        print(
            "[ERROR] The positive control did not reach the WAN as this host before any "
            "fault was injected, so this run could not detect a leak. Not sweeping.",
            file=sys.stderr,
        )
        subprocess.run(["ttp", "stop"], capture_output=True)
        cleanup_test_user()
        sys.exit(1)

    print("[INFO] TTP started successfully. Chaos Monkey loop starting...")
    start_time = time.time()
    last_injection = time.time()
    failures_injected = 0
    leaks_found = 0
    inconclusive_audits = 0

    try:
        for failure_type in plan:
            # The budget is a cap, not the schedule. A sweep that runs out of
            # time has left faults untried, and `verdict` refuses to call that
            # a pass rather than reporting success for ground never covered.
            if time.time() - start_time >= args.duration:
                print(f"[WARN] Duration budget expired before {failure_type}; the sweep is incomplete.")
                break

            # Independent trials: each fault meets a session nothing has touched.
            # The first reuses the session started above.
            if args.reset_between and failures_injected > 0:
                subprocess.run(["ttp", "stop"], capture_output=True)
                try:
                    control = start_session(real_ip, targets, bypass)
                except RuntimeError as exc:
                    print(f"[ALERT] TRIAL INCONCLUSIVE ({failure_type}): {exc}")
                    inconclusive_audits += 1
                    failures_injected += 1
                    continue
                if control is not AuditResult.LEAK:
                    print(f"[ALERT] TRIAL INCONCLUSIVE ({failure_type}): the positive control did not see this host")
                    inconclusive_audits += 1
                    failures_injected += 1
                    continue
                last_injection = 0.0  # a fresh session: nothing to space this fault from

            while time.time() - last_injection < args.interval:
                time.sleep(1)

            print(f"[INFO] Injecting {failure_type} ({failures_injected + 1}/{len(plan)})...")
            INJECTIONS[failure_type](interface)

            failures_injected += 1
            last_injection = time.time()

            # Sleep briefly to let the watchdog detect and react (15s watch interval + buffer)
            check_wait = 18
            print(f"[INFO] Waiting {check_wait} seconds for watchdog response...")
            time.sleep(check_wait)

            containment = worst(*audit_both(real_ip, TEST_USER, targets, "audited"))
            if bypass:
                # Same pass: the canary is the positive control for this pass,
                # not for some earlier moment.
                canary = all_leaked(*audit_both(real_ip, CANARY_USER, targets, "canary"))
                result, reason = judge_pass(containment, canary, killswitch_engaged())
            else:
                result, reason = judge_pass_without_canary(containment, control)
            print(f"[PASS-VERDICT] {result.value}: {reason}")
            if result is AuditResult.LEAK:
                leaks_found += 1
                break
            if result is AuditResult.INCONCLUSIVE:
                inconclusive_audits += 1

    except KeyboardInterrupt:
        print("[INFO] Stress test interrupted by user.")

    finally:
        print("[INFO] Cleaning up TTP session and environment...")
        subprocess.run(["ttp", "stop"], capture_output=True)
        cleanup_test_user()

    print("\n" + "=" * 50)
    print("Chaos Monkey Stress Test Summary:")
    print(f"  Injections Planned:   {len(plan)} ({', '.join(plan)})")
    print(f"  Failures Injected:    {failures_injected}")
    print(f"  Leaks Detected:       {leaks_found}")
    print(f"  Inconclusive Audits:  {inconclusive_audits}")
    print("=" * 50)

    code, message = verdict(
        planned=len(plan),
        executed=failures_injected,
        leaks=leaks_found,
        inconclusive=inconclusive_audits,
    )
    print(message)
    sys.exit(code)


if __name__ == "__main__":
    main()
