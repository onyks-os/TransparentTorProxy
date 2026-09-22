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
    """Create a clean temporary unprivileged user for traffic validation."""
    cleanup_test_user()
    print(f"[INFO] Creating temporary test user: {TEST_USER}")
    subprocess.run(["useradd", "-m", TEST_USER], check=True, capture_output=True)


def cleanup_test_user():
    """Delete the temporary test user and their home directory."""
    print(f"[INFO] Cleaning up test user: {TEST_USER}")
    subprocess.run(["userdel", "-r", TEST_USER], capture_output=True)


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


#: Run in the child so that a blocked request and a successful one both exit 0.
#: A non-zero exit then means the harness broke, which is a different fact from
#: "the killswitch held" and must not be scored as one.
_AUDIT_SCRIPT = (
    "import urllib.request\n"
    "req = urllib.request.Request('https://api.ipify.org',"
    " headers={'User-Agent': 'ttp-chaos-audit'})\n"
    "try:\n"
    "    print('OK ' + urllib.request.urlopen(req, timeout=3).read().decode().strip())\n"
    "except OSError as exc:\n"
    "    print('NETFAIL ' + type(exc).__name__)\n"
)


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


def run_connectivity_audit(real_ip: str | None) -> AuditResult:
    """Ask what the WAN sees, and report honestly when the question went unanswered."""
    if real_ip is None:
        result, reason = classify_audit(real_ip, 0, "")
    else:
        try:
            res = subprocess.run(
                ["python3", "-c", _AUDIT_SCRIPT],
                capture_output=True,
                text=True,
                user=TEST_USER,
            )
        except OSError as exc:
            result, reason = AuditResult.INCONCLUSIVE, f"the audit could not be launched at all: {exc!r}"
        else:
            result, reason = classify_audit(real_ip, res.returncode, res.stdout)

    label = {
        AuditResult.CONTAINED: "[AUDIT] CONTAINED",
        AuditResult.LEAK: "[ALERT] CRITICAL NET LEAK DETECTED",
        AuditResult.INCONCLUSIVE: "[ALERT] AUDIT INCONCLUSIVE",
    }[result]
    print(f"{label}: {reason}")
    return result


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
    args = parser.parse_args()

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

    interface = get_active_interface()
    if not interface:
        print("[ERROR] No active network interface found.", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] Active network interface: {interface}")

    setup_test_user()

    # 1. Start TTP
    print("[INFO] Bootstrapping TTP with watchdog...")
    res = subprocess.run(
        ["ttp", "start", "--watchdog", "--bootstrap-timeout", "300"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"[ERROR] Failed to start TTP: {res.stderr}", file=sys.stderr)
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

            # Run network leak audits
            result = run_connectivity_audit(real_ip)
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
