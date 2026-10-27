# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Opt-in tests with real resolved/D-Bus, only in a disposable Podman container.

Requires the capabilities in the documented container command, no external
network and TTP_TEST_DNSSEC_CONTAINER=1. Never run against the host's system bus.
"""

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from ttp import dns_policy, dns_resolved
from ttp.exceptions import DNSSECConflictError

pytestmark = [pytest.mark.integration, pytest.mark.real_binary_lookup]


def _run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10)


def _bus(*args):
    return _run("busctl", "--system", "--auto-start=no", "--json=short", *args)


def _wait_for(check, process):
    for _ in range(100):
        assert process.poll() is None, Path("/tmp/ttp-dnssec-daemons.log").read_text()[-3000:]
        try:
            if check():
                return
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        time.sleep(0.05)
    pytest.fail("systemd daemon did not reach the expected state")


@pytest.fixture
def resolved_service(monkeypatch):
    if os.environ.get("TTP_TEST_DNSSEC_CONTAINER") != "1":
        pytest.skip("requires the dedicated disposable DNSSEC test container")
    assert Path("/run/.containerenv").is_file(), "Refusing to change services outside a Podman container"
    assert os.geteuid() == 0
    # Reproduce systemd's RuntimeDirectory ownership. Some package builds leave
    # a root-owned /run/systemd/resolve in the image, but PID 1 is absent here.
    runtime = Path("/run/systemd/resolve")
    runtime.mkdir(parents=True, exist_ok=True)
    shutil.chown(runtime, user="systemd-resolve", group="systemd-resolve")
    Path("/run/dbus").mkdir(parents=True, exist_ok=True)
    _run("dbus-daemon", "--system", "--fork", "--nopidfile")
    _run("ip", "link", "add", "ttp-dns-test", "type", "dummy")
    _run("ip", "link", "set", "ttp-dns-test", "up")
    Path("/etc/systemd/resolved.conf").write_text("[Resolve]\nDNSSEC=yes\nLLMNR=no\nMulticastDNS=no\n")
    log = Path("/tmp/ttp-dnssec-daemons.log").open("w")  # noqa: SIM115 -- closed in the fixture's finally block
    processes = []

    def start():
        process = subprocess.Popen(["/usr/lib/systemd/systemd-resolved"], stdout=log, stderr=log)
        processes.append(process)
        _wait_for(
            lambda: (
                _bus(
                    "get-property",
                    "org.freedesktop.resolve1",
                    "/org/freedesktop/resolve1",
                    "org.freedesktop.resolve1.Manager",
                    "DNSSEC",
                ).returncode
                == 0
            ),
            process,
        )
        return process

    process = start()
    original_run = subprocess.run

    def service_commands(cmd, **kwargs):
        nonlocal process
        if len(cmd) > 1 and cmd[1] == "restart" and cmd[-1] == "systemd-resolved":
            process.terminate()
            process.wait(timeout=5)
            process = start()
            return subprocess.CompletedProcess(cmd, 0)
        return original_run(cmd, **kwargs)

    monkeypatch.setattr(dns_resolved, "is_resolved_active", lambda **kwargs: True)
    monkeypatch.setattr(dns_resolved.subprocess, "run", service_commands)
    try:
        yield socket.if_nametoindex("ttp-dns-test"), log, processes
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        _run("ip", "link", "del", "ttp-dns-test")
        log.close()


def test_real_resolved_distinguishes_inherited_and_explicit_policy_and_restores(resolved_service):
    index, _, _ = resolved_service
    # The effective value is yes, but inheritance must be accepted.
    dns_policy.check_dnssec_policy()
    _bus(
        "call",
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        "SetLinkDNSSEC",
        "is",
        str(index),
        "yes",
    )
    state = dns_policy.RESOLVED_LINKS / str(index)
    saved = state.read_bytes()
    with pytest.raises(DNSSECConflictError):
        dns_policy.check_dnssec_policy()
    assert state.read_bytes() == saved
    _bus(
        "call",
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        "SetLinkDNSSEC",
        "is",
        str(index),
        "",
    )
    dns_policy.check_dnssec_policy()

    old_mask = os.umask(0o077)
    try:
        assert dns_resolved.apply_resolved(9054)
    finally:
        os.umask(old_mask)
    reply = _bus(
        "get-property",
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        "DNSSEC",
    )
    assert json.loads(reply.stdout)["data"] == "no"
    dns_policy.check_dnssec_policy()
    dns_resolved.restore_resolved()
    reply = _bus(
        "get-property",
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
        "DNSSEC",
    )
    assert json.loads(reply.stdout)["data"] == "yes"
    assert not dns_resolved.RESOLVED_CONF_FILE.exists()


def test_real_networkd_explicit_policy_is_preserved(resolved_service):
    index, log, processes = resolved_service
    directory = Path("/run/systemd/network")
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / "10-ttp-dns-test.network"
    config.write_text("[Match]\nName=ttp-dns-test\n[Network]\nLinkLocalAddressing=no\nIPv6AcceptRA=no\nDNSSEC=yes\n")
    process = subprocess.Popen(["/usr/lib/systemd/systemd-networkd"], stdout=log, stderr=log)
    processes.append(process)
    state = dns_policy.NETWORKD_LINKS / str(index)
    _wait_for(lambda: "DNSSEC=yes" in state.read_text(), process)
    saved = state.read_bytes()
    with pytest.raises(DNSSECConflictError):
        dns_policy.check_dnssec_policy()
    assert state.read_bytes() == saved
