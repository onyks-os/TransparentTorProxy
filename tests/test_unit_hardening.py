# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""The two long-running processes TTP starts run with as little as they need.

Tor was started as root and dropped to its account itself, through the torrc's
`User` directive - as the distributions' own units do, because they may bind
ports below 1024. TTP's ports are above 1024, so Tor never needs root: systemd
now starts it as its account, with no capabilities at all. Both units also get
the filesystem, kernel and socket restrictions systemd offers, limited to what
each process was measured to use.

Parsed rather than grepped: a directive counts only as a `Key=value` line of
the [Service] section.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from ttp import tor_config
from ttp.tor_service import _build_service_unit_content
from ttp.watchdog import service as watchdog_service


def _directives(unit: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    section = None
    for raw in unit.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]" and "=" in line:
            key, _, value = line.partition("=")
            out.setdefault(key, []).append(value)
    return out


TOR_UNIT = _build_service_unit_content(tor_user="debian-tor", tor_bin="/usr/sbin/tor")


def _watchdog_unit(tmp_path: Path, *, has_account: bool = True) -> str:
    target = tmp_path / "ttp-watchdog.service"
    with (
        patch.object(watchdog_service, "WATCHDOG_SERVICE_PATH", target),
        patch("pwd.getpwnam", return_value=object()) if has_account else patch("pwd.getpwnam", side_effect=KeyError),
    ):
        watchdog_service._write_watchdog_service_unit()
    return target.read_text()


# Tor --------------------------------------------------------------------------


def test_tor_is_started_as_its_account_never_as_root():
    d = _directives(TOR_UNIT)
    assert d["User"] == ["debian-tor"]
    assert d["CapabilityBoundingSet"] == [""], "Tor needs no capability: its ports are above 1024"
    assert d["NoNewPrivileges"] == ["yes"]


def test_only_the_directory_preparation_runs_privileged():
    """The '+' prefix exempts a command from User= and the sandbox; only the
    mkdir/chown/chmod that prepare Tor's directories may carry it."""
    d = _directives(TOR_UNIT)
    assert all(cmd.startswith("+/bin/") for cmd in d["ExecStartPre"])
    assert not d["ExecStart"][0].startswith("+")


def test_tor_can_write_only_its_own_directories():
    d = _directives(TOR_UNIT)
    assert d["ProtectSystem"] == ["strict"]
    assert d["ReadWritePaths"] == [f"{tor_config.TOR_CACHE_DIR} {tor_config.TOR_RUNTIME_DIR}"]
    assert d["ProtectHome"] == ["yes"] and d["PrivateTmp"] == ["yes"] and d["PrivateDevices"] == ["yes"]


def test_tor_keeps_the_sockets_it_needs_and_no_others():
    """INET/INET6 for the network, UNIX for the control socket, NETLINK for the
    interface addresses Tor reads at startup."""
    families = set(_directives(TOR_UNIT)["RestrictAddressFamilies"][0].split())
    assert families == {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}


def test_the_torrc_no_longer_asks_tor_to_switch_user():
    content = tor_config._build_torrc_content(
        tor_user="debian-tor",
        transport_port=9041,
        dns_port=9054,
        block_doh=False,
        use_bridges=False,
        bridges=None,
        ipv6_avail=False,
    )
    assert not any(line.startswith("User ") for line in content.splitlines())


# The watchdog -----------------------------------------------------------------


def test_the_watchdog_can_write_only_its_own_directory(tmp_path):
    d = _directives(_watchdog_unit(tmp_path))
    assert d["ProtectSystem"] == ["strict"]
    assert d["ReadWritePaths"] == ["/run/ttp/watchdog"]
    assert d["CapabilityBoundingSet"] == ["CAP_NET_ADMIN"]


def test_the_watchdog_has_no_network_sockets(tmp_path):
    """It watches nftables over netlink and talks to systemd and Tor over UNIX
    sockets. It never opens an INET socket, so it cannot be given one."""
    d = _directives(_watchdog_unit(tmp_path))
    assert set(d["RestrictAddressFamilies"][0].split()) == {"AF_UNIX", "AF_NETLINK"}


def test_the_watchdog_keeps_access_to_terminals_for_wall(tmp_path):
    """PrivateDevices would hide /dev/pts, and wall is the only announcement of
    the killswitch that reaches anyone."""
    assert "PrivateDevices" not in _directives(_watchdog_unit(tmp_path))


# Both, checked by systemd itself ----------------------------------------------


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
@pytest.mark.parametrize("which", ["tor", "watchdog"])
def test_systemd_accepts_every_directive(which, tmp_path):
    unit = tmp_path / f"ttp-{which}.service"
    unit.write_text(TOR_UNIT if which == "tor" else _watchdog_unit(tmp_path))
    result = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", str(unit)], capture_output=True, text=True, check=False
    )
    unknown = [line for line in result.stderr.splitlines() if "Unknown key" in line or "Unknown section" in line]
    assert not unknown, unknown
