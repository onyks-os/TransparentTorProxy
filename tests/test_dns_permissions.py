# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Reproduce the unreadable DNS artifacts with the administrator's real umask."""

import os
import stat
from unittest.mock import patch

import pytest

from ttp import dns, dns_resolved


@pytest.mark.parametrize("mask", [0o027, 0o077])
@pytest.mark.parametrize("existing", [False, True])
def test_overlay_inode_is_public_but_runtime_state_stays_private(tmp_path, monkeypatch, mask, existing):
    runtime = tmp_path / "ttp"
    runtime.mkdir(mode=0o750)
    lock = runtime / "ttp.lock"
    lock.write_text("private session data")
    lock.chmod(0o640)
    resolver = runtime / "resolv.conf"
    target = tmp_path / "system-resolv.conf"
    target.write_text("original resolver\n")
    if existing:
        resolver.touch(mode=0o600)
    monkeypatch.setattr(dns, "RUNTIME_RESOLV", resolver)
    monkeypatch.setattr(dns, "RESOLV_CONF", target)

    def mount(cmd, **kwargs):
        assert cmd[1] == "--bind"
        assert stat.S_IMODE(resolver.stat().st_mode) == 0o644
        assert "nameserver 127.0.0.1" in resolver.read_text()

    old_mask = os.umask(mask)
    try:
        with (
            patch.object(dns_resolved, "apply_resolved", return_value=False),
            patch.object(dns.subprocess, "run", side_effect=mount),
        ):
            dns.apply_dns("wlo1")
        assert os.umask(mask) == mask  # Runtime must not change the process-wide mask.
    finally:
        os.umask(old_mask)
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o750
    assert stat.S_IMODE(lock.stat().st_mode) == 0o640
    assert target.read_text() == "original resolver\n"


@pytest.mark.parametrize("mask", [0o027, 0o077])
@pytest.mark.parametrize("existing", [False, True])
def test_resolved_dropin_is_readable_and_removal_restores_configuration(tmp_path, monkeypatch, mask, existing):
    directory = tmp_path / "resolved.conf.d"
    dropin = directory / "ttp.conf"
    persistent = tmp_path / "resolved.conf"
    original = "[Resolve]\nDNSSEC=yes\nDNS=9.9.9.9\n"
    persistent.write_text(original)
    if existing:
        directory.mkdir(mode=0o700)
        dropin.touch(mode=0o600)
    monkeypatch.setattr(dns_resolved, "RESOLVED_CONF_DIR", directory)
    monkeypatch.setattr(dns_resolved, "RESOLVED_CONF_FILE", dropin)
    restarts = []

    def run(cmd, **kwargs):
        if "restart" in cmd:
            restarts.append(dropin.read_text() if dropin.exists() else None)
            if dropin.exists():
                assert stat.S_IMODE(directory.stat().st_mode) == 0o755
                assert stat.S_IMODE(dropin.stat().st_mode) == 0o644

    old_mask = os.umask(mask)
    try:
        with (
            patch.object(dns_resolved, "is_resolved_active", return_value=True),
            patch.object(dns_resolved.subprocess, "run", side_effect=run),
        ):
            assert dns_resolved.apply_resolved(9054)
            dns_resolved.restore_resolved()
        assert os.umask(mask) == mask
    finally:
        os.umask(old_mask)
    assert "DNSSEC=no\n" in restarts[0]
    assert restarts[1] is None
    assert not dropin.exists()
    assert persistent.read_text() == original
