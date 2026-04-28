"""Tests for ttp.dns — DNS management logic.

All tests mock subprocess.run and file I/O.
Corresponds to TDD §8.3.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ttp import dns
from ttp.exceptions import DNSError


@pytest.fixture(autouse=True)
def _mock_resolv_conf(tmp_path: Path):
    """Redirect /etc/resolv.conf to a temp file for every test."""
    fake_resolv = tmp_path / "resolv.conf"
    fake_resolv.write_text("nameserver 8.8.8.8\n")
    with patch.object(dns, "RESOLV_CONF", fake_resolv):
        yield fake_resolv


# ── Detection ──────────────────────────────────────────────────────


def test_detect_mode_resolvectl():
    """detect_dns_mode returns 'resolvectl' if service is active."""
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert dns.detect_dns_mode() == "resolvectl"


def test_detect_mode_resolvconf():
    """detect_dns_mode returns 'resolv.conf' if service is inactive."""
    with patch("ttp.dns.subprocess.run") as mock_run:
        # systemctl is-active returns non-zero if inactive
        mock_run.side_effect = subprocess.CalledProcessError(3, "systemctl")
        assert dns.detect_dns_mode() == "resolv.conf"


def test_detect_active_interface():
    """detect_active_interface parses 'ip route' output correctly."""
    mock_stdout = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout)
        assert dns.detect_active_interface() == "wlan0"


# ── Application ────────────────────────────────────────────────────


def test_apply_dns_resolvectl():
    """apply_dns with resolvectl calls dns, domain, and flush commands."""
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        backup = dns.apply_dns("resolvectl", "eth0")

        assert backup["mode"] == "resolvectl"
        assert backup["interface"] == "eth0"

        # Check the 3 expected calls
        assert mock_run.call_count == 3
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["resolvectl", "dns", "eth0", "127.0.0.1"] in calls
        assert ["resolvectl", "domain", "eth0", "~."] in calls
        assert ["resolvectl", "flush-caches"] in calls


def test_apply_dns_resolvconf(_mock_resolv_conf: Path):
    """apply_dns with resolv.conf overwrites the file and returns original."""
    _mock_resolv_conf.write_text("nameserver 1.1.1.1\n")
    backup = dns.apply_dns("resolv.conf", "eth0")

    assert backup["original_content"] == "nameserver 1.1.1.1\n"
    assert "nameserver 127.0.0.1" in _mock_resolv_conf.read_text()


# ── Restoration ────────────────────────────────────────────────────


def test_restore_dns_resolvectl():
    """restore_dns with resolvectl triggers the Hard-Reset sequence."""
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        dns.restore_dns("resolvectl", {"interface": "wlan0"})

        # Hard-Reset sequence: revert, restart, flush
        assert mock_run.call_count == 3
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["resolvectl", "revert", "wlan0"] in calls
        assert ["systemctl", "restart", "systemd-resolved"] in calls
        assert ["resolvectl", "flush-caches"] in calls


def test_restore_dns_resolvconf(_mock_resolv_conf: Path):
    """restore_dns with resolv.conf restores original file content."""
    dns.restore_dns("resolv.conf", "nameserver 9.9.9.9\n")
    assert _mock_resolv_conf.read_text() == "nameserver 9.9.9.9\n"


# ── Error Handling ─────────────────────────────────────────────────


def test_apply_dns_resolvectl_failure():
    """apply_dns raises DNSError if resolvectl fails."""
    with patch("ttp.dns.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "resolvectl", stderr="error"
        )
        with pytest.raises(DNSError, match="resolvectl failed"):
            dns.apply_dns("resolvectl", "eth0")
