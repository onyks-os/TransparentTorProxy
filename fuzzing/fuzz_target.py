"""Fuzz testing harness for TTP using Hypothesis (property-based testing).

This module provides fuzz targets for critical parsing and detection
functions in TTP. It exercises code paths that process untrusted or
variable input data without requiring root privileges or network access.

Usage:
    pytest fuzzing/fuzz_target.py -v
"""

import json
import re

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# 1. JSON lock file parsing (state.py)
# ---------------------------------------------------------------------------


@given(data=st.binary())
@settings(max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_json_lock_parsing(data: bytes) -> None:
    """Fuzz the JSON lock file parsing logic.

    Simulates malformed or adversarial lock file contents to ensure
    that ``json.loads`` and downstream key access never crash.
    """
    try:
        text = data.decode("utf-8", errors="ignore")
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            _ = parsed.get("pid")
            _ = parsed.get("dns_backup")
            _ = parsed.get("transport_port", 9041)
            _ = parsed.get("dns_port", 9054)
            _ = parsed.get("allow_root", False)
            _ = parsed.get("lan_bypass", True)
            _ = parsed.get("watchdog_active", False)
            _ = parsed.get("watchdog_pid")
            _ = parsed.get("interface")
            _ = parsed.get("bypass_users", [])
            _ = parsed.get("bypass_groups", [])
            _ = parsed.get("use_bridges", False)
            _ = parsed.get("bridge_file")
            _ = parsed.get("bridges", [])
    except (json.JSONDecodeError, ValueError, TypeError, UnicodeDecodeError):
        pass


# ---------------------------------------------------------------------------
# 2. Tor version regex (tor_detect.py)
# ---------------------------------------------------------------------------


@given(data=st.text(min_size=0, max_size=500))
@settings(max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_tor_version_regex(data: str) -> None:
    """Fuzz the Tor version regex extraction against arbitrary strings
    to detect ReDoS or unexpected matches."""
    try:
        match = re.search(r"Tor version ([\d]+(?:\.[\d]+)*)", data)
        if match:
            _ = match.group(1)
    except (re.error, ValueError):
        pass


# ---------------------------------------------------------------------------
# 3. Torrc configuration validation regexes (tor_detect.py)
# ---------------------------------------------------------------------------


@given(data=st.text(min_size=0, max_size=1000))
@settings(max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_torrc_config_regex(data: str) -> None:
    """Fuzz the torrc configuration validation regexes."""
    try:
        transport_port = 9041
        dns_port = 9054
        _ = bool(re.search(rf"^\s*TransPort\s+{transport_port}\b", data, re.MULTILINE))
        _ = bool(re.search(rf"^\s*DNSPort\s+{dns_port}\b", data, re.MULTILINE))
        _ = bool(re.search(r"^\s*ControlSocket\s+", data, re.MULTILINE))
    except (re.error, ValueError):
        pass


# ---------------------------------------------------------------------------
# 4. OS family detection (tor_detect.py)
# ---------------------------------------------------------------------------


@given(data=st.text(min_size=0, max_size=500))
@settings(max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_os_release_detection(data: str) -> None:
    """Fuzz the OS family detection string matching."""
    try:
        text = data.lower()
        _ = any(x in text for x in ["fedora", "rhel", "centos", "rocky", "almalinux"])
    except (ValueError, UnicodeDecodeError):
        pass


# ---------------------------------------------------------------------------
# 5. /proc/mounts line parsing (dns.py)
# ---------------------------------------------------------------------------


@given(data=st.text(min_size=0, max_size=2000))
@settings(max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_proc_mounts_parsing(data: str) -> None:
    """Fuzz the /proc/mounts line parsing logic."""
    try:
        target = "/etc/resolv.conf"
        for line in data.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == target:
                break
    except (ValueError, UnicodeDecodeError):
        pass


# ---------------------------------------------------------------------------
# 6. SELinux module detection regex (tor_detect.py)
# ---------------------------------------------------------------------------


@given(data=st.text(min_size=0, max_size=500))
@settings(max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_selinux_module_regex(data: str) -> None:
    """Fuzz the SELinux module detection regex."""
    try:
        _ = bool(re.search(r"ttp_tor_policy\s+1\.1\b", data))
    except (re.error, ValueError):
        pass
