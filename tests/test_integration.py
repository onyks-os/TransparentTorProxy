"""Integration tests for TTP.

These tests run the actual CLI commands (start, refresh, stop) and
verify real Tor routing via the Tor Project's check API.
They are designed to be run inside the Docker-based testing environment.
"""

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

# Skip the entire module if not running as root
if os.geteuid() != 0:
    pytest.skip("Integration tests must be run as root", allow_module_level=True)

# Skip when /run is not writable (e.g. sandboxed "root", minimal CI without tmpfs)
try:
    Path("/run/ttp").mkdir(parents=True, exist_ok=True)
except OSError:
    pytest.skip(
        "Integration tests need a writable /run/ttp (use Docker integration or a real host)",
        allow_module_level=True,
    )


@pytest.fixture(scope="module", autouse=True)
def ensure_clean_state():
    """Ensure we start and end with a clean network state."""
    # Pre-cleanup in case a previous run crashed
    subprocess.run(["ttp", "stop"], capture_output=True)
    yield
    # Post-cleanup
    subprocess.run(["ttp", "stop"], capture_output=True)


@pytest.mark.integration
def test_full_ttp_flow():
    """Test the full TTP start -> verify -> refresh -> stop flow."""
    # 1. Start TTP
    res = subprocess.run(
        ["ttp", "start", "--bootstrap-timeout", "300"], capture_output=True, text=True
    )
    if res.returncode != 0:
        status_res = subprocess.run(
            ["systemctl", "status", "ttp-tor.service"], capture_output=True, text=True
        )
        journal_res = subprocess.run(
            ["journalctl", "-xeu", "ttp-tor.service", "--no-pager"], capture_output=True, text=True
        )
        
        error_msg = (
            f"ttp start failed! (returncode {res.returncode})\n\n"
            f"=== TTP STDOUT ===\n{res.stdout}\n"
            f"=== TTP STDERR ===\n{res.stderr}\n\n"
            f"=== SYSTEMCTL STATUS ===\n{status_res.stdout}\n\n"
            f"=== JOURNALCTL ===\n{journal_res.stdout}\n"
        )
        pytest.fail(error_msg)

    # 2. Verify routing through Tor
    req = urllib.request.Request(
        "https://check.torproject.org/api/ip",
        headers={"User-Agent": "ttp-integration-test"},
    )
    is_tor = False
    exit_ip = "unknown"

    for _ in range(15):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("IsTor"):
                    is_tor = True
                    exit_ip = data.get("IP", "unknown")
                    break
                else:
                    time.sleep(2)
        except Exception:
            time.sleep(2)

    assert is_tor, (
        f"Traffic is not routed through Tor!\nStart stdout:\n{res.stdout}\nStart stderr:\n{res.stderr}"
    )
    assert exit_ip != "unknown", "Could not determine exit IP"

    # 3. Test Refresh Circuit
    res = subprocess.run(["ttp", "refresh"], capture_output=True, text=True)
    assert res.returncode == 0, f"ttp refresh failed: {res.stderr}\n{res.stdout}"

    # 4. Stop TTP
    res = subprocess.run(["ttp", "stop"], capture_output=True, text=True)
    assert res.returncode == 0, f"ttp stop failed: {res.stderr}\n{res.stdout}"

    # 5. Verify we are no longer using Tor
    is_tor_after = True
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                is_tor_after = data.get("IsTor", False)
                if not is_tor_after:
                    break
        except Exception:
            time.sleep(2)

    assert not is_tor_after, "Traffic is STILL routed through Tor after 'ttp stop'!"


@pytest.mark.integration
def test_custom_ports_flow():
    """Test starting TTP with custom TransPort and DNSPort and verifying Tor routing."""
    # 1. Start TTP with custom ports
    res = subprocess.run(
        ["ttp", "start", "-t", "9081", "-d", "9091", "--bootstrap-timeout", "300"],
        capture_output=True,
        text=True
    )
    if res.returncode != 0:
        status_res = subprocess.run(
            ["systemctl", "status", "ttp-tor.service"], capture_output=True, text=True
        )
        journal_res = subprocess.run(
            ["journalctl", "-xeu", "ttp-tor.service", "--no-pager"], capture_output=True, text=True
        )
        
        error_msg = (
            f"ttp start with custom ports failed! (returncode {res.returncode})\n\n"
            f"=== TTP STDOUT ===\n{res.stdout}\n"
            f"=== TTP STDERR ===\n{res.stderr}\n\n"
            f"=== SYSTEMCTL STATUS ===\n{status_res.stdout}\n\n"
            f"=== JOURNALCTL ===\n{journal_res.stdout}\n"
        )
        pytest.fail(error_msg)

    # 2. Verify routing through Tor
    req = urllib.request.Request(
        "https://check.torproject.org/api/ip",
        headers={"User-Agent": "ttp-integration-test"},
    )
    is_tor = False
    exit_ip = "unknown"

    for _ in range(15):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("IsTor"):
                    is_tor = True
                    exit_ip = data.get("IP", "unknown")
                    break
                else:
                    time.sleep(2)
        except Exception:
            time.sleep(2)

    assert is_tor, (
        f"Traffic is not routed through Tor on custom ports!\nStart stdout:\n{res.stdout}\nStart stderr:\n{res.stderr}"
    )
    assert exit_ip != "unknown", "Could not determine exit IP"

    # 3. Stop TTP
    res = subprocess.run(["ttp", "stop"], capture_output=True, text=True)
    assert res.returncode == 0, f"ttp stop failed: {res.stderr}\n{res.stdout}"

    # 4. Verify we are no longer using Tor
    is_tor_after = True
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                is_tor_after = data.get("IsTor", False)
                if not is_tor_after:
                    break
        except Exception:
            time.sleep(2)

    assert not is_tor_after, "Traffic is STILL routed through Tor after 'ttp stop'!"

