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

import pytest

# Skip the entire module if not running as root
if os.geteuid() != 0:
    pytest.skip("Integration tests must be run as root", allow_module_level=True)


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
    res = subprocess.run(["ttp", "--quiet", "start"], capture_output=True, text=True)
    assert res.returncode == 0, f"ttp start failed: {res.stderr}\n{res.stdout}"

    # 2. Verify routing through Tor
    req = urllib.request.Request(
        "https://check.torproject.org/api/ip",
        headers={"User-Agent": "ttp-integration-test/0.1"},
    )
    is_tor = False
    exit_ip = "unknown"

    for _ in range(5):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("IsTor"):
                    is_tor = True
                    exit_ip = data.get("IP", "unknown")
                    break
        except Exception:
            time.sleep(2)

    assert is_tor, "Traffic is not routed through Tor!"
    assert exit_ip != "unknown", "Could not determine exit IP"

    # 3. Test Refresh Circuit
    res = subprocess.run(["ttp", "--quiet", "refresh"], capture_output=True, text=True)
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
