# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""A reachable SSH server cannot mask failed guest provisioning."""

import hashlib
import http.server
import json
import os
import subprocess
import threading

import pytest


@pytest.mark.parametrize("status", [0, 1, 124])
def test_cloud_init_must_complete_successfully(tmp_path, status):
    result = subprocess.run(
        [
            "bash",
            "-c",
            """
source scripts/vm/lifecycle/vm.sh
vm_ssh() {
    case "$1" in
        true) return 0 ;;
        *'cloud-init status'*) echo provisioning-evidence; return "$READINESS_STATUS" ;;
        *) echo guest-diagnostics; return 0 ;;
    esac
}
vm_wait_ready 5
""",
        ],
        env={**os.environ, "VM_WORK": str(tmp_path), "VM_DISTRO": "debian", "READINESS_STATUS": str(status)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    evidence = (tmp_path / "cloud-init.txt").read_text()
    assert "provisioning-evidence" in evidence
    if status == 0:
        assert result.returncode == 0
        assert "guest ready" in result.stderr
    else:
        assert result.returncode != 0
        assert "guest ready" not in result.stderr
        assert "guest-diagnostics" in evidence


@pytest.mark.parametrize("case", ["hostname", "package", "fatal", "unfinished", "malformed"])
def test_only_completed_hostname_warning_can_be_accepted(tmp_path, case):
    value = {"status": "done", "errors": [], "recoverable_errors": {"WARNING": ["Failed to set the hostname to test"]}}
    if case == "package":
        value["recoverable_errors"]["WARNING"].append("Failed to install packages")
    elif case == "fatal":
        value["errors"] = ["fatal"]
    elif case == "unfinished":
        value["status"] = "running"
    payload = "{" if case == "malformed" else json.dumps(value)
    result = subprocess.run(
        [
            "bash",
            "-c",
            """
source scripts/vm/lifecycle/vm.sh
vm_ssh() {
    case "$1" in
        true) return 0 ;;
        *'--format json'*) printf '%s' "$READINESS_JSON"; return 2 ;;
        *'cloud-init status'*) echo warning; return 2 ;;
        *) echo guest-diagnostics; return 0 ;;
    esac
}
vm_wait_ready 5
""",
        ],
        env={**os.environ, "VM_WORK": str(tmp_path), "VM_DISTRO": "debian", "READINESS_JSON": payload},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (result.returncode == 0) is (case == "hostname"), result.stderr


@pytest.mark.parametrize("valid", [True, False])
def test_cached_image_still_requires_matching_published_checksum(tmp_path, valid):
    expected = b"controlled-image-bytes"
    cached = tmp_path / "cached.qcow2"
    cached.write_bytes(expected if valid else b"wrong-image-bytes")
    work = tmp_path / "work"
    work.mkdir()

    class Checksums(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != "/SHA512SUMS":
                self.send_error(404)
                return
            body = (hashlib.sha512(expected).hexdigest() + "  fixture.qcow2\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Checksums)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                "bash",
                "-c",
                """
source scripts/vm/lifecycle/vm.sh
VM_IMAGE_URL="$FIXTURE_URL"
VM_IMAGE_NAME=fixture.qcow2
VM_SUMS_LINE=' fixture.qcow2$'
vm_fetch_image
""",
            ],
            env={
                **os.environ,
                "VM_WORK": str(work),
                "VM_DISTRO": "debian",
                "VM_IMAGE_CACHE": str(cached),
                "FIXTURE_URL": f"http://127.0.0.1:{server.server_port}",
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert (result.returncode == 0) is valid, result.stderr
    assert cached.read_bytes() == (expected if valid else b"wrong-image-bytes")
