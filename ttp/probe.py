# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Budgeted session verification with an explicitly non-exempt probe identity.

HTTP/TLS parsing runs in the unprivileged worker. No fallback executes that
worker's networking inside a root parent if it cannot start. The legacy tuple
API in tor_control remains separate while its callers migrate to this result.
"""

from __future__ import annotations

import grp
import ipaddress
import json
import os
import pwd
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from ttp.evidence import Diagnostic, ExitCode, Verification, VerificationState, boottime
from ttp.netprobe import ENDPOINTS

CGROUP_PATH = Path("/proc/self/cgroup")
_WORKER_ERRORS = {
    "response_too_large",
    "response_shape",
    "http_redirect",
    "http_error",
    "dns_error",
    "tls_error",
    "timeout",
    "connection_error",
    "response_encoding",
    "response_json",
}


def _issue(reason: str, endpoint: str, message: str = "") -> Diagnostic:
    return Diagnostic(ExitCode.UNVERIFIED, f"probe.{reason}", "tor", endpoint, message or reason)


def _ip(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _identity(lock: dict[str, Any] | None) -> tuple[dict[str, Any], Diagnostic | None]:
    """Resolve the worker credentials and reject known routing exemptions."""
    credentials: dict[str, Any] = {}
    try:
        if os.geteuid() == 0:
            user = pwd.getpwnam("nobody")
            uid, groups = user.pw_uid, {user.pw_gid}
            if uid <= 0:
                return {}, _issue("identity_unavailable", "identity", "nobody must be unprivileged")
            credentials = {"user": uid, "group": user.pw_gid, "extra_groups": []}
        else:
            uid, groups = os.geteuid(), {os.getegid(), *os.getgroups()}
        if lock is None:
            return credentials, None
        if uid == lock.get("tor_uid") or (uid == 0 and lock.get("allow_root")):
            return credentials, _issue("exempt_identity", "identity")
        for name in lock.get("bypass_users", []):
            bypass_uid = int(name) if str(name).isdigit() else pwd.getpwnam(name).pw_uid
            if uid == bypass_uid:
                return credentials, _issue("exempt_identity", "identity")
        for name in lock.get("bypass_groups", []):
            bypass_gid = int(name) if str(name).isdigit() else grp.getgrnam(name).gr_gid
            if bypass_gid in groups:
                return credentials, _issue("exempt_identity", "identity")
        cgroups = CGROUP_PATH.read_text()
        if any("ttp-bypass.slice" in line.split(":", 2)[-1].split("/") for line in cgroups.splitlines()):
            return credentials, _issue("exempt_cgroup", "identity")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return credentials, _issue("identity_unavailable", "identity", type(exc).__name__)
    return credentials, None


def _fetch(url: str, timeout: float, credentials: dict[str, Any]) -> tuple[dict[str, Any] | None, Diagnostic | None]:
    try:
        response = subprocess.run(
            [sys.executable, "-I", "-m", "ttp.netprobe", "--report", url, str(timeout)],
            **credentials,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, _issue("deadline", url)
    except OSError as exc:
        return None, _issue("execution_failed", url, f"{type(exc).__name__}: errno={exc.errno}")
    if response.returncode:
        return None, _issue("worker_failed", url, f"exit={response.returncode}")
    try:
        if len(response.stdout) > 4096:
            raise ValueError("oversized worker reply")
        payload = json.loads(response.stdout)
        if not isinstance(payload, dict):
            raise ValueError("invalid worker reply")
        if "error" in payload:
            error = payload["error"]
            if not isinstance(error, str) or error not in _WORKER_ERRORS:
                raise ValueError("unknown worker error")
            status = payload.get("http_status")
            detail = f"HTTP {status}" if type(status) is int and 100 <= status <= 599 else error
            return None, _issue(error, url, detail)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("invalid worker data")
        return data, None
    except ValueError:
        return None, _issue("invalid_worker_reply", url)


def verify_session(*, timeout: float = 60, lock: dict[str, Any] | None = None) -> Verification:
    """Give all retries one deadline; reflectors cannot assert a Tor verdict."""
    if not 0 < timeout <= 3600:
        raise ValueError("verification timeout must be positive and at most 3600 seconds")
    deadline = boottime() + timeout
    credentials, identity_issue = _identity(lock)
    if identity_issue:
        return Verification(VerificationState.INCONCLUSIVE, identity_issue.reason, diagnostics=(identity_issue,))
    failures: list[Diagnostic] = []
    fallback_ip: str | None = None
    for _attempt in range(5):
        for url in ENDPOINTS:
            remaining = deadline - boottime()
            if remaining <= 0:
                failures.append(_issue("deadline", "verify"))
                return Verification(
                    VerificationState.INCONCLUSIVE, "probe.deadline", fallback_ip, boottime(), tuple(failures)
                )
            data, error = _fetch(url, min(15, remaining), credentials)
            if error:
                failures.append(error)
                if error.reason in {"probe.execution_failed", "probe.worker_failed", "probe.invalid_worker_reply"}:
                    return Verification(
                        VerificationState.INCONCLUSIVE, error.reason, fallback_ip, boottime(), tuple(failures)
                    )
                continue
            assert data is not None
            if url == ENDPOINTS[0]:
                verdict, address = data.get("IsTor"), _ip(data.get("IP"))
                if type(verdict) is bool and address is not None:
                    state = VerificationState.CONFIRMED if verdict else VerificationState.NEGATIVE
                    reason = "probe.tor_confirmed" if verdict else "probe.tor_negative"
                    # Earlier failed attempts remain inspectable but do not
                    # turn an eventual authoritative answer into an error.
                    history = tuple(replace(item, active=False) for item in failures)
                    return Verification(state, reason, address, boottime(), history)
                failures.append(_issue("authority_response_invalid", url))
            else:
                address = _ip(data.get("ip") or data.get("ip_addr"))
                if address:
                    fallback_ip = address
                    break
                failures.append(_issue("reflector_response_invalid", url))
        remaining = deadline - boottime()
        if _attempt < 4 and remaining > 0:
            time.sleep(min(3, remaining))
    return Verification(
        VerificationState.INCONCLUSIVE, "probe.no_authoritative_answer", fallback_ip, boottime(), tuple(failures)
    )
