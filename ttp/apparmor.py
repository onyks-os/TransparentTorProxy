# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Mandatory confinement for managed Tor on AppArmor kernels.

Only root loads policy. Readers, including the unprivileged watchdog, inspect
the actual service process label; they do not need access to the policy store.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ttp import state
from ttp.exceptions import TorError
from ttp.paths import resolve

PROFILE = "ttp-tor"
LSM = Path("/sys/kernel/security/lsm")
ENABLED = Path("/sys/module/apparmor/parameters/enabled")
MODE = Path("/sys/module/apparmor/parameters/mode")
PROFILES = Path("/sys/kernel/security/apparmor/profiles")
PROC = Path("/proc")
POLICY_SOURCE = Path(__file__).with_name("ttp-tor.apparmor")
GUIDE = "https://github.com/onyks-os/TransparentTorProxy/blob/main/docs/web/how-to/apparmor.md"


class _TorInactive(Exception):
    """A definitely stopped daemon can follow the existing Tor healing path."""


def active() -> bool:
    """Distinguish a compiled module from an LSM selected by the running kernel.

    An unreadable securityfs is not evidence that AppArmor is disabled. Some
    kernels lack the LSM list; an explicitly disabled/absent module is the only
    safe fallback in that case.
    """
    try:
        names = LSM.read_text(encoding="ascii").strip().split(",")
    except FileNotFoundError:
        names = []
    except (OSError, UnicodeError) as exc:
        raise TorError(f"Cannot determine whether AppArmor is active. See {GUIDE}") from exc
    if names:
        if any(not name or not name.replace("_", "").isalnum() for name in names):
            raise TorError("Invalid kernel LSM evidence")
        return "apparmor" in names
    try:
        enabled = ENABLED.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return False
    except (OSError, UnicodeError) as exc:
        raise TorError("Cannot read AppArmor kernel state") from exc
    if enabled == "N":
        return False
    raise TorError(f"AppArmor may be active but its kernel evidence is unavailable. See {GUIDE}")


def prepare() -> dict[str, Any] | None:
    """Load TTP's own enforce policy, without changing a distribution profile."""
    if not active():
        return None
    try:
        # The process label reports the profile's mode, not the kernel-wide
        # override. Refuse a globally relaxed kernel at startup even when the
        # named profile itself says enforce. This root-only parameter cannot
        # be monitored by the unprivileged watchdog; root changes to global
        # policy have the same trust limit as replacement of policy contents.
        if MODE.read_text(encoding="ascii").strip() != "enforce":
            raise TorError("AppArmor must be in global enforce mode before starting managed Tor")
        container = subprocess.run(
            [resolve("systemd-detect-virt"), "--container", "--quiet"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if container.returncode != 1:
            raise TorError(f"Managed Tor with AppArmor requires a host or VM, not a container. See {GUIDE}")
        # A root-only writer prevents the Tor account, helpers and watchdog
        # from replacing the source submitted to the privileged policy parser.
        info = state.LOCK_DIR.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise TorError("Unsafe AppArmor policy directory")
        fd, name = tempfile.mkstemp(prefix=".apparmor-", dir=state.LOCK_DIR)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(POLICY_SOURCE.read_text(encoding="utf-8"))
            policy = state.LOCK_DIR / "ttp-tor.apparmor"
            temporary.replace(policy)
            subprocess.run(
                [resolve("apparmor_parser"), "--replace", "--skip-cache", str(policy)],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
            )
        finally:
            temporary.unlink(missing_ok=True)
        if f"{PROFILE} (enforce)" not in PROFILES.read_text(encoding="utf-8").splitlines():
            raise TorError("AppArmor profile ttp-tor is not loaded in enforce mode")
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise TorError(f"Cannot load and verify the required AppArmor profile. See {GUIDE}") from exc
    return {"required": True, "profile": PROFILE}


def _main_pid() -> int:
    result = subprocess.run(
        [resolve("systemctl"), "show", "ttp-tor.service", "-p", "ActiveState", "-p", "MainPID"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    pid = int(fields.get("MainPID", "0"))
    if fields.get("ActiveState") in ("inactive", "failed") and pid == 0:
        raise _TorInactive
    if fields.get("ActiveState") != "active" or pid <= 0:
        raise ValueError("Managed Tor is not active")
    return pid


def observe(policy: Any, tor_uid: int | None) -> dict[str, Any]:
    """Passive local evidence. A label is not proof of policy contents or safety.

    Require the exact enforce label and account of systemd's current MainPID.
    Prefer the LSM-specific attribute so stacked LSMs cannot be mistaken for
    AppArmor. Legacy fallback is only for kernels without that attribute.
    """
    result: dict[str, Any] = {
        "required": True,
        "profile": PROFILE,
        "state": "unknown",
        "reason": "apparmor.evidence_invalid",
    }
    if (
        not isinstance(policy, dict)
        or policy != {"required": True, "profile": PROFILE}
        or policy.get("required") is not True
        or type(tor_uid) is not int
        or tor_uid <= 0
    ):
        return result
    try:
        pid = _main_pid()
        process = PROC / str(pid)
        if process.stat().st_uid != tor_uid:
            raise ValueError("Managed Tor account differs")
        try:
            label = (process / "attr/apparmor/current").read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            label = (process / "attr/current").read_text(encoding="utf-8").strip()
        if _main_pid() != pid:
            raise ValueError("Managed Tor changed during observation")
        result.update(pid=pid, label=label)
        if label != f"{PROFILE} (enforce)":
            result.update(state="unverified", reason="apparmor.confinement_unverified")
        else:
            result.update(state="enforced", reason="apparmor.process_enforced")
    except _TorInactive:
        result["reason"] = "apparmor.tor_inactive"
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        pass
    return result
