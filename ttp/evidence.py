# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Typed observations and deterministic result selection, without side effects.

An operation's exit code is a projection of all its diagnostics, never a reason
to discard concurrent errors. A timestamp belongs to a boot, session and service
instance; it cannot attest the replacement process is doing useful work.
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass
from enum import Enum, IntEnum
from typing import Any


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    USAGE = 2
    UNVERIFIED = 3
    DNSSEC_CONFLICT = 4
    WATCHDOG_UNAVAILABLE = 5
    TOR_NEGATIVE = 6
    EMERGENCY_VERIFIED = 7
    CONTAINMENT_UNCONFIRMED = 8
    NOTIFICATION_FAILED = 9


_PRIORITY = {
    ExitCode.OK: 0,
    ExitCode.UNVERIFIED: 10,
    ExitCode.NOTIFICATION_FAILED: 20,
    ExitCode.ERROR: 25,
    ExitCode.WATCHDOG_UNAVAILABLE: 30,
    ExitCode.TOR_NEGATIVE: 40,
    ExitCode.EMERGENCY_VERIFIED: 50,
    ExitCode.CONTAINMENT_UNCONFIRMED: 60,
    # Preflight refusals do not participate in normal session evaluation.
    ExitCode.USAGE: 70,
    ExitCode.DNSSEC_CONFLICT: 70,
}


class VerificationState(str, Enum):
    NOT_RUN = "not_run"
    CONFIRMED = "confirmed"
    NEGATIVE = "negative"
    INCONCLUSIVE = "inconclusive"


class DeliveryState(str, Enum):
    DISABLED = "disabled"
    PENDING = "pending"
    ACCEPTED = "accepted"
    UNCONFIRMED = "unconfirmed"
    FAILED = "failed"


@dataclass(frozen=True)
class Diagnostic:
    code: ExitCode
    reason: str
    component: str
    operation: str
    message: str
    active: bool = True

    def as_dict(self) -> dict[str, Any]:
        phase = {"start": "startup", "stop": "teardown", "terminate": "supervision", "supervise": "supervision"}.get(
            self.operation, "session"
        )
        return {**asdict(self), "code": int(self.code), "phase": phase}

    @classmethod
    def from_dict(cls, value: object) -> Diagnostic:
        if not isinstance(value, dict) or type(value.get("code")) is not int:
            raise ValueError("Invalid diagnostic code")
        if any(not isinstance(value.get(key), str) for key in ("reason", "component", "operation", "message")):
            raise ValueError("Invalid diagnostic fields")
        if type(value.get("active", True)) is not bool:
            raise ValueError("Invalid diagnostic activity")
        return cls(
            ExitCode(value["code"]),
            value["reason"],
            value["component"],
            value["operation"],
            value["message"],
            value.get("active", True),
        )


@dataclass(frozen=True)
class Result:
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def exit_code(self) -> ExitCode:
        return max(
            (item.code for item in self.diagnostics if item.active),
            key=lambda code: _PRIORITY[code],
            default=ExitCode.OK,
        )

    def add(self, *diagnostics: Diagnostic) -> Result:
        return Result(self.diagnostics + tuple(diagnostics))

    def as_dict(self) -> dict[str, Any]:
        return {"exit_code": int(self.exit_code), "diagnostics": [item.as_dict() for item in self.diagnostics]}


@dataclass(frozen=True)
class Observation:
    value: str
    session_id: str
    boot_id: str
    instance_id: str
    observed_at: float
    reason: str = ""

    def is_current(self, *, session_id: str, boot_id: str, instance_id: str, now: float, max_age: float) -> bool:
        if not session_id or not boot_id or not instance_id:
            return False
        if (self.session_id, self.boot_id, self.instance_id) != (session_id, boot_id, instance_id):
            return False
        if not all(math.isfinite(value) for value in (now, self.observed_at, max_age)) or max_age <= 0:
            return False
        return 0 <= now - self.observed_at < max_age


def boottime() -> float:
    """Linux suspend-aware clock; never substitute a mutable wall clock."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


@dataclass(frozen=True)
class Verification:
    state: VerificationState
    reason: str
    ip: str | None = None
    observed_at: float | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def confirmed(self) -> bool:
        return self.state is VerificationState.CONFIRMED

    @property
    def result(self) -> Result:
        if self.state is VerificationState.CONFIRMED:
            return Result(self.diagnostics)
        code = ExitCode.TOR_NEGATIVE if self.state is VerificationState.NEGATIVE else ExitCode.UNVERIFIED
        return Result(self.diagnostics).add(Diagnostic(code, self.reason, "tor", "verify", self.state.value))
