# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
The verdict layer for the offensive leak probes.

Why this module exists
----------------------

Every probe in this package used to decide its own verdict inline, and every one
of them reached the same shape::

    try:
        ...send the packet...
        assert response_is_well_formed
    except TimeoutError:
        pass          # "success: the packet was blocked"
    except OSError:
        pass          # "success: the socket errored"

There is no path through that code which fails. Worse, the path that looks like
the strict one is the weakest: a well-formed DNS answer is exactly what you get
**both** when TTP redirected the query to Tor's DNSPort **and** when the query
leaked in cleartext to the resolver it was addressed to. The external resolver
answers with the same transaction ID and the same response bit. The probe scored
that as "safely intercepted" either way, and it scored it that way whether or not
a TTP session existed at all.

So the probes were not measuring containment. They were measuring that a socket
call returned.

The design
----------

Three verdicts, not two. ``CONTAINED`` and ``LEAK`` are claims about the host;
``INCONCLUSIVE`` is a claim about the probe, and it is **red**, because a check
that could not measure has not produced evidence of safety.

The verdict is derived from a recorded :class:`Observation` rather than from
control flow, and it is written to an artifact before it is asserted on. That
ordering is the point: an exception raised anywhere in a probe cannot produce an
artifact, so a crashed probe reads as ``INCONCLUSIVE`` rather than as a silent
pass. A missing file, an unparseable file, or a schema this code does not
recognise are all the same verdict for the same reason.

See https://github.com/onyks-os/TransparentTorProxy/issues/26.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

#: Bumped whenever the artifact's field set changes in a way a reader must
#: notice. A reader that does not recognise the value must report INCONCLUSIVE
#: rather than parse what it can - a best-effort read of an unknown schema is
#: how a green result gets manufactured from a format change.
SCHEMA_VERSION = 1

ARTIFACT_DIR = Path(os.environ.get("TTP_LEAK_ARTIFACT_DIR", "/tmp/ttp-leak-artifacts"))


class Verdict(str, Enum):
    """What the probe is entitled to claim."""

    CONTAINED = "contained"
    LEAK = "leak"
    INCONCLUSIVE = "inconclusive"


class Outcome(str, Enum):
    """What the probe actually observed at the socket."""

    #: The packet was refused or silently dropped - a timeout, ICMP unreachable,
    #: or ECONNREFUSED. Decisive: something stopped it leaving.
    BLOCKED = "blocked"
    #: A well-formed answer came back. NOT decisive - see the module docstring.
    ANSWERED = "answered"
    #: An answer came back and carries positive proof it did not come from the
    #: address the probe was sent to.
    ANSWERED_BY_PROXY = "answered_by_proxy"
    #: An answer came back that only the addressed host could have produced, so
    #: the packet left in cleartext. Decisive in the other direction. Applies to
    #: protocols TTP does not redirect at all - STUN over UDP/19302, for
    #: instance - where any reply is proof of escape.
    ESCAPED = "escaped"
    #: The probe could not run: DNS resolution of its own target failed, the
    #: address family is unavailable, the interface is down.
    UNREACHABLE = "unreachable"
    #: The probe was never attempted.
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True)
class Observation:
    """Everything the probe saw, including what it could not see."""

    probe: str
    target: str
    outcome: Outcome
    session_active: bool
    detail: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def verdict_for(observation: Observation) -> tuple[Verdict, str]:
    """Derive the verdict and the reason it was reached.

    The ordering matters. The session check comes first because without a live
    TTP session *no* socket outcome says anything about TTP: a blocked packet
    on a host with no session was blocked by something else, and calling that
    ``CONTAINED`` credits TTP for a firewall it did not install.
    """
    if not observation.session_active:
        return (
            Verdict.INCONCLUSIVE,
            "no active TTP session: this probe cannot attribute any outcome to TTP",
        )

    if observation.outcome is Outcome.BLOCKED:
        return Verdict.CONTAINED, "the packet was refused or dropped before leaving the host"

    if observation.outcome is Outcome.ANSWERED_BY_PROXY:
        return Verdict.CONTAINED, "the answer carries proof it was not produced by the addressed host"

    if observation.outcome is Outcome.ESCAPED:
        return Verdict.LEAK, "the addressed host answered, so the packet left the machine in cleartext"

    if observation.outcome is Outcome.ANSWERED:
        return (
            Verdict.INCONCLUSIVE,
            "the answer's shape is produced both by a redirect to Tor and by a "
            "cleartext leak to the addressed resolver; this probe cannot tell "
            "them apart",
        )

    if observation.outcome is Outcome.UNREACHABLE:
        return Verdict.INCONCLUSIVE, "the probe could not reach its own target"

    return Verdict.INCONCLUSIVE, f"unhandled outcome {observation.outcome!r}"


def record(observation: Observation) -> Path:
    """Write the artifact for *observation* and return its path.

    Called by the probe, never by a wrapper around the probe. A wrapper that
    writes the artifact on the probe's behalf can write one for a probe that
    crashed, which is precisely the property this design exists to remove.
    """
    verdict, reason = verdict_for(observation)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    path = ARTIFACT_DIR / f"{observation.probe}.json"
    payload = {
        "schema": SCHEMA_VERSION,
        **asdict(observation),
        "outcome": observation.outcome.value,
        "verdict": verdict.value,
        "reason": reason,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def read_verdict(path: Path) -> tuple[Verdict, str]:
    """Read a verdict back from an artifact, failing closed on every doubt."""
    try:
        raw = path.read_text()
    except OSError as exc:
        return Verdict.INCONCLUSIVE, f"artifact could not be read: {exc}"

    try:
        payload = json.loads(raw)
    except ValueError as exc:
        return Verdict.INCONCLUSIVE, f"artifact is not valid JSON: {exc}"

    if not isinstance(payload, dict):
        return Verdict.INCONCLUSIVE, "artifact is not a JSON object"

    if payload.get("schema") != SCHEMA_VERSION:
        return (
            Verdict.INCONCLUSIVE,
            f"artifact schema {payload.get('schema')!r} is not the {SCHEMA_VERSION} this reader understands",
        )

    try:
        return Verdict(payload["verdict"]), str(payload.get("reason", ""))
    except (KeyError, ValueError):
        return Verdict.INCONCLUSIVE, f"artifact carries no verdict this reader recognises: {payload.get('verdict')!r}"


def assert_contained(observation: Observation) -> None:
    """Record *observation*, then fail unless the artifact says CONTAINED.

    ``INCONCLUSIVE`` fails. That is the whole change: the probe no longer has a
    way to report success without having produced evidence for it.
    """
    path = record(observation)
    verdict, reason = read_verdict(path)
    assert verdict is Verdict.CONTAINED, (
        f"{observation.probe}: {verdict.value.upper()} - {reason}\n"
        f"  target:   {observation.target}\n"
        f"  outcome:  {observation.outcome.value}\n"
        f"  detail:   {observation.detail or '(none)'}\n"
        f"  artifact: {path}"
    )


def session_is_active() -> bool:
    """True when a TTP lock file exists, i.e. when there is something to test."""
    from ttp import state

    return state.read_lock() is not None
