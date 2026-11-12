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
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

#: Bumped whenever the artifact's field set changes in a way a reader must
#: notice. A reader that does not recognise the value must report INCONCLUSIVE
#: rather than parse what it can - a best-effort read of an unknown schema is
#: how a green result gets manufactured from a format change.
SCHEMA_VERSION = 2

ARTIFACT_DIR = Path(os.environ.get("TTP_LEAK_ARTIFACT_DIR", "/tmp/ttp-leak-artifacts"))


class Verdict(str, Enum):
    """What the probe is entitled to claim."""

    CONTAINED = "contained"
    LEAK = "leak"
    INCONCLUSIVE = "inconclusive"


class Outcome(str, Enum):
    """What the probe actually observed at the socket."""

    #: A socket refusal/silence observation. It does not identify the path.
    BLOCKED = "blocked"
    #: A well-formed answer came back. NOT decisive - see the module docstring.
    ANSWERED = "answered"
    #: Legacy proxy-origin label; without boundary evidence it is inconclusive.
    ANSWERED_BY_PROXY = "answered_by_proxy"
    #: Legacy reported egress label. It requires matching boundary evidence;
    #: a label alone cannot certify either containment or a leak.
    ESCAPED = "escaped"
    #: The probe could not run: DNS resolution of its own target failed, the
    #: address family is unavailable, the interface is down.
    UNREACHABLE = "unreachable"
    #: The probe was never attempted.
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True)
class BoundaryEvidence:
    """Exact-flow measurements from outside the protected network namespace.

    Counts refer to this probe's unique payload, not global firewall counters.
    Missing/incomplete capture cannot establish absence. An observed packet
    remains positive evidence even if the rest of the capture failed.
    """

    escaped: int
    control_before: int
    control_after: int
    capture_complete: bool
    stimulus_attempted: bool

    def __post_init__(self):
        for value in (self.escaped, self.control_before, self.control_after):
            if type(value) is not int or value < 0:
                raise ValueError("Invalid packet count")
        if type(self.capture_complete) is not bool or type(self.stimulus_attempted) is not bool:
            raise ValueError("Invalid capture evidence")


@dataclass(frozen=True)
class Observation:
    """Everything the probe saw, including what it could not see."""

    probe: str
    target: str
    outcome: Outcome
    session_active: bool
    detail: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    boundary: BoundaryEvidence | None = None


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

    evidence = observation.boundary
    if evidence is not None:
        if evidence.escaped:
            return Verdict.LEAK, "the external observer saw this probe's exact payload outside the protected namespace"
        if (
            evidence.capture_complete
            and evidence.stimulus_attempted
            and evidence.control_before > 0
            and evidence.control_after > 0
        ):
            return (
                Verdict.CONTAINED,
                "complete external capture with successful pre/post controls saw no matching egress",
            )
        return Verdict.INCONCLUSIVE, "external capture, stimulus or positive controls are incomplete"

    if observation.outcome in (Outcome.BLOCKED, Outcome.ANSWERED_BY_PROXY):
        return Verdict.INCONCLUSIVE, "socket refusal, silence or reply shape alone does not establish the network path"

    if observation.outcome is Outcome.ESCAPED:
        return Verdict.INCONCLUSIVE, "an egress label without a matching external observation is unproven"

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
        saved = Verdict(payload["verdict"])
        observation = observation_from_dict(payload)
        derived, reason = verdict_for(observation)
        if saved is not derived:
            return Verdict.INCONCLUSIVE, "saved verdict differs from its measurement evidence"
        return derived, reason
    except (KeyError, TypeError, ValueError):
        return Verdict.INCONCLUSIVE, f"artifact carries no verdict this reader recognises: {payload.get('verdict')!r}"


def observation_from_dict(payload: dict) -> Observation:
    """Validate serialized evidence instead of trusting a saved green label."""
    if type(payload["session_active"]) is not bool:
        raise ValueError("Invalid session evidence")
    for key in ("probe", "target", "detail", "observed_at"):
        if not isinstance(payload[key], str):
            raise ValueError("Invalid observation field")
    boundary = payload.get("boundary")
    return Observation(
        probe=payload["probe"],
        target=payload["target"],
        outcome=Outcome(payload["outcome"]),
        session_active=payload["session_active"],
        detail=payload["detail"],
        observed_at=payload["observed_at"],
        boundary=BoundaryEvidence(**boundary) if boundary is not None else None,
    )


def measured_observation(probe: str) -> Observation:
    """Read the completed external fixture's historical measurement.

    The report is finalized only after explicit stop and successful post-stop
    controls. It describes the protected window, not the current session state.
    """
    try:
        report = json.loads(Path(os.environ["TTP_BOUNDARY_REPORT"]).read_text())
        if (
            report["schema"] != SCHEMA_VERSION
            or report["run_id"] != os.environ["TTP_BOUNDARY_RUN"]
            or report["complete"] is not True
        ):
            raise ValueError("Mismatched or unfinished boundary measurement")
        observation = observation_from_dict(report["observations"][probe])
        if observation.probe != probe or observation.boundary is None:
            raise ValueError("Wrong measurement identity")
        return observation
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return Observation(probe, "unknown", Outcome.NOT_ATTEMPTED, False, f"Boundary evidence unavailable: {exc}")


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


def redirect_delta(before: int | None, after: int | None) -> int | None:
    """How many packets the redirect rule matched between two readings.

    ``None`` whenever the pair cannot support a count:

    * either reading failed - ``read_counters`` returns an absent entry rather
      than 0 when nft cannot be reached or the table is gone, and subtracting
      one of those would turn "could not measure" into "did not redirect";
    * the second reading is lower than the first, which means the table was
      destroyed and rebuilt between them (``ttp restart`` resets every counter).
      The readings then belong to different rulesets, and their difference
      describes nothing.

    Zero is a real counter difference, not per-query evidence. Neither zero nor
    a positive difference establishes the path of an individual probe.
    """
    if before is None or after is None:
        return None
    if after < before:
        return None
    return after - before
