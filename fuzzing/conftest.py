"""Hypothesis profiles for the fuzzing suite.

Pull requests run the fast `ci` profile so review stays quick; the weekly
scheduled workflow runs `ci-deep`, which explores far more of the input space.
Select one with `HYPOTHESIS_PROFILE=ci-deep pytest fuzzing/`.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, Verbosity, settings

settings.register_profile(
    "dev",
    max_examples=50,
    verbosity=Verbosity.normal,
)

settings.register_profile(
    "ci",
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.register_profile(
    "ci-deep",
    max_examples=10_000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))
