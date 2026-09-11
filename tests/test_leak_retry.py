# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Coverage for the retry budget used by the offensive leak tests.

`tests/leak/` is excluded from the default suite (`--ignore=tests/leak` in
addopts) because those tests need a live TTP session and a real Tor circuit.
That leaves their retry helper with no coverage at all: `_ATTEMPTS` could
quietly go back to 1 and the flake it was introduced to fix would return with
nothing to report it. So the helper is loaded by path here and exercised
directly, in the suite that actually runs on every commit.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_MODULE_PATH = Path(__file__).resolve().parent / "leak" / "test_ip_leak.py"


def _load_leak_module():
    """Import `tests/leak/test_ip_leak.py` without collecting it as a test module."""
    spec = importlib.util.spec_from_file_location("_ttp_leak_ip", _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


leak_ip = _load_leak_module()


def _ok_response(body: bytes) -> MagicMock:
    """A urlopen() return value usable as a context manager."""
    response = MagicMock()
    response.__enter__.return_value.read.return_value = body
    return response


def test_fetch_retries_a_transient_failure_and_succeeds():
    """A dropped TLS handshake must not be the final answer.

    This is the 2026-09-11 failure in miniature: one `URLError` from an exit
    node that gave up mid-handshake, on a run whose identical tree had passed
    the same job minutes earlier.
    """
    attempts = [OSError("EOF occurred in violation of protocol"), _ok_response(b'{"IsTor": true}')]

    with (
        patch("urllib.request.urlopen", side_effect=attempts) as mock_urlopen,
        patch.object(leak_ip.time, "sleep") as mock_sleep,
    ):
        assert leak_ip._fetch("https://check.torproject.org/api/ip", timeout=10) == b'{"IsTor": true}'

    assert mock_urlopen.call_count == 2
    assert mock_sleep.call_count == 1
    assert mock_sleep.call_args[0][0] == leak_ip._BACKOFF_SECONDS


def test_fetch_gives_up_after_the_full_budget_and_reraises():
    """Exhausting the budget re-raises rather than inventing a verdict.

    The caller turns this into an explicit "transport failure, not a leak
    verdict". Swallowing it and returning something empty would let the leak
    assertions run against nothing - a check that could not fail.
    """
    last = OSError("still unreachable")
    failures = [OSError("nope")] * (leak_ip._ATTEMPTS - 1) + [last]

    with (
        patch("urllib.request.urlopen", side_effect=failures) as mock_urlopen,
        patch.object(leak_ip.time, "sleep") as mock_sleep,
        pytest.raises(OSError, match="still unreachable"),
    ):
        leak_ip._fetch("https://check.torproject.org/api/ip", timeout=10)

    assert mock_urlopen.call_count == leak_ip._ATTEMPTS
    # No sleep after the final attempt - that wait would buy nothing.
    assert mock_sleep.call_count == leak_ip._ATTEMPTS - 1


def test_the_retry_budget_is_not_silently_disarmed():
    """`_ATTEMPTS = 1` would restore the original single-shot behaviour.

    The two tests above would still pass with a budget of one if their fixtures
    were adjusted to match, so the budget itself is asserted here: it exists to
    mirror `ttp.tor_control.verify_tor`, which makes five attempts.
    """
    assert leak_ip._ATTEMPTS >= 5
    assert leak_ip._BACKOFF_SECONDS >= 1
