# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Untrusted network input is handled by an unprivileged process.

`ttp start` runs as root and verifies Tor by fetching JSON from
check.torproject.org and two IP echo services: TLS, HTTP and JSON parsing of
data a third party chose, in the most privileged process on the host. As root,
that now happens in a child running as `nobody`, which hands back only the four
fields TTP reads, reduced to their types and lengths; root validates them again.
`nobody` rather than the invoking user because it is never in a bypass list, so
the probe always goes through Tor.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from ttp import netprobe, tor_control

URL = tor_control.VERIFY_ENDPOINTS[0]


# The child: what it may hand back -------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"IsTor": True, "IP": "185.220.101.1"}, {"IsTor": True, "IP": "185.220.101.1"}),
        ({"ip": "203.0.113.5", "junk": "x" * 10_000}, {"ip": "203.0.113.5"}),
        ({"IP": "x" * 200}, {}),  # longer than any address: dropped, not truncated
        ({"IsTor": "yes"}, {}),  # a verdict must be a real boolean
        ({"ip_addr": 7}, {}),
        (["not", "an", "object"], None),
    ],
)
def test_the_child_hands_back_only_the_fields_ttp_reads(payload, expected):
    assert netprobe.reduce(payload) == expected


def test_the_child_prints_one_json_line(capsys):
    with patch.object(netprobe, "fetch", return_value={"IsTor": False, "IP": "198.51.100.9", "extra": 1}):
        assert netprobe.main([URL]) == 0
    assert json.loads(capsys.readouterr().out) == {"IsTor": False, "IP": "198.51.100.9"}


def test_the_child_refuses_urls_that_are_not_ttps_endpoints(capsys):
    """Its argv comes from root, but it should still do only its one job."""
    assert netprobe.main(["https://example.invalid/steal"]) == 2


# The parent: who runs it --------------------------------------------------------


def _as_root():
    return patch.object(tor_control.os, "geteuid", return_value=0)


def test_as_root_the_fetch_runs_as_nobody():
    done = subprocess.CompletedProcess([], 0, stdout='{"IsTor": true, "IP": "185.220.101.1"}\n', stderr="")
    with (
        _as_root(),
        patch.object(tor_control.pwd, "getpwnam", return_value=MagicMock(pw_uid=65534, pw_gid=65534)),
        patch.object(tor_control.subprocess, "run", return_value=done) as run,
    ):
        assert tor_control._fetch_endpoint(URL) == {"IsTor": True, "IP": "185.220.101.1"}
    kwargs = run.call_args.kwargs
    assert (kwargs["user"], kwargs["group"], kwargs["extra_groups"]) == (65534, 65534, [])
    argv = run.call_args.args[0]
    assert argv[1:4] == ["-I", "-m", "ttp.netprobe"] and argv[-1] == URL


def test_as_root_a_malformed_answer_from_the_child_is_no_answer():
    for bad in ('{"IsTor": "yes"}', "not json", '{"IP": "' + "9" * 100 + '"}', "[1,2]", "x" * 70_000):
        done = subprocess.CompletedProcess([], 0, stdout=bad, stderr="")
        with (
            _as_root(),
            patch.object(tor_control.pwd, "getpwnam", return_value=MagicMock(pw_uid=65534, pw_gid=65534)),
            patch.object(tor_control.subprocess, "run", return_value=done),
        ):
            result = tor_control._fetch_endpoint(URL)
        assert result in (None, {}), bad


def test_as_root_an_unreachable_endpoint_is_no_answer():
    done = subprocess.CompletedProcess([], 0, stdout="null\n", stderr="")
    with (
        _as_root(),
        patch.object(tor_control.pwd, "getpwnam", return_value=MagicMock(pw_uid=65534, pw_gid=65534)),
        patch.object(tor_control.subprocess, "run", return_value=done),
    ):
        assert tor_control._fetch_endpoint(URL) is None


def test_if_the_child_cannot_start_the_fetch_falls_back_and_says_so():
    """A pipx install under a home directory is unreadable by nobody. The check
    still runs, in-process as before, and the log says why."""
    failed = subprocess.CompletedProcess([], 1, stdout="", stderr="ModuleNotFoundError: No module named 'ttp'")
    with (
        _as_root(),
        patch.object(tor_control.pwd, "getpwnam", return_value=MagicMock(pw_uid=65534, pw_gid=65534)),
        patch.object(tor_control.subprocess, "run", return_value=failed),
        patch.object(tor_control, "_fetch_in_process", return_value={"IP": "203.0.113.5"}) as fallback,
        patch.object(tor_control.logger, "warning") as warning,
    ):
        assert tor_control._fetch_endpoint(URL) == {"IP": "203.0.113.5"}
    fallback.assert_called_once_with(URL)
    assert "unprivileged" in str(warning.call_args)


def test_a_child_that_hangs_is_no_answer():
    with (
        _as_root(),
        patch.object(tor_control.pwd, "getpwnam", return_value=MagicMock(pw_uid=65534, pw_gid=65534)),
        patch.object(tor_control.subprocess, "run", side_effect=subprocess.TimeoutExpired("python", 25)),
    ):
        assert tor_control._fetch_endpoint(URL) is None


def test_without_root_the_fetch_stays_in_process():
    with (
        patch.object(tor_control.os, "geteuid", return_value=1000),
        patch.object(tor_control, "_fetch_in_process", return_value={"ip": "203.0.113.5"}) as direct,
        patch.object(tor_control.subprocess, "run") as run,
    ):
        assert tor_control._fetch_endpoint(URL) == {"ip": "203.0.113.5"}
    direct.assert_called_once_with(URL)
    run.assert_not_called()


def test_the_child_and_the_parent_agree_on_the_endpoints():
    assert tuple(tor_control.VERIFY_ENDPOINTS) == netprobe.ENDPOINTS


def test_the_child_reads_a_bounded_body_and_parses_it():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"IP": "185.220.101.1", "IsTor": true}'
    with patch.object(netprobe.urllib.request, "urlopen", return_value=response):
        assert netprobe.fetch(URL) == {"IP": "185.220.101.1", "IsTor": True}
    response.read.assert_called_once_with(netprobe._MAX_BODY)


@pytest.mark.parametrize("error", [OSError("unreachable"), TimeoutError(), ValueError("bad json")])
def test_the_child_turns_any_failure_into_no_answer(error):
    with patch.object(netprobe.urllib.request, "urlopen", side_effect=error):
        assert netprobe.fetch(URL) is None


def test_without_a_nobody_account_the_conventional_ids_are_used():
    done = subprocess.CompletedProcess([], 0, stdout="null", stderr="")
    with (
        _as_root(),
        patch.object(tor_control.pwd, "getpwnam", side_effect=KeyError("nobody")),
        patch.object(tor_control.subprocess, "run", return_value=done) as run,
    ):
        tor_control._fetch_endpoint(URL)
    assert (run.call_args.kwargs["user"], run.call_args.kwargs["group"]) == (65534, 65534)
