# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""
Tests for ``run_watchdog_loop`` - the event loop, not the event decoding.

``tests/test_ux_and_events.py`` covers ``inotify_watch_lost``, which is a pure
function. What was left uncovered is the loop around it, and the loop is where
the watchdog's guarantees actually live:

* an unexpected exception anywhere in the loop must escalate to ``tamper``,
  not kill the daemon quietly. A watchdog that dies without saying so leaves
  the user believing they are protected while nothing is watching;
* a signal (EINTR) must not be mistaken for that kind of failure;
* the FSM must be shut down on every exit path.

Every test here drives the loop to a controlled termination by exhausting a
``read_lock`` side-effect list ending in ``None``, which is the loop's own
graceful-exit condition (``inotify.py:84-86``).
"""

from __future__ import annotations

import struct
import time
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ttp.watchdog.inotify import IN_DELETE_SELF, run_watchdog_loop

LOCK = {"interface": "eth0", "pid": 123}


def _fsm(state: str = "healthy", inotify_fd: int = 7, in_cooldown: bool = False) -> MagicMock:
    """A WatchdogFSM double whose scalars are real values, not MagicMocks.

    The loop compares these with ``>=``, ``-`` and ``in``, which a bare
    MagicMock attribute would raise on rather than answer.
    """
    fsm = MagicMock()
    fsm.state = state
    fsm.inotify_fd = inotify_fd
    fsm.netlink_socket = None
    fsm.COOLDOWN_SECONDS = 2.0
    fsm.last_heal_time = time.time() if in_cooldown else 0.0
    fsm.last_check_time = 0.0
    return fsm


@contextmanager
def _loop_env(
    fsm: MagicMock,
    locks: list,
    integrity: object = (None, ""),
    readable: list | None = None,
    online: object = True,
    route: object = True,
    select_effect: object = None,
):
    """Patch every boundary the loop touches; yield the mocks worth asserting on."""
    with ExitStack() as stack:
        stack.enter_context(patch("ttp.watchdog.inotify.WatchdogFSM", return_value=fsm))
        read_lock = stack.enter_context(patch("ttp.state.read_lock", side_effect=locks))
        stack.enter_context(patch("ttp.watchdog.inotify.time.sleep"))
        stack.enter_context(
            patch("ttp.watchdog.inotify.is_interface_online", **_effect(online))  # type: ignore[arg-type]
        )
        stack.enter_context(patch("ttp.watchdog.inotify.has_default_route", **_effect(route)))  # type: ignore[arg-type]
        if select_effect is not None:
            stack.enter_context(patch("ttp.watchdog.inotify.select.select", side_effect=select_effect))
        else:
            stack.enter_context(patch("ttp.watchdog.inotify.select.select", return_value=(readable or [], [], [])))
        integ = stack.enter_context(
            patch("ttp.watchdog.inotify.check_system_integrity", **_effect(integrity))  # type: ignore[arg-type]
        )
        yield SimpleNamespace(integrity=integ, read_lock=read_lock)


def _effect(value: object) -> dict:
    """Pass a list as side_effect and anything else as return_value."""
    return {"side_effect": value} if isinstance(value, list) else {"return_value": value}


def _event(mask: int) -> bytes:
    """One packed struct inotify_event with no trailing name."""
    return struct.pack("iIII", 1, mask, 0, 0)


# ---------------------------------------------------------------------------
# The guarantee: a loop that dies must say so
# ---------------------------------------------------------------------------


def test_an_unexpected_failure_escalates_to_tamper() -> None:
    """
    This is the branch the whole daemon rests on (``inotify.py:178-181``).

    Without it, any unhandled exception ends the loop silently: the process
    exits, the lock file stays, ``ttp status`` still reports the watchdog as
    active, and nothing is watching the firewall. The escalation to ``tamper``
    is what converts an internal bug into a visible, fail-closed event.
    """
    fsm = _fsm()
    with _loop_env(fsm, locks=[RuntimeError("netlink went away")]):
        run_watchdog_loop()

    assert fsm.tamper.call_count == 1
    assert fsm.tamper.call_args.kwargs["failed_comp"] == "watchdog"
    assert "netlink went away" in fsm.tamper.call_args.kwargs["err_msg"]


def test_a_loop_already_in_killswitch_is_not_tampered_again() -> None:
    """Once the killswitch has fired the host is already isolated; re-entering
    the tamper transition from the exception handler would be a second, spurious
    escalation of a state that is terminal by design."""
    fsm = _fsm(state="killswitch")
    with _loop_env(fsm, locks=[RuntimeError("boom")]):
        run_watchdog_loop()

    assert fsm.tamper.call_count == 0


@pytest.mark.parametrize(
    "locks",
    [
        pytest.param([RuntimeError("boom")], id="crash"),
        pytest.param([None], id="graceful-exit"),
    ],
)
def test_the_fsm_is_shut_down_on_every_exit_path(locks: list) -> None:
    """``shutdown`` releases the netlink socket and the inotify fd. A path that
    skips it leaks both for the lifetime of the parent process."""
    fsm = _fsm()
    with _loop_env(fsm, locks=locks):
        run_watchdog_loop()

    assert fsm.shutdown.call_count == 1


def test_a_failed_initialization_never_enters_the_loop() -> None:
    """``initialize`` raising means there are no fds to watch, so the loop
    returns before the ``try``/``finally`` (``inotify.py:71-75``).

    ``shutdown`` is deliberately *not* called here, and that is correct rather
    than an oversight: ``WatchdogFSM.initialize`` closes its own netlink socket
    when the inotify half fails (``fsm.py:229-231``), so there is nothing left
    for the loop to release.
    """
    fsm = _fsm()
    fsm.initialize.side_effect = OSError("inotify_init: too many open files")
    with _loop_env(fsm, locks=[LOCK, None]) as mocks:
        run_watchdog_loop()

    assert mocks.integrity.call_count == 0
    assert fsm.shutdown.call_count == 0
    assert fsm.tamper.call_count == 0


# ---------------------------------------------------------------------------
# A signal is not a failure
# ---------------------------------------------------------------------------


def test_an_interrupted_select_is_retried_rather_than_escalated() -> None:
    """EINTR (``inotify.py:130-132``) is ordinary: any signal delivered to the
    process interrupts ``select``. Without the handler it would reach the outer
    ``except`` and fire a tamper, isolating the host because a signal arrived."""
    fsm = _fsm()
    with _loop_env(
        fsm,
        locks=[LOCK, None],
        select_effect=[InterruptedError(), ([], [], [])],
    ) as mocks:
        run_watchdog_loop()

    assert fsm.tamper.call_count == 0
    assert mocks.integrity.call_count == 0  # the retry skipped the check, it did not run it


# ---------------------------------------------------------------------------
# Debounce, inotify handling, link loss
# ---------------------------------------------------------------------------


def test_events_arriving_during_the_heal_cooldown_are_discarded() -> None:
    """After a heal the loop refuses to re-check for COOLDOWN_SECONDS, and must
    drain the fds it is ignoring - an undrained fd stays readable and spins
    ``select`` at full CPU (``inotify.py:137-140``)."""
    fsm = _fsm(in_cooldown=True)
    with _loop_env(fsm, locks=[LOCK, None], readable=[7]) as mocks:
        run_watchdog_loop()

    assert fsm.flush_event_buffers.call_args[0][0] == [7]
    assert mocks.integrity.call_count == 0


def test_a_lost_inotify_watch_is_re_added() -> None:
    """A DELETE_SELF on /etc/resolv.conf means the DNS overlay was replaced.
    The watch is gone with it, so re-arming it is what keeps the next tamper
    observable (``inotify.py:149-152``)."""
    fsm = _fsm()
    with (
        _loop_env(fsm, locks=[LOCK, None], readable=[7]),
        patch("ttp.watchdog.inotify.os.read", return_value=_event(IN_DELETE_SELF)),
    ):
        run_watchdog_loop()

    assert fsm.readd_watch.call_count == 1


def test_an_unreadable_inotify_fd_is_logged_and_survived(caplog: pytest.LogCaptureFixture) -> None:
    """The handler at ``inotify.py:155-156`` swallows the error and continues.

    That is a deliberate trade - the integrity check below it still runs, so
    the loop keeps its 15s polling guarantee - but it is worth stating plainly:
    after this branch the watch has *not* been re-added, so the loop continues
    with no event-driven visibility into resolv.conf until the next lost-watch
    event it can actually read. The warning is the only trace.
    """
    fsm = _fsm()
    with (
        caplog.at_level("WARNING", logger="ttp"),
        _loop_env(fsm, locks=[LOCK, None], readable=[7]) as mocks,
        patch("ttp.watchdog.inotify.os.read", side_effect=OSError("EBADF")),
    ):
        run_watchdog_loop()

    assert "Error processing inotify data" in caplog.text
    assert fsm.readd_watch.call_count == 0
    assert fsm.tamper.call_count == 0
    assert mocks.integrity.call_count == 1  # the check below it still ran


def test_a_would_block_read_is_not_worth_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """The fd is non-blocking (``fsm.py:225``), so EAGAIN is expected, not a
    fault, and is handled separately from the warning path."""
    fsm = _fsm()
    with (
        caplog.at_level("WARNING", logger="ttp"),
        _loop_env(fsm, locks=[LOCK, None], readable=[7]),
        patch("ttp.watchdog.inotify.os.read", side_effect=BlockingIOError()),
    ):
        run_watchdog_loop()

    assert "Error processing inotify data" not in caplog.text
    assert fsm.readd_watch.call_count == 0


def test_stopping_the_session_during_an_outage_exits_the_watchdog() -> None:
    """Without the lock re-read at ``inotify.py:103-105`` the offline loop has
    no exit condition: ``ttp stop`` during a network outage would leave the
    watchdog spinning on a session that no longer exists."""
    fsm = _fsm()
    with _loop_env(fsm, locks=[LOCK, None, None], online=False, route=False):
        run_watchdog_loop()

    assert fsm.disconnect.call_count == 1
    assert fsm.reconnect.call_count == 0
    assert fsm.shutdown.call_count == 1
    # The assertion that actually pins the branch: a deliberate `ttp stop` is
    # not tampering. Without the inner lock re-read the loop walks on into
    # `lock.get(...)` on a None lock, and that exception reaches the outer
    # handler - which would isolate the host because the user stopped TTP.
    assert fsm.tamper.call_count == 0


def test_the_link_coming_back_reconnects_rather_than_exiting() -> None:
    """The offline loop's other exit: the interface returns and the FSM is told,
    instead of the watchdog treating the outage as terminal."""
    fsm = _fsm()
    with _loop_env(
        fsm,
        locks=[LOCK, LOCK, LOCK, None],
        online=[False, True],
        route=[True, True],
    ):
        run_watchdog_loop()

    assert fsm.reconnect.call_count == 1
    assert fsm.shutdown.call_count == 1


# ---------------------------------------------------------------------------
# Integrity outcomes
# ---------------------------------------------------------------------------


def test_a_killswitch_transition_ends_the_loop() -> None:
    """Once isolated there is nothing left to watch, and continuing would keep
    re-reporting a failure the FSM has already acted on (``inotify.py:165-166``)."""
    fsm = _fsm()
    fsm.integrity_fail.side_effect = lambda **_: setattr(fsm, "state", "killswitch")
    with _loop_env(fsm, locks=[LOCK, LOCK, None], integrity=("firewall", "table vanished")) as mocks:
        run_watchdog_loop()

    assert fsm.integrity_fail.call_count == 1
    assert fsm.heal_fail.call_count == 0
    assert fsm.shutdown.call_count == 1
    # Asserting on integrity_fail alone does not pin this branch: the 15s
    # debouncer suppresses the second check anyway, so the loop would spin
    # quietly rather than re-report. The lock read count is what shows it
    # stopped - exactly one pass through the loop.
    assert mocks.read_lock.call_count == 1


def test_a_heal_that_holds_is_confirmed() -> None:
    """The re-verification at ``inotify.py:169-176`` is what makes healing a
    claim about the host rather than about the healing command's exit code."""
    fsm = _fsm()
    fsm.integrity_fail.side_effect = lambda **_: setattr(fsm, "state", "healing")
    with _loop_env(fsm, locks=[LOCK, None], integrity=[("dns", "overlay gone"), (None, "")]):
        run_watchdog_loop()

    assert fsm.heal_success.call_count == 1
    assert fsm.heal_fail.call_count == 0


def test_a_heal_that_did_not_hold_fails_closed() -> None:
    """If the second check still fails, the heal did not work. Reporting success
    here would be the same defect as an oracle that cannot fail."""
    fsm = _fsm()
    fsm.integrity_fail.side_effect = lambda **_: setattr(fsm, "state", "healing")
    with _loop_env(
        fsm,
        locks=[LOCK, None],
        integrity=[("dns", "overlay gone"), ("dns", "overlay still gone")],
    ):
        run_watchdog_loop()

    assert fsm.heal_success.call_count == 0
    assert fsm.heal_fail.call_count == 1
    assert fsm.heal_fail.call_args.kwargs["failed_comp"] == "dns"
