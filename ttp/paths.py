# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Trusted resolution of the external binaries TTP executes as root.

Why this module exists
----------------------

TTP runs as root and shells out to ``nft``, ``ip``, ``systemctl`` and a dozen
others. Passing a bare name to :mod:`subprocess` makes the kernel resolve it
through ``$PATH`` - so anyone who can influence the environment of the ``sudo``
invocation can put their own ``nft`` earlier in the search order and have it
executed with full privileges. That is a local privilege escalation in a tool
whose entire job is to be trusted with the network stack.

``sudo`` usually blunts this with ``secure_path``, but "usually" is not a
security property: it is a distribution default that an administrator can
disable and that is not enabled everywhere TTP supports.

So TTP does not use ``$PATH``. It resolves every binary against a fixed list of
root-owned system directories, and refuses to execute one that is writable by
anybody but root.

Usage
-----

    from ttp.paths import resolve

    subprocess.run([resolve("nft"), "list", "ruleset"], ...)

The result is cached, so the cost is one ``stat`` per binary per process.
"""

from __future__ import annotations

import os
import stat
from functools import cache
from pathlib import Path

from ttp.exceptions import TTPError

#: Where a system binary may legitimately live, in search order.
#:
#: sbin first: ``nft``, ``ip`` and ``systemctl`` live there on every supported
#: distribution, and on merged-/usr systems the bin entries are symlinks to the
#: same files. ``/usr/local`` is included last because a locally built ``tor`` is
#: a legitimate setup, and excluded from nothing else: it is still checked for
#: safe ownership like every other candidate.
TRUSTED_DIRS: tuple[str, ...] = (
    "/usr/sbin",
    "/sbin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
)


class BinaryNotFoundError(TTPError):
    """A required external binary is absent from every trusted directory."""


class UnsafeBinaryError(TTPError):
    """A binary was found, but its permissions let a non-root user replace it."""


def _is_safely_owned(path: Path) -> bool:
    """
    True when only root can modify *path*.

    A binary that is group- or world-writable can be swapped by whoever holds
    that access, which defeats the point of resolving it from a fixed directory
    in the first place. The same applies to the directory holding it: write
    access there is enough to replace the file by rename.
    """
    for target in (path, path.parent):
        try:
            info = target.stat()
        except OSError:
            return False
        if info.st_uid != 0:
            return False
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
    return True


@cache
def resolve(binary: str) -> str:
    """
    Return the absolute path of *binary*, searched in :data:`TRUSTED_DIRS`.

    Args:
        binary: A bare executable name, e.g. ``"nft"``.

    Returns:
        The absolute path to execute.

    Raises:
        ValueError: if *binary* is not a bare name. A caller passing a path has
            usually made a mistake, and silently accepting it would reopen the
            hole this module closes.
        BinaryNotFoundError: if no trusted directory holds it.
        UnsafeBinaryError: if the one found could be replaced by a non-root user.
    """
    if not binary or "/" in binary:
        raise ValueError(f"resolve() takes a bare binary name, not {binary!r}")

    searched: list[str] = []
    for directory in TRUSTED_DIRS:
        candidate = Path(directory) / binary
        searched.append(str(candidate))
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        if not _is_safely_owned(candidate):
            raise UnsafeBinaryError(
                f"{candidate} is executable but not owned exclusively by root, so a "
                f"non-root user could replace it before TTP runs it with full "
                f"privileges. Refusing to execute it."
            )
        return str(candidate)

    raise BinaryNotFoundError(
        f"Required binary '{binary}' was not found in any trusted directory. "
        f"Searched: {', '.join(searched)}. "
        f"TTP deliberately does not consult $PATH, because a caller-controlled "
        f"PATH would let an attacker choose which program runs as root."
    )


def resolve_optional(binary: str) -> str | None:
    """
    Like :func:`resolve`, but ``None`` when the binary is simply absent.

    For the tools TTP uses when they happen to exist - ``notify-send`` for a
    desktop notification, the SELinux utilities on a non-SELinux host. Raising
    for those would turn a missing nicety into a failed teardown, at the exact
    moment the killswitch is firing.

    :class:`UnsafeBinaryError` still propagates: a binary that is present but
    replaceable is a finding, not an absence, and must never be silently
    skipped.
    """
    try:
        return resolve(binary)
    except BinaryNotFoundError:
        return None


def clear_cache() -> None:
    """Forget resolved paths. For tests, and for after a package installation."""
    resolve.cache_clear()
