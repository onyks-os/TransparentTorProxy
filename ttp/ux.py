# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""One-time UX engagement features.

This module manages persistent user-experience state that survives reboots,
such as the one-time GitHub star-encouragement message.  It deliberately
lives outside ``state.py`` (which is strictly volatile / tmpfs) because
its storage path is ``/var/lib/ttp/`` — a persistent directory.

PUBLIC API
----------
should_show_star_message() -> bool
mark_star_message_shown() -> None
delete_star_sentinel() -> None
"""

from __future__ import annotations

from pathlib import Path

# Persistent directory - survives reboots.
# Only non-sensitive persistent configurations or UX flags should go here.
PERSISTENT_DIR = Path("/var/lib/ttp")
STAR_NOTIFIED_PATH = PERSISTENT_DIR / ".starred_notified"


def should_show_star_message() -> bool:
    """Return ``True`` if the one-time star message should be shown."""
    return not STAR_NOTIFIED_PATH.exists()


def mark_star_message_shown() -> None:
    """Mark the star message as shown by creating a sentinel file."""
    try:
        PERSISTENT_DIR.mkdir(parents=True, exist_ok=True)
        STAR_NOTIFIED_PATH.touch()
    except OSError:
        # Best effort - if we can't write, we might show it again next time.
        pass


def delete_star_sentinel() -> None:
    """Remove the star notification sentinel file."""
    STAR_NOTIFIED_PATH.unlink(missing_ok=True)
