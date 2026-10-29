# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Decode inotify invalidations for the session supervisor."""

import struct

# inotify event masks we care about. Either one means the file we were watching
# is gone from under us - which for /etc/resolv.conf means the DNS overlay has
# been unmounted or replaced, i.e. the exact leak this watchdog exists to catch.
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800

#: struct inotify_event { int wd; uint32 mask; uint32 cookie; uint32 len; }
_INOTIFY_HEADER = "iIII"
_INOTIFY_HEADER_SIZE = 16


def inotify_watch_lost(data: bytes | bytearray) -> bool:
    """
    Return True if *data* contains an event meaning the watched file is gone.

    A read from an inotify fd returns a packed sequence of variable-length
    events, so this walks the buffer rather than decoding a single struct. It is
    a pure function so the decision can be tested against real event layouts:
    inline in the monitoring loop, it was only reachable by running the daemon.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < _INOTIFY_HEADER_SIZE:
        return False

    offset = 0
    lost = False
    while offset < len(data):
        if len(data) - offset < _INOTIFY_HEADER_SIZE:
            # A truncated trailing record. Report what we decoded rather than
            # raising: a partial read must not take the watchdog down.
            break
        _wd, mask, _cookie, name_len = struct.unpack_from(_INOTIFY_HEADER, data, offset)
        if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
            lost = True
        offset += _INOTIFY_HEADER_SIZE + name_len
    return lost
