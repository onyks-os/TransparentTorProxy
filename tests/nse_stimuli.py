# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""How a leak probe reports whether its packet actually left the socket.

This lives apart from ``tests/test_nse_rules.py`` for the same reason the
classifier does: that module skips itself unless the process is root and the
network-sandbox-engine is installed, so anything defined inside it cannot be
exercised by the ordinary unit suite.

The problem it solves
---------------------

Every stimulus suppresses ``OSError`` around its send, and it has to: with
TTP's ruleset loaded, nftables answers a rejected packet with EPERM on the
local socket, and that is the firewall working, not a broken probe. A
stimulus that exited non-zero on a refusal would fail every containment test.

But the positive control runs the *same* script with the ruleset flushed, and
there a refused send is not the firewall -- it is the instrument failing to
produce the traffic it is about to assert the absence of. Swallowed, the two
are indistinguishable, and the only symptom is "the sniffer observed no
cleartext packet", which reads as a broken namespace.

So the send is not suppressed, it is *reported*: the probe always exits zero
on ``OSError`` and prints why on stdout, where the positive control's failure
message can quote it.
"""

from __future__ import annotations

#: What a probe prints when its packet left the socket.
SEND_OK = "send: ok"

#: Prefix for the other outcome. The kernel's reason follows it.
SEND_REFUSED = "send: refused by the kernel:"


def reporting_send(send_expr: str) -> str:
    """Build the script fragment that performs *send_expr* and reports its outcome.

    Only ``OSError`` is treated as a legitimate outcome, because only ``OSError``
    is what a firewall rejection looks like from userspace. Anything else -- a
    typo in the probe, a missing name, a bad argument -- propagates and exits
    non-zero, so a broken probe stays loud instead of masquerading as a blocked
    one.

    Args:
        send_expr: A single Python expression statement that sends the packet.

    Returns:
        Python source ending in a newline, suitable for appending to a probe.
    """
    return (
        f"try:\n    {send_expr}\n    print({SEND_OK!r})\nexcept OSError as _exc:\n    print({SEND_REFUSED!r}, _exc)\n"
    )
