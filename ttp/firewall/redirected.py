# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Close the TCP sockets TTP redirected to Tor before its rules are removed.

An application socket whose connection was redirected to the TransPort can
outlive the session. An orphan in FIN-WAIT-1 keeps retransmitting with an
exponential backoff, so it may stay silent through any fixed teardown window.
Once the redirect and filter rules are gone, its next segment leaves the
physical interface towards the original destination, revealing a connection
attempted during the session (seen by the external capture of the VPN VM
qualification). The rules cannot outlive ``ttp stop``, so these sockets must
not either.

Connection tracking is the authority on which connections were redirected:
TCP entries with destination NAT whose reply comes from the TransPort on
loopback. Both ends are closed: the application's socket and Tor's accepted
TransPort socket, which becomes an orphan when Tor stops and whose
retransmissions made the host answer with RSTs carrying a stale NAT
destination (``::1``) on the physical link. Inbound connections, bypassed
traffic and Tor's relay connections are never translated and are left alone.
Each selected socket is destroyed with
``SOCK_DESTROY`` while the teardown lockdown still holds, then looked up again.
If the kernel lacks ``SOCK_DESTROY`` or a socket remains, the caller keeps the
rules for a bounded wait and otherwise refuses to remove them.

Only the kernel's netlink interfaces are used: no ``conntrack`` or ``ss``
binary is required, and nothing here sends a packet itself.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import socket
import struct
import time
from collections.abc import Collection
from typing import NamedTuple

from ttp.exceptions import FirewallError

WAIT_SECONDS = 15.0
_POLL_SECONDS = 0.5

NETLINK_SOCK_DIAG = 4
NETLINK_NETFILTER = 12
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLM_F_DUMP = 0x300
NLMSG_ERROR = 2
NLMSG_DONE = 3
_CTNETLINK_GET = (1 << 8) | 1  # NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET
SOCK_DIAG_BY_FAMILY = 20
SOCK_DESTROY = 21

CTA_TUPLE_ORIG, CTA_TUPLE_REPLY, CTA_STATUS = 1, 2, 3
CTA_TUPLE_IP, CTA_TUPLE_PROTO = 1, 2
CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_PROTO_DST_PORT = 1, 2, 3
_ADDRESS_ATTRS = {1: "src", 2: "dst", 3: "src", 4: "dst"}  # CTA_IP_V4_*, CTA_IP_V6_*
IPS_DST_NAT = 1 << 5
TCP_TIME_WAIT = 6
TCP_LISTEN = 10
_ALL_STATES = 0xFFFFFFFF
_NO_COOKIE = 0xFFFFFFFF


class RedirectedSocketsRemain(FirewallError):
    """Redirected connections could not be proven closed; keep the rules."""


class Flow(NamedTuple):
    """An application socket as conntrack's original tuple saw it."""

    family: int
    local: str
    local_port: int
    remote: str
    remote_port: int


def parse_messages(data: bytes) -> list[tuple[int, bytes]]:
    """Split a netlink byte stream into (type, payload); refuse truncation."""
    messages = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Truncated netlink header")
        length, kind = struct.unpack_from("=IH", data, offset)
        if length < 16 or offset + length > len(data):
            raise ValueError("Truncated netlink message")
        messages.append((kind, data[offset + 16 : offset + length]))
        offset += (length + 3) & ~3
    return messages


def _attributes(data: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        length, kind = struct.unpack_from("=HH", data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError("Truncated netlink attribute")
        result[kind & 0x3FFF] = data[offset + 4 : offset + length]
        offset += (length + 3) & ~3
    return result


def _tuple(data: bytes) -> tuple[int, str, str, int, int]:
    """Protocol, source, destination and ports of a CTA_TUPLE_* attribute."""
    parts = _attributes(data)
    ip = _attributes(parts[CTA_TUPLE_IP])
    proto = _attributes(parts[CTA_TUPLE_PROTO])
    addresses = {_ADDRESS_ATTRS[kind]: str(ipaddress.ip_address(value)) for kind, value in ip.items()}
    return (
        proto[CTA_PROTO_NUM][0],
        addresses["src"],
        addresses["dst"],
        struct.unpack("!H", proto[CTA_PROTO_SRC_PORT])[0],
        struct.unpack("!H", proto[CTA_PROTO_DST_PORT])[0],
    )


def _raise_on_error(payload: bytes) -> None:
    code = struct.unpack_from("=i", payload)[0]
    if code:
        raise OSError(-code, os.strerror(-code))


def flows_from_dump(messages: list[tuple[int, bytes]], ports: Collection[int]) -> list[Flow]:
    """Select TCP connections destination-NATed to a local TransPort."""
    flows: list[Flow] = []
    for kind, payload in messages:
        if kind == NLMSG_DONE:
            return flows
        if kind == NLMSG_ERROR:
            _raise_on_error(payload)
            continue
        attributes = _attributes(payload[4:])  # after struct nfgenmsg
        if CTA_STATUS not in attributes or not struct.unpack("!I", attributes[CTA_STATUS])[0] & IPS_DST_NAT:
            continue
        proto, local, remote, local_port, remote_port = _tuple(attributes[CTA_TUPLE_ORIG])
        _, tor, tor_peer, tor_port, tor_peer_port = _tuple(attributes[CTA_TUPLE_REPLY])
        if proto == socket.IPPROTO_TCP and ipaddress.ip_address(tor).is_loopback and tor_port in ports:
            family = socket.AF_INET6 if ":" in local else socket.AF_INET
            # The application's socket, then Tor's accepted TransPort socket:
            # orphaned when Tor stops, Tor's end keeps retransmitting to the
            # application, whose RST answers left with a stale NAT destination.
            flows.append(Flow(family, local, local_port, remote, remote_port))
            flows.append(Flow(family, tor, tor_port, tor_peer, tor_peer_port))
    raise ValueError("Connection tracking dump ended without NLMSG_DONE")


def _exchange(protocol: int, kind: int, flags: int, payload: bytes) -> list[tuple[int, bytes]]:
    """One netlink request; collect replies until DONE, an error/ACK or a reply."""
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol) as stream:
        stream.settimeout(5)
        stream.bind((0, 0))
        stream.send(struct.pack("=IHHII", 16 + len(payload), kind, flags, 1, 0) + payload)
        messages: list[tuple[int, bytes]] = []
        while True:
            for message in parse_messages(stream.recv(1 << 20)):
                messages.append(message)
                if not flags & NLM_F_DUMP or message[0] in (NLMSG_DONE, NLMSG_ERROR):
                    return messages


def _dump_flows(ports: Collection[int]) -> list[Flow]:
    request = struct.pack("=BBH", socket.AF_UNSPEC, 0, 0)  # struct nfgenmsg, all families
    messages = _exchange(NETLINK_NETFILTER, _CTNETLINK_GET, NLM_F_REQUEST | NLM_F_DUMP, request)
    return flows_from_dump(messages, set(ports))


class Socket(NamedTuple):
    """One TCP socket from a sock_diag dump."""

    family: int
    state: int
    local: str
    local_port: int
    remote: str
    remote_port: int


def sockets_from_dump(messages: list[tuple[int, bytes]]) -> list[Socket]:
    """Parse struct inet_diag_msg replies; refuse an error or a missing end."""
    sockets: list[Socket] = []
    for kind, payload in messages:
        if kind == NLMSG_DONE:
            return sockets
        if kind == NLMSG_ERROR:
            _raise_on_error(payload)
            continue
        if kind != SOCK_DIAG_BY_FAMILY:
            raise ValueError("Unexpected socket diagnostic message")
        sockets.append(_socket(payload))
    raise ValueError("Socket diagnostic dump ended without NLMSG_DONE")


def _socket(payload: bytes) -> Socket:
    """Parse one struct inet_diag_msg."""
    if len(payload) < 52:
        raise ValueError("Truncated socket diagnostic message")
    family, state = payload[0], payload[1]
    size = 16 if family == socket.AF_INET6 else 4
    local_port, remote_port = struct.unpack_from("!HH", payload, 4)
    local = str(ipaddress.ip_address(payload[8 : 8 + size]))
    remote = str(ipaddress.ip_address(payload[24 : 24 + size]))
    return Socket(family, state, local, local_port, remote, remote_port)


def _live(item: Socket) -> bool:
    """LISTEN and TIME-WAIT sockets never carry the redirected stream."""
    return item.state not in (TCP_LISTEN, TCP_TIME_WAIT)


def transport_flows(sockets: list[Socket], ports: Collection[int]) -> list[Flow]:
    """Tor's accepted TransPort sockets and the application sockets they serve.

    Conntrack forgets a closing connection within seconds (LAST-ACK/CLOSE
    timeouts) while the kernel socket keeps retransmitting for minutes, so
    conntrack alone missed orphaned Tor ends in CI. Only Tor listens on the
    loopback TransPort; after Tor stops, any connected socket there is its
    orphan, and its peer address names the application's socket.
    """

    tor = [
        item
        for item in sockets
        if _live(item) and item.local_port in ports and ipaddress.ip_address(item.local).is_loopback
    ]
    peers = {(item.family, item.remote, item.remote_port) for item in tor}
    flows = [Flow(item.family, item.local, item.local_port, item.remote, item.remote_port) for item in tor]
    flows += [
        Flow(item.family, item.local, item.local_port, item.remote, item.remote_port)
        for item in sockets
        if _live(item) and (item.family, item.local, item.local_port) in peers and item.local_port not in ports
    ]
    return flows


def _dump_transport_flows(ports: Collection[int]) -> list[Flow]:
    sockets: list[Socket] = []
    for family in (socket.AF_INET, socket.AF_INET6):
        request = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 0, 0, _ALL_STATES) + bytes(48)
        sockets += sockets_from_dump(
            _exchange(NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, request)
        )
    return transport_flows(sockets, set(ports))


def _address(family: int, value: str) -> bytes:
    return socket.inet_pton(family, value).ljust(16, b"\0")


def socket_request(flow: Flow) -> bytes:
    """struct inet_diag_req_v2 naming exactly one TCP socket."""
    return (
        struct.pack("=BBBBI", flow.family, socket.IPPROTO_TCP, 0, 0, _ALL_STATES)
        + struct.pack("!HH", flow.local_port, flow.remote_port)
        + _address(flow.family, flow.local)
        + _address(flow.family, flow.remote)
        + struct.pack("=III", 0, _NO_COOKIE, _NO_COOKIE)
    )


def _destroy(flow: Flow) -> None:
    reply = _exchange(NETLINK_SOCK_DIAG, SOCK_DESTROY, NLM_F_REQUEST | NLM_F_ACK, socket_request(flow))
    try:
        _raise_on_error(reply[0][1])
    except FileNotFoundError:
        pass  # already gone


def _exists(flow: Flow) -> bool:
    """A live socket with exactly the flow's tuple.

    The kernel's single-socket lookup falls back to a listener on the local
    port, so once Tor's accepted end is gone a request for it may return
    Tor's TransPort listener instead; that socket is not the flow.
    """
    kind, payload = _exchange(NETLINK_SOCK_DIAG, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST, socket_request(flow))[0]
    if kind == NLMSG_ERROR:
        try:
            _raise_on_error(payload)
        except FileNotFoundError:
            return False
        raise OSError(errno.EPROTO, "Unexpected socket diagnostic acknowledgement")
    if kind != SOCK_DIAG_BY_FAMILY:
        raise ValueError("Unexpected socket diagnostic message")
    found = _socket(payload)
    same = (found.family, found.local, found.local_port, found.remote, found.remote_port) == tuple(flow)
    return same and _live(found)


def close_redirected_sockets(transport_port: int) -> int:
    """Destroy redirected TCP sockets; return how many were closed.

    Call only while the redirect rules and teardown lockdown are still in
    place. Raises RedirectedSocketsRemain when the connections cannot be
    enumerated or a socket survives the bounded wait; the caller must then
    keep its rules.
    """
    try:
        # Conntrack names both ends while it remembers the connection; the
        # socket table still finds Tor's orphaned ends after it has forgotten.
        flows = list(dict.fromkeys(_dump_flows({transport_port}) + _dump_transport_flows({transport_port})))
    except (OSError, ValueError, KeyError, IndexError) as exc:
        raise RedirectedSocketsRemain(
            f"Redirected connections cannot be enumerated ({exc}); protection retained"
        ) from exc
    for flow in flows:
        try:
            _destroy(flow)
        except OSError:
            pass  # e.g. EOPNOTSUPP without CONFIG_INET_DIAG_DESTROY: wait below
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        try:
            remaining = [flow for flow in flows if _exists(flow)]
        except (OSError, ValueError, IndexError) as exc:
            raise RedirectedSocketsRemain(
                f"Redirected connections cannot be verified closed ({exc}); protection retained"
            ) from exc
        if not remaining:
            return len(flows)
        if time.monotonic() >= deadline:
            raise RedirectedSocketsRemain(
                f"{len(remaining)} redirected TCP connection(s) could not be closed; protection retained. "
                "Close the applications holding them, then run 'sudo ttp stop' again."
            )
        time.sleep(_POLL_SECONDS)
