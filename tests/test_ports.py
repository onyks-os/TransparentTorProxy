# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Unit tests for ``ttp.commands._ports``.

These functions decide whether TTP believes a Tor port is free, and a wrong
answer sends preflight down the wrong branch: a false "free" makes TTP try to
start Tor on an occupied port, a false "in use" aborts a session that would have
worked. They were the least-covered module in the package at 45%.

Where a real socket is cheap, these tests use one - binding a loopback port and
asking whether the code notices is a better test of a port prober than a mock of
``socket.socket``.
"""

from __future__ import annotations

import errno
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from ttp.commands._ports import (
    get_uid_from_port,
    is_port_in_use,
    is_port_listening_tcp,
    is_port_listening_udp,
)


def _free_port() -> int:
    """A port that was free a moment ago. Good enough: nothing else is racing us."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------------------
# is_port_in_use
# ---------------------------------------------------------------------------


def test_free_port_is_not_in_use() -> None:
    assert is_port_in_use(_free_port()) is False


def test_bound_ipv4_tcp_port_is_in_use() -> None:
    port = _free_port()
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", port))
        taken.listen(1)
        assert is_port_in_use(port) is True


def test_bound_ipv4_udp_port_is_in_use() -> None:
    port = _free_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
        taken.bind(("127.0.0.1", port))
        assert is_port_in_use(port) is True


def test_bound_ipv6_tcp_port_is_in_use() -> None:
    """An IPv6-only listener is still a conflict, and IPv4 probing alone misses it."""
    port = _free_port()
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as taken:
        taken.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            taken.bind(("::1", port))
        except OSError:  # pragma: no cover - host without IPv6 loopback
            pytest.skip("no IPv6 loopback available")
        taken.listen(1)
        assert is_port_in_use(port) is True


def test_bound_ipv6_udp_port_is_in_use() -> None:
    port = _free_port()
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as taken:
        taken.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            taken.bind(("::1", port))
        except OSError:  # pragma: no cover - host without IPv6 loopback
            pytest.skip("no IPv6 loopback available")
        assert is_port_in_use(port) is True


def test_ipv6_unavailable_does_not_report_a_port_in_use() -> None:
    """
    On a host with IPv6 compiled out, creating the socket raises. That must not
    be read as "the port is taken" - it would abort every session on such a host.
    """
    real_socket = socket.socket
    port = _free_port()

    def fake_socket(family=socket.AF_INET, type_=socket.SOCK_STREAM, *args, **kwargs):  # type: ignore[no-untyped-def]
        if family == socket.AF_INET6:
            raise OSError(errno.EAFNOSUPPORT, "Address family not supported")
        return real_socket(family, type_, *args, **kwargs)

    with patch("socket.socket", side_effect=fake_socket):
        assert is_port_in_use(port) is False


def test_ipv6_bind_error_other_than_in_use_is_not_a_conflict() -> None:
    """EACCES on ::1 is a permission problem, not evidence that Tor is running."""
    real_socket = socket.socket

    class _Refusing:
        def __init__(self, family, type_):  # type: ignore[no-untyped-def]
            self._sock = real_socket(family, type_)

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *exc):  # type: ignore[no-untyped-def]
            self._sock.close()

        def setsockopt(self, *a, **k):  # type: ignore[no-untyped-def]
            pass

        def bind(self, addr):  # type: ignore[no-untyped-def]
            raise OSError(errno.EACCES, "Permission denied")

    port = _free_port()

    def fake_socket(family=socket.AF_INET, type_=socket.SOCK_STREAM, *args, **kwargs):  # type: ignore[no-untyped-def]
        if family == socket.AF_INET6:
            return _Refusing(family, type_)
        return real_socket(family, type_, *args, **kwargs)

    with patch("socket.socket", side_effect=fake_socket):
        assert is_port_in_use(port) is False


# ---------------------------------------------------------------------------
# is_port_listening_tcp
# ---------------------------------------------------------------------------


def test_listening_tcp_port_is_detected() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])
        assert is_port_listening_tcp(port) is True


def test_closed_tcp_port_is_not_listening() -> None:
    assert is_port_listening_tcp(_free_port()) is False


def test_ipv6_only_listener_is_detected() -> None:
    """A bound-but-IPv6-only Tor port must not look dead to the IPv4 probe."""
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            server.bind(("::1", 0))
        except OSError:  # pragma: no cover - host without IPv6 loopback
            pytest.skip("no IPv6 loopback available")
        server.listen(1)
        port = int(server.getsockname()[1])
        assert is_port_listening_tcp(port) is True


# ---------------------------------------------------------------------------
# is_port_listening_udp
# ---------------------------------------------------------------------------


def test_bound_udp_port_is_listening() -> None:
    port = _free_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", port))
        assert is_port_listening_udp(port) is True


def test_free_udp_port_is_not_listening() -> None:
    assert is_port_listening_udp(_free_port()) is False


def test_ipv6_bound_udp_port_is_listening() -> None:
    port = _free_port()
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            server.bind(("::1", port))
        except OSError:  # pragma: no cover - host without IPv6 loopback
            pytest.skip("no IPv6 loopback available")
        assert is_port_listening_udp(port) is True


# ---------------------------------------------------------------------------
# get_uid_from_port
# ---------------------------------------------------------------------------

# sl local_address rem_address st ... uid
_TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _tcp_line(hex_port: str, state: str = "0A", uid: str = "110") -> str:
    return (
        f"   0: 0100007F:{hex_port} 00000000:0000 {state} "
        f"00000000:00000000 00:00000000 00000000   {uid}        0 12345 1 0000 100 0\n"
    )


def _write_proc(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(_TCP_HEADER + body)
    return path


def _patched_open(mapping: dict[str, Path]):  # type: ignore[no-untyped-def]
    real_open = open

    def fake_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path in mapping:
            return real_open(mapping[path], *args, **kwargs)
        raise FileNotFoundError(path)

    return fake_open


def test_uid_is_read_from_proc_net_tcp(tmp_path: Path) -> None:
    # 9051 == 0x235B, the default Tor ControlPort.
    proc = _write_proc(tmp_path, "tcp", _tcp_line("235B", uid="110"))
    with patch("builtins.open", _patched_open({"/proc/net/tcp": proc})):
        assert get_uid_from_port(9051) == 110


def test_uid_falls_back_to_proc_net_tcp6(tmp_path: Path) -> None:
    """A Tor listening only on IPv6 appears in tcp6 and nowhere else."""
    proc6 = _write_proc(tmp_path, "tcp6", _tcp_line("235B", uid="123"))
    with patch("builtins.open", _patched_open({"/proc/net/tcp6": proc6})):
        assert get_uid_from_port(9051) == 123


def test_non_listening_socket_is_ignored(tmp_path: Path) -> None:
    """State 01 is ESTABLISHED. Only 0A (LISTEN) identifies the owner of a port."""
    proc = _write_proc(tmp_path, "tcp", _tcp_line("235B", state="01"))
    with patch("builtins.open", _patched_open({"/proc/net/tcp": proc})):
        assert get_uid_from_port(9051) is None


def test_other_ports_are_ignored(tmp_path: Path) -> None:
    proc = _write_proc(tmp_path, "tcp", _tcp_line("0050"))  # port 80
    with patch("builtins.open", _patched_open({"/proc/net/tcp": proc})):
        assert get_uid_from_port(9051) is None


def test_truncated_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "tcp"
    path.write_text(_TCP_HEADER + "   0: 0100007F:235B\n")
    with patch("builtins.open", _patched_open({"/proc/net/tcp": path})):
        assert get_uid_from_port(9051) is None


def test_missing_proc_files_return_none() -> None:
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert get_uid_from_port(9051) is None


def test_unreadable_proc_files_return_none() -> None:
    with patch("builtins.open", side_effect=PermissionError):
        assert get_uid_from_port(9051) is None


def test_empty_proc_file_returns_none(tmp_path: Path) -> None:
    proc = _write_proc(tmp_path, "tcp", "")
    with patch("builtins.open", _patched_open({"/proc/net/tcp": proc})):
        assert get_uid_from_port(9051) is None


def test_port_is_matched_on_the_suffix_not_a_substring(tmp_path: Path) -> None:
    """
    Local addresses are `<hex ip>:<hex port>`; matching anywhere in the string
    would let an address whose IP happens to end in the port digits win.
    """
    proc = _write_proc(
        tmp_path,
        "tcp",
        "   0: 0000235B:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000   110 0 1 1 0 100 0\n",
    )
    with patch("builtins.open", _patched_open({"/proc/net/tcp": proc})):
        assert get_uid_from_port(9051) is None


def test_first_listening_match_wins(tmp_path: Path) -> None:
    body = _tcp_line("235B", uid="110") + _tcp_line("235B", uid="999")
    proc = _write_proc(tmp_path, "tcp", body)
    with patch("builtins.open", _patched_open({"/proc/net/tcp": proc})):
        assert get_uid_from_port(9051) == 110
