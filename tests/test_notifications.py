# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

import json
import os
import struct
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from ttp.evidence import ExitCode
from ttp.notifications import agent, delivery, protocol, service
from ttp.runtime_records import RecordStore
from ttp.settings import NotificationSettings, Settings

SESSION = "12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    store = RecordStore(tmp_path / "records", os.getuid(), os.getgid())
    store.prepare()
    import ttp.runtime_records

    monkeypatch.setattr(ttp.runtime_records, "session_store", lambda: store)
    lock = {
        "session_id": SESSION,
        "settings": Settings().select(notifications=True).snapshot(),
        "notification_target": {"uid": 1000, "gid": 1000, "login_session": "2"},
    }
    return store, lock


def test_notify_acceptance_requires_valid_nonzero_server_identifier(monkeypatch):
    call = Mock(return_value={"type": "u", "data": [42]})
    monkeypatch.setattr(delivery, "call", call)
    sender = delivery.Delivery("unix:path=/private/bus", NotificationSettings())
    receipt = sender.deliver("emergency_verified")
    assert receipt["state"] == "accepted" and receipt["notification_id"] == 42
    args = call.call_args.args[2]
    assert args[0] == "susssasa{sv}i"
    assert args[6] == "0"  # no action buttons
    assert args[-1] == "0"  # request no expiration, not a guarantee
    assert "sensitive applications" in args[5]


def test_repeated_incident_is_deduplicated_and_worsening_updates_without_debounce(monkeypatch):
    call = Mock(return_value={"type": "u", "data": [42]})
    monkeypatch.setattr(delivery, "call", call)
    sender = delivery.Delivery("bus", NotificationSettings())
    sender.deliver("emergency_verified")
    assert sender.deliver("emergency_verified")["deduplicated"]
    assert call.call_count == 1
    sender.deliver("containment_unconfirmed")
    assert call.call_count == 2
    assert call.call_args.args[2][2] == "42"
    assert "UNCONFIRMED" in call.call_args.args[2][4]


@pytest.mark.parametrize(
    "reply",
    [
        {},
        {"type": "s", "data": [42]},
        {"type": "u", "data": [0]},
        {"type": "u", "data": [True]},
        {"type": "u", "data": [2**32]},
        {"type": "u", "data": []},
        {"type": "u", "data": 42},
    ],
)
def test_invalid_notify_reply_never_claims_acceptance(monkeypatch, reply):
    call = Mock(return_value=reply)
    monkeypatch.setattr(delivery, "call", call)
    result = delivery.Delivery("bus", NotificationSettings()).deliver("started")
    assert result["state"] == "failed"
    assert call.call_count == 3


def test_timeout_remains_ambiguous_even_if_later_attempts_fail(monkeypatch):
    call = Mock(side_effect=[subprocess.TimeoutExpired("busctl", 5), OSError(), OSError()])
    monkeypatch.setattr(delivery, "call", call)
    assert delivery.Delivery("bus", NotificationSettings()).deliver("started")["state"] == "unconfirmed"


def test_total_delivery_budget_is_not_reset_by_retries(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(delivery, "boottime", lambda: now[0])

    def slow(bus, method, args, timeout):
        now[0] += timeout
        raise subprocess.TimeoutExpired("busctl", timeout)

    call = Mock(side_effect=slow)
    monkeypatch.setattr(delivery, "call", call)
    result = delivery.Delivery("bus", NotificationSettings(delivery_timeout=6, call_timeout=5)).deliver("started")
    assert result["state"] == "unconfirmed"
    assert [item.args[-1] for item in call.call_args_list] == [5, 1]


def test_busctl_is_addressed_to_recipient_bus_and_reply_is_bounded(monkeypatch):
    run = Mock(return_value=SimpleNamespace(stdout='{"type":"u","data":[7]}'))
    monkeypatch.setattr(delivery.subprocess, "run", run)
    assert delivery.call("unix:path=/recipient/bus", "Notify", [], 2)["data"] == [7]
    assert "--address=unix:path=/recipient/bus" in run.call_args.args[0]
    assert run.call_args.kwargs["timeout"] == 2
    run.return_value.stdout = "x" * 4097
    with pytest.raises(ValueError, match="Oversized"):
        delivery.call("bus", "Notify", [], 2)
    run.return_value.stdout = "[]"
    with pytest.raises(ValueError, match="Invalid"):
        delivery.call("bus", "Notify", [], 2)


def test_server_readiness_requires_correct_protocol_reply(monkeypatch):
    call = Mock(return_value={"type": "ssss", "data": ["server", "vendor", "1", "1.2"]})
    monkeypatch.setattr(delivery, "call", call)
    delivery.check_server("bus", 5)
    call.return_value = {"type": "s", "data": "not a server response"}
    with pytest.raises(ValueError):
        delivery.check_server("bus", 5)


def test_recipient_is_not_guessed_for_direct_root_or_ambiguous_desktops(monkeypatch):
    monkeypatch.delenv("SUDO_UID", raising=False)
    with pytest.raises(service.NotificationError, match="Direct root"):
        service.recipient()
    monkeypatch.setattr(service.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000))
    run = Mock(
        side_effect=[
            SimpleNamespace(stdout="1 user\n2 user\n"),
            SimpleNamespace(stdout="User=1000\nRemote=no\nType=wayland\nState=active\nClass=user\n"),
            SimpleNamespace(stdout="User=1000\nRemote=no\nType=x11\nState=online\nClass=user\n"),
        ]
    )
    monkeypatch.setattr(service.subprocess, "run", run)
    with pytest.raises(service.NotificationError, match="Exactly one"):
        service.recipient("alice")


def test_sudo_recipient_requires_local_graphical_session(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(service.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_uid=uid, pw_gid=1000))
    run = Mock(
        side_effect=[
            SimpleNamespace(stdout="2 user\n"),
            SimpleNamespace(stdout="User=1000\nRemote=no\nType=wayland\nState=active\nClass=user\n"),
        ]
    )
    monkeypatch.setattr(service.subprocess, "run", run)
    assert service.recipient()["uid"] == 1000


@pytest.mark.parametrize("selected", ["root", "unknown"])
def test_root_and_nonexistent_recipients_are_rejected(monkeypatch, selected):
    def account(name):
        if name == "unknown":
            raise KeyError(name)
        return SimpleNamespace(pw_uid=0)

    monkeypatch.setattr(service.pwd, "getpwnam", account)
    with pytest.raises(service.NotificationError):
        service.recipient(selected)


def test_protocol_uses_kernel_peer_credentials_and_bounded_packets():
    sock = Mock()
    sock.getsockopt.return_value = struct.pack("3i", 44, 1000, 1000)
    assert protocol.peer_uid(sock) == 1000
    protocol.send(sock, {"session_id": SESSION})
    assert json.loads(sock.sendall.call_args.args[0])["session_id"] == SESSION
    for raw in [b"", b"[]", b"{", b"x" * (protocol.MAX_MESSAGE + 1)]:
        sock.recv.return_value = raw
        with pytest.raises(ValueError):
            protocol.receive(sock)
    with pytest.raises(ValueError):
        protocol.send(sock, {"v": "x" * protocol.MAX_MESSAGE})


def test_ipc_refuses_an_agent_owned_by_another_user(desktop, monkeypatch):
    _, lock = desktop
    sock = MagicMock()
    sock.__enter__.return_value = sock
    monkeypatch.setattr(service.socket, "socket", Mock(return_value=sock))
    monkeypatch.setattr(service, "peer_uid", lambda conn: 1001)
    with pytest.raises(service.NotificationError, match="identity mismatch"):
        service.rpc(lock, "status")
    sock.sendall.assert_not_called()


def test_notification_failure_does_not_invoke_any_firewall_operation(desktop, monkeypatch):
    store, lock = desktop
    from ttp import firewall

    apply = Mock()
    monkeypatch.setattr(firewall, "apply_emergency_killswitch", apply)
    monkeypatch.setattr(service, "rpc", Mock(side_effect=TimeoutError()))
    result = service.emit(lock, "started")
    assert result.exit_code == ExitCode.NOTIFICATION_FAILED
    assert store.read("notifications", SESSION)["data"]["state"] == "unconfirmed"
    apply.assert_not_called()


def test_disabled_notifications_do_not_require_a_desktop_or_agent(desktop, monkeypatch):
    _, lock = desktop
    lock["settings"] = Settings().snapshot()
    rpc = Mock()
    monkeypatch.setattr(service, "rpc", rpc)
    assert service.emit(lock, "started").exit_code == 0
    assert service.finish_notifications(lock).exit_code == 0
    rpc.assert_not_called()


def test_emergency_enqueue_is_bounded_and_does_not_wait_for_desktop(desktop, monkeypatch):
    _, lock = desktop
    rpc = Mock(return_value={"state": "pending", "reason": "notifications.enqueued"})
    monkeypatch.setattr(service, "rpc", rpc)
    assert service.emit(lock, "emergency_verified", wait=False).exit_code == 0
    assert rpc.call_args.kwargs["wait"] is False
    assert rpc.call_args.kwargs["timeout"] == 0.2


def test_stop_delivery_failure_still_stops_agent_and_never_rearms(desktop, monkeypatch):
    _, lock = desktop
    monkeypatch.setattr(service, "rpc", Mock(side_effect=OSError("no agent")))
    stop = Mock()
    monkeypatch.setattr(service, "stop_agent", stop)
    assert service.finish_notifications(lock).exit_code == 9
    stop.assert_called_once()


def test_agent_unit_has_no_firewall_privileges_or_watchdog_group(desktop, monkeypatch, tmp_path):
    _, lock = desktop
    path = tmp_path / "notify.service"
    monkeypatch.setattr(service, "UNIT_PATH", path)
    monkeypatch.setattr(service.subprocess, "run", Mock())
    monkeypatch.setattr(service, "rpc", Mock(return_value={"state": "pending", "instance_id": "a" * 32}))
    service.start_agent(lock, lock["notification_target"])
    unit = path.read_text()
    assert "User=1000\nGroup=1000" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "SupplementaryGroups" not in unit
    assert "ExecStopPost" not in unit
    assert "WatchdogSec=30" in unit


def test_agent_cannot_deliver_as_root(monkeypatch):
    monkeypatch.setattr(agent.os, "geteuid", lambda: 0)
    with pytest.raises(PermissionError):
        agent.run_agent(0, SESSION, 42, NotificationSettings(), 5)


def test_fixed_events_contain_no_addresses_or_network_actions():
    assert set(protocol.EVENTS) == {
        "started",
        "stopped",
        "inconclusive",
        "watchdog_unavailable",
        "tor_negative",
        "emergency_verified",
        "containment_unconfirmed",
        "recovered",
    }
    for event in protocol.EVENTS.values():
        assert "http" not in event.body
        assert "192." not in event.body


def test_agent_authenticates_requests_keeps_receipts_and_reports_progress(monkeypatch, tmp_path, caplog):
    import stat

    monkeypatch.setattr(agent.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(agent.Path, "lstat", lambda self: SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=1000))
    monkeypatch.setattr(agent, "socket_path", lambda *args: tmp_path / "agent.sock")
    # The listener is a socket boundary; protocol decisions and dispatch run in
    # the real agent loop. Filesystem chmod follows the mocked bind operation.
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.bind.side_effect = lambda path: __import__("pathlib").Path(path).touch()
    clients = [MagicMock() for _ in range(8)]
    for client in clients:
        client.__enter__.return_value = client
    listener.accept.side_effect = [TimeoutError(), *[(client, None) for client in clients], KeyboardInterrupt()]
    monkeypatch.setattr(agent.socket, "socket", lambda *args: listener)
    monkeypatch.setattr(agent, "peer_uid", lambda conn: 1001 if conn is clients[0] else 42)
    payloads = [
        {"session_id": "foreign", "operation": "notify", "event": "started"},
        {"session_id": SESSION, "operation": "notify", "event": []},
        {"session_id": SESSION, "operation": "status"},
        {"session_id": SESSION, "operation": "notify", "event": "started"},
        {"session_id": SESSION, "operation": "status"},
        {"session_id": SESSION, "operation": "notify", "event": "containment_unconfirmed"},
        ValueError("malformed packet"),
    ]
    monkeypatch.setattr(agent, "receive", Mock(side_effect=payloads))
    sender = delivery.Delivery("private-bus", NotificationSettings())
    calls = Mock(side_effect=[{"type": "u", "data": [42]}, OSError(), OSError(), OSError()])
    monkeypatch.setattr(delivery, "call", calls)
    monkeypatch.setattr(agent, "Delivery", lambda *args: sender)
    monkeypatch.setattr(agent, "check_server", Mock())
    receipts = []

    def reply(conn, payload):
        receipts.append(payload)
        if conn is clients[4]:
            raise BrokenPipeError()

    monkeypatch.setattr(agent, "send", reply)
    progress = Mock()
    monkeypatch.setattr(agent, "notify_progress", progress)
    with pytest.raises(KeyboardInterrupt):
        agent.run_agent(1000, SESSION, 42, NotificationSettings(), 5)
    assert [item["state"] for item in receipts] == ["pending", "accepted", "accepted", "failed"]
    assert receipts[2]["notification_id"] == 42  # retained after publisher disconnected
    assert "notifications.reply_invalid" in caplog.text
    assert progress.call_args_list[0].kwargs == {"ready": True}
    assert progress.call_count > 1


@pytest.mark.parametrize("mode,owner", [(0, 1000), (0o140000, 1001)])
def test_agent_rejects_invalid_recipient_bus(monkeypatch, mode, owner):
    monkeypatch.setattr(agent.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(agent.Path, "lstat", lambda self: SimpleNamespace(st_mode=mode, st_uid=owner))
    with pytest.raises(PermissionError, match="bus ownership"):
        agent.run_agent(1000, SESSION, 42, NotificationSettings(), 5)


def test_agent_entrypoint_passes_explicit_recipient_and_budgets(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent",
            "--uid",
            "1000",
            "--session",
            SESSION,
            "--watchdog-uid",
            "42",
            "--call-timeout",
            "5",
            "--delivery-timeout",
            "15",
            "--attempts",
            "3",
            "--heartbeat",
            "5",
        ],
    )
    run = Mock()
    monkeypatch.setattr(agent, "run_agent", run)
    agent.main()
    assert run.call_args.args[:3] == (1000, SESSION, 42)
    assert run.call_args.args[3].attempts == 3


def test_nonzero_dbus_exit_is_ambiguous(monkeypatch):
    monkeypatch.setattr(delivery, "call", Mock(side_effect=subprocess.CalledProcessError(1, "busctl")))
    assert delivery.Delivery("bus", NotificationSettings()).deliver("started")["state"] == "unconfirmed"


@pytest.mark.parametrize(
    "payload",
    [
        {"session_id": "foreign", "state": "pending"},
        {"state": "invented"},
        {"state": "accepted", "notification_id": 0},
        {"state": "accepted", "notification_id": True},
        {"state": "pending", "instance_id": "invalid"},
        {"state": "pending", "progress_at": -100},
    ],
)
def test_rpc_rejects_forged_receipt_identity_progress_or_acceptance(desktop, monkeypatch, payload):
    _, lock = desktop
    sock = MagicMock()
    sock.__enter__.return_value = sock
    monkeypatch.setattr(service.socket, "socket", lambda *args: sock)
    monkeypatch.setattr(service, "peer_uid", lambda conn: 1000)
    monkeypatch.setattr(
        service,
        "receive",
        lambda conn: {"session_id": SESSION, "instance_id": "a" * 32, "progress_at": service.boottime(), **payload},
    )
    with pytest.raises((ValueError, service.NotificationError)):
        service.rpc(lock, "status")


def test_rpc_success_and_async_send(desktop, monkeypatch):
    _, lock = desktop
    sock = MagicMock()
    sock.__enter__.return_value = sock
    monkeypatch.setattr(service.socket, "socket", lambda *args: sock)
    monkeypatch.setattr(service, "peer_uid", lambda conn: 1000)
    monkeypatch.setattr(
        service,
        "receive",
        lambda conn: {
            "session_id": SESSION,
            "instance_id": "a" * 32,
            "progress_at": service.boottime(),
            "state": "accepted",
            "notification_id": 42,
        },
    )
    assert service.rpc(lock, "status")["notification_id"] == 42
    assert service.rpc(lock, "notify", event="started", wait=False)["state"] == "pending"
    del lock["notification_target"]
    with pytest.raises(service.NotificationError, match="recipient"):
        service.rpc(lock, "status")


def test_delivery_pending_is_not_synchronous_success_and_storage_failure_is_reported(desktop, monkeypatch):
    _, lock = desktop
    monkeypatch.setattr(service, "rpc", Mock(return_value={"state": "pending", "reason": "pending"}))
    monkeypatch.setattr(RecordStore, "write", Mock(side_effect=OSError()))
    result = service.emit(lock, "started")
    assert {d.reason for d in result.diagnostics} == {
        "notifications.acceptance_pending",
        "notifications.evidence_write_failed",
    }
    with pytest.raises(ValueError):
        service.emit(lock, "arbitrary_event")


def test_failed_agent_shutdown_retains_delivery_diagnostics(desktop, monkeypatch):
    _, lock = desktop
    monkeypatch.setattr(service, "rpc", Mock(side_effect=OSError()))
    monkeypatch.setattr(service, "stop_agent", Mock(side_effect=OSError()))
    result = service.finish_notifications(lock)
    assert {d.reason for d in result.diagnostics} == {
        "notifications.agent_unavailable",
        "notifications.agent_stop_failed",
    }


def test_unit_cleanup_and_readiness_identity(desktop, monkeypatch, tmp_path):
    _, lock = desktop
    path = tmp_path / "agent.service"
    monkeypatch.setattr(service, "UNIT_PATH", path)
    monkeypatch.setattr(service.subprocess, "run", Mock())
    monkeypatch.setattr(service, "rpc", Mock(return_value={"state": "pending"}))
    with pytest.raises(service.NotificationError, match="identity"):
        service.start_agent(lock, lock["notification_target"])
    service.stop_agent()
    assert not path.exists()
    with pytest.raises(service.NotificationError):
        service._quote("injected\nExecStart=bad")


def test_invalid_recipient_listing_and_total_discovery_deadline(monkeypatch):
    monkeypatch.setattr(service.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000))
    monkeypatch.setattr(service.subprocess, "run", Mock(return_value=SimpleNamespace(stdout="\n../bad user\n")))
    with pytest.raises(service.NotificationError, match="identifier"):
        service.recipient("alice")
    monkeypatch.setattr(service, "boottime", Mock(side_effect=[0, 6]))
    with pytest.raises(service.NotificationError, match="timed out"):
        service.recipient("alice")


def test_protocol_valid_packet_and_invalid_recipient():
    sock = Mock()
    sock.recv.return_value = b'{"operation":"status"}'
    assert protocol.receive(sock)["operation"] == "status"
    with pytest.raises(ValueError):
        protocol.socket_path(0, SESSION)
