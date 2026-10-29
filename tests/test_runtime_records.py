# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Real files and locks: evidence must never become partial or silently healthy."""

import json
import os

import pytest

from ttp import runtime_records as records
from ttp.exceptions import StateError


@pytest.fixture
def store(tmp_path):
    result = records.RecordStore(tmp_path / "observations", os.getuid(), os.getgid())
    result.prepare()
    return result


def test_atomic_replacement_leaves_open_reader_on_complete_old_record(store):
    store.write("emergency", "session", {"requested": True, "verified": False})
    with (store.directory / store._filename("emergency", "session")).open() as old:
        store.write("emergency", "session", {"requested": True, "verified": True})
        assert not json.load(old)["data"]["verified"]
    assert store.read("emergency", "session")["data"]["verified"]
    assert not list(store.directory.glob("*.tmp"))
    assert (store.directory / store._filename("emergency", "session")).stat().st_mode & 0o777 == 0o600


def test_absence_foreign_session_and_previous_boot_are_not_current(store, monkeypatch):
    assert store.read("emergency", "s") is None
    store.write("emergency", "s", {"requested": True})
    assert store.read("emergency", "other") is None
    monkeypatch.setattr(records, "boot_id", lambda: "00000000-0000-0000-0000-000000000000")
    assert store.read("emergency", "s") is None


def test_boot_identity_failure_is_not_absent_evidence(store, monkeypatch, tmp_path):
    monkeypatch.setattr(records, "BOOT_ID_PATH", tmp_path / "missing")
    with pytest.raises(StateError, match="boot identity"):
        store.read("emergency", "s")
    with pytest.raises(StateError, match="publish"):
        store.write("emergency", "s", {})


@pytest.mark.parametrize("name", ["../outside", "", "ttp.lock"])
def test_record_names_cannot_escape_directory(store, name):
    with pytest.raises(StateError, match="Unknown observation"):
        store.write(name, "s", {})
    with pytest.raises(StateError):
        store.read(name, "s")


def test_write_replaces_symlink_without_modifying_target(store, tmp_path):
    target = tmp_path / "target"
    target.write_text("untouched")
    (store.directory / store._filename("emergency", "s")).symlink_to(target)
    with pytest.raises(StateError):
        store.read("emergency", "s")
    store.write("emergency", "s", {"requested": True})
    assert target.read_text() == "untouched"
    assert not (store.directory / store._filename("emergency", "s")).is_symlink()


@pytest.mark.parametrize("mutation", ["mode", "hardlink", "fifo", "directory"])
def test_untrusted_record_types_and_permissions_are_rejected(store, mutation, tmp_path):
    store.write("emergency", "s", {})
    path = store.directory / store._filename("emergency", "s")
    if mutation == "mode":
        path.chmod(0o644)
    elif mutation == "hardlink":
        os.link(path, tmp_path / "alias")
    else:
        path.unlink()
        if mutation == "fifo":
            os.mkfifo(path)
        else:
            path.mkdir()
    with pytest.raises(StateError):
        store.read("emergency", "s")


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("schema", 2),
        ("data", []),
        ("session_id", ""),
        ("boot_id", None),
        ("boot_id", "invalid"),
        ("written_at", True),
        ("written_at", -1),
        ("written_at", float("inf")),
        ("written_at", None),
    ],
)
def test_corrupt_evidence_is_an_error_not_an_absent_latch(store, field, value):
    store.write("emergency", "s", {})
    path = store.directory / store._filename("emergency", "s")
    payload = json.loads(path.read_text())
    payload[field] = value
    path.write_text(json.dumps(payload))
    with pytest.raises(StateError):
        store.read("emergency", "s")


@pytest.mark.parametrize("content", ["{", "null", "[]", "x" * (records.MAX_RECORD_BYTES + 1)])
def test_invalid_or_oversized_file(store, content):
    store.write("emergency", "s", {})
    (store.directory / store._filename("emergency", "s")).write_text(content)
    with pytest.raises(StateError):
        store.read("emergency", "s")


def test_failed_publish_keeps_last_complete_record(store, monkeypatch):
    store.write("emergency", "s", {"requested": True})

    def fail(*args, **kwargs):
        raise OSError("out of space")

    monkeypatch.setattr(records.os, "rename", fail)
    with pytest.raises(StateError, match="out of space"):
        store.write("emergency", "s", {"requested": False})
    assert store.read("emergency", "s")["data"]["requested"]
    assert not list(store.directory.glob("*.tmp"))


@pytest.mark.parametrize(
    "session,data", [("", {}), ("s", {"v": float("nan")}), ("s", {"v": "x" * records.MAX_RECORD_BYTES})]
)
def test_invalid_publish_arguments(store, session, data):
    with pytest.raises(StateError):
        store.write("emergency", session, data)


def test_unsafe_directory_is_not_used(store):
    store.directory.chmod(0o755)
    with pytest.raises(StateError, match="directory"):
        store.write("emergency", "s", {})
    store.prepare()
    store.write("emergency", "s", {})


def test_transition_lock_serializes_and_releases_on_exception(store):
    with store.transition():
        with pytest.raises(StateError, match="Timed out"):
            with store.transition(timeout=0.01):
                pytest.fail("concurrent transition entered")
    with pytest.raises(RuntimeError):
        with store.transition():
            raise RuntimeError("interrupted")
    with store.transition():
        pass


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_transition_budget(store, timeout):
    with pytest.raises(StateError, match="timeout"):
        with store.transition(timeout=timeout):
            pytest.fail("invalid timeout accepted")


def test_transition_rejects_hardlink(store, tmp_path):
    with store.transition():
        pass
    os.link(store.directory / "transition.lock", tmp_path / "alias")
    with pytest.raises(StateError, match="Invalid transition"):
        with store.transition():
            pytest.fail("hardlinked lock accepted")


def test_session_store_uses_watchdog_account(monkeypatch, tmp_path):
    from ttp import state

    monkeypatch.setattr(state, "LOCK_DIR", tmp_path)
    monkeypatch.setattr(state, "_watchdog_uid_or_root", lambda: 42)
    monkeypatch.setattr(state, "_watchdog_gid", lambda: 43)
    assert records.session_store() == records.RecordStore(tmp_path / "watchdog", 42, 43)


def test_boot_id_is_canonical_uuid(monkeypatch, tmp_path):
    path = tmp_path / "boot"
    path.write_text("ABCDEF00-0000-0000-0000-000000000000\n")
    monkeypatch.setattr(records, "BOOT_ID_PATH", path)
    assert records.boot_id() == "abcdef00-0000-0000-0000-000000000000"


def test_late_old_session_writer_cannot_replace_new_session_emergency(store):
    store.write("emergency", "new", {"requested": True})
    store.write("emergency", "old", {"requested": False})
    assert store.read("emergency", "new")["data"]["requested"] is True
