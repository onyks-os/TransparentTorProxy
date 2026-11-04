# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Shared properties over production parsers; no privileged actions or networking."""

import json

from ttp.commands._validation import parse_txt_dig_ipv4, validate_bridge_line
from ttp.evidence import Diagnostic
from ttp.netprobe import _MAX_FIELD, reduce
from ttp.settings import Settings, SettingsError


def exercise_text(text: str) -> None:
    try:
        validate_bridge_line(text)
    except ValueError:
        pass
    else:
        assert all(char == "\t" or 32 <= ord(char) <= 126 for char in text)
        assert text.split()
    address = parse_txt_dig_ipv4(text)
    assert address is None or address in text


def exercise_value(value: object) -> None:
    reduced = reduce(value)
    if reduced is not None:
        assert set(reduced) <= {"IP", "ip", "ip_addr", "IsTor"}
        for key, field in reduced.items():
            assert type(field) is bool if key == "IsTor" else isinstance(field, str) and len(field) <= _MAX_FIELD
    try:
        config = Settings.from_snapshot(value)
    except SettingsError:
        pass
    else:
        assert Settings.from_snapshot(config.snapshot()) == config
        config.validate()
    try:
        diagnostic = Diagnostic.from_dict(value)
    except ValueError:
        pass
    else:
        assert Diagnostic.from_dict(diagnostic.as_dict()) == diagnostic


def exercise_bytes(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    exercise_text(text)
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return
    exercise_value(value)
