# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
"""Generate adversarial inputs for actual TTP parsers, sharing Atheris properties."""

from hypothesis import given
from hypothesis import strategies as st

from fuzzing.parsers import exercise_bytes, exercise_text, exercise_value
from ttp.settings import Settings

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=100),
    lambda children: st.lists(children, max_size=8) | st.dictionaries(st.text(max_size=40), children, max_size=8),
    max_leaves=30,
)


@given(st.binary(max_size=16384))
def test_untrusted_serialized_input(data):
    exercise_bytes(data)


@given(st.text(max_size=2000))
def test_bridge_and_dns_output(text):
    exercise_text(text)


@given(json_values)
def test_structured_replies_and_snapshots(value):
    exercise_value(value)


@given(st.sampled_from(tuple(Settings().snapshot())), json_values)
def test_snapshot_section_mutations(section, value):
    snapshot = Settings().snapshot()
    snapshot[section] = value
    exercise_value(snapshot)


@given(st.data(), json_values)
def test_snapshot_field_mutations(data, value):
    snapshot = Settings().snapshot()
    section = data.draw(st.sampled_from(tuple(snapshot)))
    field = data.draw(st.sampled_from(tuple(snapshot[section])))
    snapshot[section][field] = value
    exercise_value(snapshot)


@given(st.fixed_dictionaries({}, optional={key: json_values for key in ("IP", "ip", "ip_addr", "IsTor")}))
def test_external_result_fields(value):
    exercise_value(value)
