"""M5 properties of what an API answer is reduced to: it never fails, it never keeps a value, and it does not depend on order."""

from __future__ import annotations

import json
import random
from typing import Any

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from scopedagent.adapters.parse import MAX_SHAPE_ENTRIES, api_markers, json_shape
from scopedagent.domain.schemas import ShapeEntry

pytestmark = pytest.mark.milestone("M5")

KEYS = st.text(min_size=0, max_size=12)
LEAVES = (
    st.none()
    | st.booleans()
    | st.integers(-(10**6), 10**6)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=20)
)
DOCS = st.recursive(
    LEAVES,
    lambda inner: st.lists(inner, max_size=6) | st.dictionaries(KEYS, inner, max_size=6),
    max_leaves=40,
)


@settings(max_examples=150, deadline=None)
@given(DOCS)
@example({"": [], "a b": {"x<": None}})
def test_any_json_document_has_a_shape_that_fits_the_schema_and_never_raises(doc: Any) -> None:
    shape = json_shape(json.dumps(doc))
    assert shape.status in ("ok", "partial") and len(shape.entries) <= MAX_SHAPE_ENTRIES
    assert shape.digest is not None and len(shape.digest) == 64
    for path, kind, length in shape.entries:
        ShapeEntry.model_validate({"path": path, "type": kind, "length": length})  # every entry is storable


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=300))
def test_any_text_at_all_is_a_shape_or_not_json_and_never_an_error(text: str) -> None:
    shape = json_shape(text)
    assert shape.status in ("ok", "partial", "not_json")
    assert api_markers(text, shape).keys() == {"has_stack_trace_markers", "has_debug_markers", "echoes_request_headers"}


@settings(max_examples=100, deadline=None)
@given(st.dictionaries(st.from_regex(r"[a-z]{1,8}", fullmatch=True), LEAVES, min_size=1, max_size=10), st.randoms())
def test_the_digest_does_not_depend_on_the_order_of_keys(doc: dict[str, Any], rng: random.Random) -> None:
    items = list(doc.items())
    shuffled = items[:]
    rng.shuffle(shuffled)
    assert json_shape(json.dumps(dict(items))).digest == json_shape(json.dumps(dict(shuffled))).digest


@settings(max_examples=100, deadline=None)
@given(st.from_regex(r"[A-Za-z0-9]{12,40}", fullmatch=True), st.from_regex(r"[A-Za-z0-9]{12,40}", fullmatch=True))
def test_a_value_never_appears_in_the_shape_whatever_it_is(first: str, second: str) -> None:
    doc = {"name": first, "items": [{"id": second}]}
    rendered = repr(json_shape(json.dumps(doc)))
    assert first not in rendered and second not in rendered


@settings(max_examples=100, deadline=None)
@given(
    st.text(min_size=1, max_size=30).filter(lambda s: any(not (c.isascii() and (c.isalnum() or c in "_.-")) for c in s))
)
def test_a_key_that_is_not_a_plain_name_is_never_stored(key: str) -> None:
    shape = json_shape(json.dumps({key: 1}))
    assert [path for path, _, _ in shape.entries] == ["$", "$.?"]
