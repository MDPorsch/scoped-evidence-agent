"""Stage 2a: whatever a hostile target sends in `Set-Cookie`, the parser never fails and never lets a value through."""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scopedagent.adapters.parse import MAX_COOKIES, cookie_flags
from scopedagent.domain.schemas import CookieFlags

pytestmark = pytest.mark.milestone("M7")

TOKEN = "SYNTHETICVALUE9X7Q2"  # a value no name or flag can spell


@settings(max_examples=300, deadline=None)
@given(st.lists(st.text(max_size=300), max_size=40))
def test_any_header_text_gives_valid_records_and_at_most_sixteen(headers: list[str]) -> None:
    cookies = cookie_flags(headers)
    assert len(cookies) <= MAX_COOKIES
    for cookie in cookies:
        CookieFlags.model_validate(cookie)


@settings(max_examples=300, deadline=None)
@given(
    st.text(alphabet=st.characters(blacklist_characters="=;"), max_size=20),
    st.text(alphabet=st.characters(blacklist_characters=";"), max_size=40),
    st.lists(st.sampled_from(["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Domain=x.invalid", "junk"]), max_size=6),
)
def test_the_value_of_a_cookie_is_never_kept(name: str, value: str, attributes: list[str]) -> None:
    header = "; ".join([f"{name}={TOKEN}{value}", *attributes])
    assert TOKEN not in json.dumps(cookie_flags([header]))
