"""Stage 2a, check A1: a cookie's name and three flags are recorded; its value never is."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from pydantic import ValidationError

from scopedagent.adapters.offline import OfflineHttp
from scopedagent.adapters.pack import Pack
from scopedagent.adapters.parse import MAX_COOKIES, cookie_flags
from scopedagent.domain.schemas import CookieFlags, HttpPayload
from scopedagent.policy.scope import PlannedOperation
from tests.support import assemble

pytestmark = pytest.mark.milestone("M7")

HOST = "lab.example.invalid"
SECRET = assemble("SYNTHETIC", "-SESSION-", "VALUE-0001")


def one(header: str) -> dict[str, Any]:
    (cookie,) = cookie_flags([header])
    return cookie


# ----------------------------------------------------------------------------------------------- the parser ----
def test_a_cookie_with_no_attributes_has_no_flag() -> None:
    assert one("session=abc") == {"name": "session", "secure": False, "http_only": False, "same_site": "missing"}


@pytest.mark.parametrize(
    ("header", "secure", "http_only", "same_site"),
    [
        ("a=1; Secure", True, False, "missing"),
        ("a=1; HttpOnly", False, True, "missing"),
        ("a=1; SameSite=Lax", False, False, "lax"),
        ("a=1; SameSite=Strict", False, False, "strict"),
        ("a=1; SameSite=None; Secure", True, False, "none"),
        ("a=1; SECURE; HTTPONLY; SAMESITE=STRICT", True, True, "strict"),
        ("a=1;secure;httponly;samesite=lax", True, True, "lax"),
        ("a=1 ;  Secure  ;  HttpOnly ; SameSite = Lax ", True, True, "lax"),
        ("a=1; Path=/; Domain=example.invalid; Max-Age=60; Secure", True, False, "missing"),
        ("a=1; SameSite=Bogus", False, False, "other"),
        ("a=1; SameSite=", False, False, "other"),
        ("a=1; SameSite=Lax; SameSite=Strict", False, False, "strict"),  # the last one is the one a browser uses
        ("a=1; Secure=false", True, False, "missing"),  # a flag is present or not; its setting is ignored
    ],
)
def test_the_three_flags_are_read_whatever_the_case_spacing_or_order(
    header: str, secure: bool, http_only: bool, same_site: str
) -> None:
    cookie = one(header)
    assert (cookie["secure"], cookie["http_only"], cookie["same_site"]) == (secure, http_only, same_site)


def test_the_value_is_never_in_the_result() -> None:
    for header in (f"sid={SECRET}; Secure", f"sid={SECRET}", f"sid==={SECRET};;;", f"sid={SECRET}; Path={SECRET}"):
        assert SECRET not in json.dumps(cookie_flags([header]))
    assert one(f"sid={SECRET}; Secure")["name"] == "sid"


@pytest.mark.parametrize("name", ["__Host-id", "__Secure-sid", "a.b_c-d", "A1", "x" * 64])
def test_a_plain_name_is_kept(name: str) -> None:
    assert one(f"{name}=1")["name"] == name


@pytest.mark.parametrize("name", ["", " ", "a b", "a" * 65, "<script>", "naïve", "a\nb", "a/b"])
def test_a_name_that_is_not_short_and_plain_becomes_a_question_mark(name: str) -> None:
    (cookie,) = cookie_flags([f"{name}=1; Secure"])
    assert cookie["name"] == "?" and cookie["secure"] is True


def test_a_header_that_is_not_a_cookie_is_skipped() -> None:
    assert cookie_flags(["", "no equals sign; Secure", "; Secure"]) == []
    assert [c["name"] for c in cookie_flags(["x", "a=1", "y; Secure", "b=2"])] == ["a", "b"]


def test_no_header_means_no_cookie() -> None:
    assert cookie_flags([]) == []


def test_at_most_sixteen_cookies_are_kept_in_order() -> None:
    cookies = cookie_flags([f"c{i}=v" for i in range(40)])
    assert MAX_COOKIES == 16 and [c["name"] for c in cookies] == [f"c{i}" for i in range(16)]
    assert (
        len(cookie_flags([f"c{i}=v" for i in range(16)])) == 16
        and len(cookie_flags([f"c{i}=v" for i in range(15)])) == 15
    )


def test_a_very_long_header_is_handled() -> None:
    assert len(cookie_flags(["a=" + "x" * 1_000_000 + "; Secure"])) == 1


# ------------------------------------------------------------------------------------------------ the schema ----
def test_every_parser_result_is_a_valid_cookie_record() -> None:
    for header in ("a=1", "a=1; Secure; HttpOnly; SameSite=None", "<x>=1", "b=2; SameSite=Weird"):
        CookieFlags.model_validate(one(header))


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "a b", "secure": True, "http_only": True, "same_site": "lax"},
        {"name": "", "secure": True, "http_only": True, "same_site": "lax"},
        {"name": "a" * 65, "secure": True, "http_only": True, "same_site": "lax"},
        {"name": "a", "secure": "yes", "http_only": True, "same_site": "lax"},
        {"name": "a", "secure": True, "http_only": True, "same_site": "sometimes"},
        {"name": "a", "secure": True, "http_only": True, "same_site": "lax", "value": "x"},
        {"name": "a", "secure": True, "http_only": True},
    ],
)
def test_a_cookie_record_outside_the_schema_is_refused(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CookieFlags.model_validate(bad)


def http_payload(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "host": HOST, "port": 443, "scheme": "https", "path": "/", "method": "GET", "http_status": 200,
        "headers": {}, "redirect_location": None, "body": None,
    }  # fmt: skip
    base.update(over)
    return base


def test_an_http_observation_stored_before_cookies_were_recorded_still_validates_with_none() -> None:
    assert HttpPayload.model_validate(http_payload()).cookies == []


def test_at_most_sixteen_cookies_fit_in_a_payload() -> None:
    cookie = {"name": "a", "secure": True, "http_only": True, "same_site": "lax"}
    assert len(HttpPayload.model_validate(http_payload(cookies=[cookie] * 16)).cookies) == 16
    with pytest.raises(ValidationError):
        HttpPayload.model_validate(http_payload(cookies=[cookie] * 17))


# ----------------------------------------------------------------------------------------------- the adapter ----
def collect(headers: dict[str, list[str]]) -> Any:
    pack = Pack("t", {}, {}, {f"https://{HOST}:443/": {"status": 200, "headers": headers, "body": "x"}}, {}, {})
    return asyncio.run(OfflineHttp(pack, 100_000).collect(PlannedOperation("http_metadata", HOST, "https", 443, "/")))


def test_the_adapter_records_the_flags_and_still_redacts_the_header() -> None:
    result = collect({"set-cookie": [f"sid={SECRET}; HttpOnly", "theme=dark; Secure; SameSite=Lax"]})
    payload = result.envelope.payload.model_dump()
    assert [(c["name"], c["secure"], c["http_only"], c["same_site"]) for c in payload["cookies"]] == [
        ("sid", False, True, "missing"),
        ("theme", True, False, "lax"),
    ]
    assert payload["headers"]["set-cookie"] == ["[REDACTED]", "[REDACTED]"]
    assert SECRET not in json.dumps(payload)
    assert SECRET.encode() not in (result.body or b"") and SECRET.encode() not in result.source_bytes


def test_a_response_without_cookies_records_an_empty_list() -> None:
    assert collect({"content-type": ["text/plain"]}).envelope.payload.cookies == []


def test_a_cookie_header_in_any_letter_case_is_read() -> None:
    assert [c.name for c in collect({"Set-Cookie": ["a=1"]}).envelope.payload.cookies] == ["a"]
