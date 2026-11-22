"""Stage 2a: the three passive rules (R-COOKIE-01, R-HDR-02, R-API-02). Each is tested on its gate, what it must say, what it
must not, and its edges. Observations are built from payloads the real schemas validate."""

from __future__ import annotations

from typing import Any

import pytest

from scopedagent.domain.findings import Assessment, SeverityValue, VulnClass
from scopedagent.pipeline.rules import HSTS_SHORT_SECONDS, ObservationView, RuleDraft
from scopedagent.policy.scope import ScopeConfig, parse_scope
from tests.support import NOW, dump, scope_dict
from tests.unit.test_rules import FINGERPRINT, HOST, WEB_TARGET, evaluate, only, view

pytestmark = pytest.mark.milestone("M7")


def checked(passive: list[str], name: str = "misconfigured") -> ScopeConfig:
    data = scope_dict(name)
    data["checks"] = {"passive": passive}
    return parse_scope(dump(data), now=NOW).config


def cookie(name: str, *, secure: bool = True, http_only: bool = True, same_site: str = "lax") -> dict[str, Any]:
    return {"name": name, "secure": secure, "http_only": http_only, "same_site": same_site}


def web(
    path: str = "/",
    status: int = 200,
    headers: dict[str, list[str]] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    scheme: str = "https",
    port: int = 443,
) -> ObservationView:
    payload = {
        "host": HOST, "port": port, "scheme": scheme, "path": path, "method": "GET", "http_status": status,
        "headers": headers or {}, "redirect_location": None, "body": None, "cookies": cookies or [],
    }  # fmt: skip
    return view("http_metadata", payload, target=(HOST, scheme, port))


# ======================================================================================================= R-COOKIE-01
def cookie_draft(*views: ObservationView) -> RuleDraft:
    return only(evaluate(*views, config=checked(["cookie_flags"]), rule="R-COOKIE-01"))


def test_the_cookie_rule_is_silent_unless_the_scope_switches_it_on() -> None:
    weak = web(cookies=[cookie("sid", secure=False, http_only=False, same_site="missing")])
    assert evaluate(weak, rule="R-COOKIE-01") == []  # no checks block at all
    assert evaluate(weak, config=checked(["header_quality"]), rule="R-COOKIE-01") == []  # another check only


def test_a_cookie_with_every_flag_makes_no_draft() -> None:
    assert evaluate(web(cookies=[cookie("sid")]), config=checked(["cookie_flags"]), rule="R-COOKIE-01") == []
    assert evaluate(web(), config=checked(["cookie_flags"]), rule="R-COOKIE-01") == []  # no cookie at all


def test_a_cookie_with_no_flags_gives_one_conditional_low_draft_with_its_three_conditions_in_order() -> None:
    weak = web(cookies=[cookie("sid", secure=False, http_only=False, same_site="missing")])
    draft = cookie_draft(weak)
    assert draft.vulnerability_class is VulnClass.INSECURE_COOKIE and draft.rule_id == "R-COOKIE-01"
    assert draft.title == f"Cookie flags missing on {HOST}:443"
    assert draft.conditions == (
        "1 cookie has no Secure attribute, so a browser may send it over plain http.",
        "1 cookie has no HttpOnly attribute, so a script on the page can read it.",
        "1 cookie has no SameSite attribute, so the site does not state whether it goes with cross-site requests.",
    )
    assert draft.facts == ("cookie lacking Secure: sid", "cookie lacking HttpOnly: sid", "cookie lacking SameSite: sid")
    assert list(draft.cwe_candidates) == ["CWE-614", "CWE-1004", "CWE-1275"]
    assert (draft.assessment, draft.severity, draft.confidence) == (Assessment.CONDITIONAL, SeverityValue.LOW, 0.5)
    assert draft.evidence == (weak.id,)
    assert [s.kind for s in draft.specs] == ["read_recorded_observation", "rerequest_listed_path", "owner_confirmation"]
    assert any("never saw a cookie's value" in u for u in draft.unknowns)


@pytest.mark.parametrize(
    ("flags", "text", "cwe"),
    [
        ({"secure": False}, "no Secure attribute", "CWE-614"),
        ({"http_only": False}, "no HttpOnly attribute", "CWE-1004"),
        ({"same_site": "missing"}, "no SameSite attribute", "CWE-1275"),
    ],
)
def test_each_missing_flag_alone_gives_only_its_condition_and_its_cwe(
    flags: dict[str, Any], text: str, cwe: str
) -> None:
    draft = cookie_draft(web(cookies=[cookie("sid", **flags)]))
    assert len(draft.conditions) == 1 and text in draft.conditions[0] and list(draft.cwe_candidates) == [cwe]


@pytest.mark.parametrize("same_site", ["lax", "strict", "none", "other"])
def test_a_stated_samesite_value_is_not_a_missing_flag(same_site: str) -> None:
    weak = web(cookies=[cookie("sid", same_site=same_site)])
    assert evaluate(weak, config=checked(["cookie_flags"]), rule="R-COOKIE-01") == []


def test_secure_is_not_asked_of_a_response_that_was_not_https() -> None:
    plain = web(scheme="http", port=80, cookies=[cookie("sid", secure=False)])
    assert evaluate(plain, config=checked(["cookie_flags"]), rule="R-COOKIE-01") == []
    both = web(scheme="http", port=80, cookies=[cookie("sid", secure=False, http_only=False)])
    draft = cookie_draft(both)
    assert len(draft.conditions) == 1 and "HttpOnly" in draft.conditions[0]


def test_two_cookies_are_counted_and_worded_in_the_plural() -> None:
    draft = cookie_draft(web(cookies=[cookie("a", secure=False), cookie("b", secure=False), cookie("c")]))
    assert draft.conditions == ("2 cookies have no Secure attribute, so a browser may send them over plain http.",)
    assert draft.facts == ("cookie lacking Secure: a", "cookie lacking Secure: b")


def test_the_same_cookie_in_several_responses_is_counted_once_and_only_weak_responses_are_cited() -> None:
    one = web("/", cookies=[cookie("sid", secure=False)])
    two = web("/app", cookies=[cookie("sid", secure=False)])
    fine = web("/ok", cookies=[cookie("theme")])
    draft = cookie_draft(one, two, fine)
    assert draft.conditions == ("1 cookie has no Secure attribute, so a browser may send it over plain http.",)
    assert draft.evidence == (one.id, two.id)


def test_a_cookie_with_an_unusual_name_is_counted_but_never_quoted() -> None:
    draft = cookie_draft(web(cookies=[cookie("?", secure=False)]))
    assert draft.conditions[0].startswith("1 cookie has no Secure") and draft.facts == ()


def test_no_more_than_six_cookie_names_are_quoted() -> None:
    draft = cookie_draft(web(cookies=[cookie(f"c{i}", secure=False) for i in range(10)]))
    assert draft.conditions == ("10 cookies have no Secure attribute, so a browser may send them over plain http.",)
    assert len(draft.facts) == 6


def test_each_target_gets_its_own_cookie_draft_and_an_errored_observation_is_ignored() -> None:
    other = view(
        "http_metadata",
        {
            "host": "b.example.invalid", "port": 443, "scheme": "https", "path": "/", "method": "GET",
            "http_status": 200, "headers": {}, "redirect_location": None, "body": None,
            "cookies": [cookie("x", secure=False)],
        },
        target=("b.example.invalid", "https", 443),
    )  # fmt: skip
    mine = web(cookies=[cookie("y", secure=False)])
    errored = view(
        "http_metadata",
        {
            "host": HOST, "port": 8443, "scheme": "https", "path": "/", "method": "GET", "http_status": None,
            "headers": {}, "redirect_location": None, "body": None, "cookies": [cookie("z", secure=False)],
        },
        target=(HOST, "https", 8443),
        error_status="timeout",
    )  # fmt: skip
    drafts = evaluate(mine, other, errored, config=checked(["cookie_flags"]), rule="R-COOKIE-01")
    assert sorted(d.title for d in drafts) == sorted(
        [f"Cookie flags missing on {HOST}:443", "Cookie flags missing on b.example.invalid:443"]
    )


# ========================================================================================================= R-HDR-02
def header_draft(*views: ObservationView) -> RuleDraft:
    return only(evaluate(*views, config=checked(["header_quality"]), rule="R-HDR-02"))


def issues(headers: dict[str, list[str]]) -> tuple[str, ...]:
    drafts = evaluate(web(headers=headers), config=checked(["header_quality"]), rule="R-HDR-02")
    return drafts[0].conditions if drafts else ()


EVAL = "The Content-Security-Policy lets scripts use eval ('unsafe-eval')."
INLINE = "The Content-Security-Policy lets any inline script run ('unsafe-inline' with no nonce or hash)."
ANYHOST = "The Content-Security-Policy lets scripts load from any host (*)."


def test_the_header_rule_is_silent_unless_the_scope_switches_it_on() -> None:
    weak = web(headers={"content-security-policy": ["script-src 'unsafe-inline'"]})
    assert evaluate(weak, rule="R-HDR-02") == []
    assert evaluate(weak, config=checked(["cookie_flags"]), rule="R-HDR-02") == []


def test_a_weak_policy_gives_one_conditional_low_draft() -> None:
    weak = web(headers={"content-security-policy": ["script-src 'unsafe-eval'"]})
    draft = header_draft(weak)
    assert (
        draft.vulnerability_class is VulnClass.WEAK_HEADER_POLICY
        and draft.title == f"Weak security header policy on {HOST}:443"
    )
    assert draft.conditions == (EVAL,) and list(draft.cwe_candidates) == ["CWE-693"]
    assert (draft.assessment, draft.severity, draft.confidence) == (Assessment.CONDITIONAL, SeverityValue.LOW, 0.6)
    assert draft.evidence == (weak.id,) and draft.facts == ()
    assert [s.kind for s in draft.specs] == ["read_recorded_observation", "rerequest_listed_path", "owner_confirmation"]


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("script-src 'self' 'unsafe-eval'", (EVAL,)),
        ("script-src 'self' 'unsafe-inline'", (INLINE,)),
        ("script-src 'unsafe-inline' 'unsafe-eval'", (EVAL, INLINE)),
        ("script-src *", (ANYHOST,)),
        ("script-src 'self' https://cdn.example.invalid", ()),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", ()),  # a nonce makes a browser ignore 'unsafe-inline'
        ("script-src 'unsafe-inline' 'sha256-AAAA'", ()),
        ("script-src 'unsafe-inline' 'sha384-AAAA'", ()),
        ("script-src 'unsafe-inline' 'sha512-AAAA'", ()),
        ("script-src 'unsafe-inline' 'strict-dynamic'", ()),
        ("default-src 'self' 'unsafe-inline'", (INLINE,)),  # no script-src: default-src governs scripts
        ("default-src 'unsafe-inline'; script-src 'self'", ()),  # script-src overrides default-src
        ("SCRIPT-SRC 'UNSAFE-EVAL'", (EVAL,)),
        ("style-src 'unsafe-inline'", ()),  # styles are not scripts
        ("img-src *", ()),
        ("default-src 'none'", ()),
        ("script-src 'self'; ; style-src 'unsafe-inline'", ()),
        ("", ()),
    ],
)
def test_the_content_security_policy_is_judged_by_the_directive_that_governs_scripts(
    csp: str, expected: tuple[str, ...]
) -> None:
    assert issues({"content-security-policy": [csp]}) == expected


def test_an_absent_policy_is_not_this_rules_business() -> None:
    assert issues({}) == () and issues({"x-content-type-options": ["nosniff"]}) == ()  # R-HDR-01 reports absence


@pytest.mark.parametrize(
    ("hsts", "expected"),
    [
        (f"max-age={HSTS_SHORT_SECONDS}", ()),
        (
            f"max-age={HSTS_SHORT_SECONDS - 1}",
            ("The Strict-Transport-Security max-age is 15551999 seconds, under 180 days.",),
        ),
        ("max-age=31536000; includeSubDomains; preload", ()),
        ("max-age=3600", ("The Strict-Transport-Security max-age is 3600 seconds, under 180 days.",)),
        (
            "max-age=0",
            ("The Strict-Transport-Security max-age is 0 seconds, under 180 days (0 turns the protection off).",),
        ),
        ('max-age="100"', ("The Strict-Transport-Security max-age is 100 seconds, under 180 days.",)),
        ("MAX-AGE = 60", ("The Strict-Transport-Security max-age is 60 seconds, under 180 days.",)),
        ("includeSubDomains", ("The Strict-Transport-Security header has no max-age.",)),
        ("max-age=abc", ("The Strict-Transport-Security header has no max-age.",)),
    ],
)
def test_strict_transport_security_is_short_below_a_hundred_and_eighty_days(
    hsts: str, expected: tuple[str, ...]
) -> None:
    assert HSTS_SHORT_SECONDS == 180 * 24 * 3600
    assert issues({"strict-transport-security": [hsts]}) == expected


@pytest.mark.parametrize(
    ("policy", "weak"),
    [
        ("unsafe-url", True),
        ("UNSAFE-URL", True),
        ("origin, unsafe-url", True),
        ("no-referrer", False),
        ("strict-origin-when-cross-origin", False),
        ("same-origin", False),
    ],
)
def test_only_an_unsafe_url_referrer_policy_is_weak_and_an_absent_one_is_not(policy: str, weak: bool) -> None:
    expected = ("The Referrer-Policy is unsafe-url, which sends the full address to other sites.",) if weak else ()
    assert issues({"referrer-policy": [policy]}) == expected


def test_conditions_from_all_responses_are_merged_without_repeats_and_only_weak_responses_are_cited() -> None:
    a = web("/", headers={"content-security-policy": ["script-src 'unsafe-eval'"]})
    b = web("/b", headers={"content-security-policy": ["script-src 'unsafe-eval'"], "referrer-policy": ["unsafe-url"]})
    c = web("/c", headers={"content-security-policy": ["script-src 'self'"]})
    draft = header_draft(a, b, c)
    assert len(draft.conditions) == 2 and draft.conditions[0] == EVAL and "Referrer-Policy" in draft.conditions[1]
    assert draft.evidence == (a.id, b.id)


@pytest.mark.parametrize("status", [199, 400, 404, 500])
def test_a_response_outside_two_hundred_to_three_ninety_nine_is_not_judged(status: int) -> None:
    weak = web(status=status, headers={"content-security-policy": ["script-src 'unsafe-eval'"]})
    assert evaluate(weak, config=checked(["header_quality"]), rule="R-HDR-02") == []


@pytest.mark.parametrize("status", [200, 301, 399])
def test_the_edges_of_the_judged_range_are_judged(status: int) -> None:
    weak = web(status=status, headers={"content-security-policy": ["script-src 'unsafe-eval'"]})
    assert len(evaluate(weak, config=checked(["header_quality"]), rule="R-HDR-02")) == 1


def test_a_plain_http_response_is_not_judged_and_a_missing_status_is_not_judged() -> None:
    weak = {"content-security-policy": ["script-src 'unsafe-eval'"]}
    assert (
        evaluate(web(scheme="http", port=80, headers=weak), config=checked(["header_quality"]), rule="R-HDR-02") == []
    )
    unknown = view(
        "http_metadata",
        {
            "host": HOST, "port": 443, "scheme": "https", "path": "/", "method": "GET", "http_status": None,
            "headers": weak, "redirect_location": None, "body": None,
        },
        target=WEB_TARGET,
    )  # fmt: skip
    assert evaluate(unknown, config=checked(["header_quality"]), rule="R-HDR-02") == []


# ======================================================================================================== R-API-02
def api_checked() -> ScopeConfig:
    return checked(["spec_drift"], "api-orders")


def spec(operations: list[Any], *, count: int | None = None, target: str = "orders-api") -> ObservationView:
    parsed: dict[str, Any] = {"openapi": "3.0.3", "operation_count": len(operations) if count is None else count}
    if operations is not None:
        parsed["operations"] = operations
    payload = {
        "api_target_id": target, "host": "api.staging.example.invalid", "port": 443, "scheme": "https",
        "path": "/openapi.json", "http_status": 200, "headers": {},
        "body": {
            "size_bytes": 10, "truncated": False, "content_type": "application/json",
            "artifact_sha256": FINGERPRINT, "parsed": parsed,
        },
    }  # fmt: skip
    return view("api_spec", payload, target=("api.staging.example.invalid", "https", 443))


# the api-orders scope lists: GET /projects, GET /projects/{project_id}, HEAD /health, under base path /v1
COVERED = ["GET /projects", "GET /projects/{project_id}", "GET /health"]


def drift(*operations: str, count: int | None = None) -> list[RuleDraft]:
    return evaluate(spec(list(operations), count=count), config=api_checked(), rule="R-API-02")


def test_the_drift_rule_is_silent_unless_the_scope_switches_it_on() -> None:
    extra = spec([*COVERED, "GET /internal/debug"])
    assert evaluate(extra, config=scope_for_api(), rule="R-API-02") == []  # no checks block at all
    assert only(evaluate(extra, config=api_checked(), rule="R-API-02"))  # the same observation with the check on


def scope_for_api() -> ScopeConfig:
    return parse_scope(dump(scope_dict("api-orders")), now=NOW).config


def test_a_documented_read_the_scope_does_not_list_is_an_unassessed_inventory_draft() -> None:
    draft = only(drift(*COVERED, "GET /internal/debug"))
    assert draft.vulnerability_class is VulnClass.API_INVENTORY_DRIFT and draft.rule_id == "R-API-02"
    assert draft.title == "API description and scope disagree for orders-api"
    assert draft.conditions == ("1 read operation is documented in the API description but not listed in the scope.",)
    assert draft.facts == ("documented, not in scope: GET /internal/debug",)
    assert (draft.assessment, draft.severity, draft.confidence) == (Assessment.NOT_ASSESSED, SeverityValue.INFO, 0.5)
    assert list(draft.cwe_candidates) == [] and [s.kind for s in draft.specs] == [
        "read_recorded_observation",
        "owner_confirmation",
    ]


def test_a_documented_change_of_state_is_not_called_drift_because_the_scope_never_reads_it() -> None:
    assert drift(*COVERED, "DELETE /projects/{project_id}", "POST /projects") == []


def test_a_documented_head_the_scope_does_not_list_is_drift_too() -> None:
    draft = only(drift(*COVERED, "HEAD /only-head"))
    assert draft.facts == ("documented, not in scope: HEAD /only-head",)


def test_head_and_get_on_one_path_are_the_same_endpoint_and_a_head_only_documentation_counts() -> None:
    assert drift("GET /projects", "GET /projects/{project_id}", "HEAD /health") == []


@pytest.mark.parametrize(
    "documented",
    ["GET /projects/{id}", "GET /projects/{project_id}", "GET /projects/{}", "GET /projects/", "GET /v1/projects"],
)
def test_the_same_place_written_another_way_is_not_drift(documented: str) -> None:
    assert drift(documented, "GET /projects/{project_id}", "GET /projects", "GET /health") == []


def test_a_listed_endpoint_missing_from_a_complete_description_is_reported() -> None:
    draft = only(drift("GET /projects", "GET /projects/{project_id}"))  # /health is listed in the scope, not documented
    assert draft.conditions == ("1 listed endpoint is missing from the API description.",)
    assert draft.facts == ()


def test_both_differences_give_one_draft_with_both_conditions_in_the_plural_where_needed() -> None:
    draft = only(drift("GET /projects", "GET /a", "GET /b", "GET /c"))
    assert draft.conditions == (
        "3 read operations are documented in the API description but not listed in the scope.",
        "2 listed endpoints are missing from the API description.",
    )
    assert draft.facts == (
        "documented, not in scope: GET /a",
        "documented, not in scope: GET /b",
        "documented, not in scope: GET /c",
    )


def test_an_incomplete_listing_never_claims_an_endpoint_is_undocumented() -> None:
    assert drift("GET /projects", "GET /projects/{project_id}", count=40) == []  # the list was cut: say nothing
    draft = only(drift("GET /projects", "GET /extra", count=40))
    assert draft.conditions == ("1 read operation is documented in the API description but not listed in the scope.",)


def test_no_difference_means_no_draft_and_a_spec_without_operations_or_for_another_target_is_ignored() -> None:
    assert drift(*COVERED) == []
    assert evaluate(spec([*COVERED, "GET /x"], target="other-api"), config=api_checked(), rule="R-API-02") == []
    assert only(drift(*COVERED, "GET /x"))  # control: the same list for the right target does draft
    bare = view(
        "api_spec",
        {
            "api_target_id": "orders-api", "host": "api.staging.example.invalid", "port": 443, "scheme": "https",
            "path": "/openapi.json", "http_status": 200, "headers": {},
            "body": {"size_bytes": 1, "truncated": False, "content_type": None, "artifact_sha256": FINGERPRINT, "parsed": {"openapi": "3.0.3"}},
        },
        target=("api.staging.example.invalid", "https", 443),
    )  # fmt: skip
    assert (
        evaluate(bare, config=api_checked(), rule="R-API-02") == []
    )  # an observation stored before operations were listed
    nobody = view(
        "api_spec",
        {
            "api_target_id": "orders-api", "host": "api.staging.example.invalid", "port": 443, "scheme": "https",
            "path": "/openapi.json", "http_status": 200, "headers": {}, "body": None,
        },
        target=("api.staging.example.invalid", "https", 443),
    )  # fmt: skip
    assert evaluate(nobody, config=api_checked(), rule="R-API-02") == []


def test_an_operation_that_is_not_a_plain_path_is_not_quoted_but_still_counts() -> None:
    draft = only(drift(*COVERED, "GET /ok", 'GET /<script>"'))  # type: ignore[arg-type]
    assert draft.facts == ("documented, not in scope: GET /ok",)
    assert draft.conditions[0].startswith(
        "1 read operation is documented"
    )  # the odd one never matched the strict shape


def test_no_more_than_six_documented_paths_are_quoted() -> None:
    draft = only(drift(*COVERED, *[f"GET /x{i}" for i in range(10)]))
    assert draft.conditions[0].startswith("10 read operations are documented") and len(draft.facts) == 6
