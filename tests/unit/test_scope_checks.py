"""Stage 2a: the `checks` block of a scope: off unless written, in the hash only when present, refused when it has nothing to read."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import normalised, parse_scope
from tests.support import NOW, SCOPE_FILES, dump, scope_dict

pytestmark = pytest.mark.milestone("M7")


def refused(data: dict[str, Any], code: ErrorCode) -> ScopeError:
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert caught.value.code is code, f"{caught.value.code}: {caught.value}"
    return caught.value


def with_checks(name: str = "healthy", **checks: Any) -> dict[str, Any]:
    data = scope_dict(name)
    data["checks"] = checks
    return data


def test_a_scope_without_a_checks_block_is_unchanged_and_hashes_as_before() -> None:
    for name in ("healthy", "misconfigured", "poisoned", "ai-support-bot", "api-orders"):
        loaded = parse_scope(SCOPE_FILES[name].read_text(encoding="utf-8"), now=NOW)
        assert loaded.config.checks is None and "checks" not in normalised(loaded.config)


def test_a_checks_block_joins_the_hash_in_the_order_given() -> None:
    plain = parse_scope(dump(scope_dict("healthy")), now=NOW)
    both = parse_scope(dump(with_checks(passive=["cookie_flags", "header_quality"])), now=NOW)
    swapped = parse_scope(dump(with_checks(passive=["header_quality", "cookie_flags"])), now=NOW)
    assert normalised(both.config)["checks"] == {"passive": ["cookie_flags", "header_quality"]}
    assert len({plain.sha256, both.sha256, swapped.sha256}) == 3  # a different list is a different scope


@pytest.mark.parametrize("check", ["cookie_flags", "header_quality"])
def test_each_web_check_is_accepted_alone(check: str) -> None:
    assert parse_scope(dump(with_checks(passive=[check])), now=NOW).config.checks.passive == [check]  # type: ignore[union-attr]


def test_spec_drift_is_accepted_with_an_api_target_that_allows_api_spec() -> None:
    loaded = parse_scope(dump(with_checks("api-orders", passive=["spec_drift"])), now=NOW)
    assert loaded.config.checks.passive == ["spec_drift"]  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("block", "needle"),
    [
        ({"passive": []}, "passive"),
        ({"passive": ["cookie_flags", "cookie_flags"]}, "must not repeat"),
        ({"passive": ["sql_injection"]}, "passive"),
        ({"passive": ["cookie_flags", "header_quality", "spec_drift", "cookie_flags"]}, "passive"),
        ({"passive": "cookie_flags"}, "passive"),
        ({"passive": ["cookie_flags"], "active": ["x"]}, "active"),
        ({}, "passive"),
    ],
)
def test_a_malformed_checks_block_is_refused(block: dict[str, Any], needle: str) -> None:
    data = scope_dict("healthy")
    data["checks"] = block
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert caught.value.code in (ErrorCode.SCOPE_003, ErrorCode.SCOPE_007) and needle in str(caught.value)


def test_a_web_check_needs_http_metadata_to_be_allowed() -> None:
    data = with_checks(passive=["cookie_flags"])
    data["allowed_operations"] = ["dns_metadata", "tls_metadata"]
    data["allowed_targets"][0]["allowed_paths"] = ["/robots.txt"]
    assert "http_metadata is not allowed" in str(refused(data, ErrorCode.SCOPE_009))
    data["checks"] = {"passive": ["header_quality"]}
    assert "header_quality reads HTTP answers" in str(refused(data, ErrorCode.SCOPE_009))


def test_spec_drift_needs_an_api_target_that_allows_api_spec() -> None:
    assert "spec_drift needs an API target" in str(refused(with_checks(passive=["spec_drift"]), ErrorCode.SCOPE_009))
    data = with_checks("api-orders", passive=["spec_drift"])
    data["api_targets"][0]["operations"] = ["api_read", "api_options"]
    data["api_targets"][0]["spec_paths"] = []
    data["allowed_operations"] = ["api_read", "api_options"]
    assert "spec_drift needs an API target" in str(refused(data, ErrorCode.SCOPE_009))


def test_a_live_scope_may_carry_checks_and_they_still_join_the_hash() -> None:
    from tests.unit.test_scope_live import live_dict  # noqa: PLC0415

    data = live_dict()
    plain = parse_scope(dump(data), now=NOW)
    data = copy.deepcopy(data)
    data["checks"] = {"passive": ["header_quality"]}
    checked = parse_scope(dump(data), now=NOW)
    assert checked.config.mode == "live" and checked.sha256 != plain.sha256
