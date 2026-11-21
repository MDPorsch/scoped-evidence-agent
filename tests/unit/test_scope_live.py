"""M6, D-E41 and D-E45: a live scope declares an authorization and, optionally, its egress. Every rule has a refusal and its code."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import normalised, parse_scope
from tests.support import NOW, SCOPE_FILES, dump, scope_dict

pytestmark = pytest.mark.milestone("M6")

AUTH = {"engagement": "ACME-2026-114", "not_before": "2026-11-20T00:00:00Z", "not_after": "2026-12-04T23:59:59Z"}


def live_dict(name: str = "healthy") -> dict[str, Any]:
    data = scope_dict(name)
    data["mode"] = "live"
    data["authorization"] = copy.deepcopy(AUTH)
    return data


def refused(data: dict[str, Any], code: ErrorCode) -> ScopeError:
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert caught.value.code is code, f"{caught.value.code}: {caught.value}"
    return caught.value


def accepted(data: dict[str, Any]) -> Any:
    return parse_scope(dump(data), now=NOW)


def test_a_live_scope_with_an_authorization_is_valid() -> None:
    loaded = accepted(live_dict())
    assert loaded.config.mode == "live" and loaded.config.authorization.engagement == "ACME-2026-114"
    assert loaded.config.egress is None


def test_the_offline_fixtures_stay_offline_and_hash_as_before() -> None:
    for path in SCOPE_FILES.values():
        loaded = parse_scope(path.read_text(encoding="utf-8"), now=NOW)
        assert loaded.config.mode == "offline" and "authorization" not in normalised(loaded.config)


def test_live_needs_an_authorization_block() -> None:
    data = live_dict()
    del data["authorization"]
    assert "authorization block" in str(refused(data, ErrorCode.SCOPE_009))


def test_an_offline_scope_may_not_carry_the_live_blocks() -> None:
    for key, value in (("authorization", AUTH), ("egress", {"max_requests_per_second": 2})):
        data = scope_dict()
        data[key] = value
        assert "valid only with mode live" in str(refused(data, ErrorCode.SCOPE_009))


def test_the_authorization_and_egress_join_the_hash_only_when_present() -> None:
    base = accepted(live_dict()).sha256
    data = live_dict()
    data["authorization"]["engagement"] = "ACME-2026-115"
    assert accepted(data).sha256 != base
    data = live_dict()
    data["egress"] = {"allowed_networks": ["10.20.0.0/16"]}
    assert accepted(data).sha256 != base
    data = live_dict()
    data["egress"] = {"max_requests_per_second": 5}
    assert accepted(data).sha256 != base
    data = live_dict()
    data["authorization"]["not_before"] = "2026-11-21T00:00:00Z"
    assert accepted(data).sha256 != base
    assert accepted(live_dict()).sha256 == base


@pytest.mark.parametrize("engagement", ["", "ab", "a b c", "x" * 129, "bad<char>", "a\nb"])
def test_the_engagement_reference_is_three_to_128_plain_characters(engagement: str) -> None:
    data = live_dict()
    data["authorization"]["engagement"] = engagement
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize("field", ["not_before", "not_after"])
@pytest.mark.parametrize("value", ["2026-12-04", "2026-12-04 23:59:59", "tomorrow", 5, True, "2026-12-04T23:59:59"])
def test_a_window_time_is_a_quoted_utc_timestamp(field: str, value: Any) -> None:
    data = live_dict()
    data["authorization"][field] = value
    refused(data, ErrorCode.SCOPE_004)


def test_not_after_is_required_and_not_before_is_optional() -> None:
    data = live_dict()
    del data["authorization"]["not_after"]
    refused(data, ErrorCode.SCOPE_003)
    data = live_dict()
    del data["authorization"]["not_before"]
    assert accepted(data).config.authorization.not_before is None


def test_the_window_must_run_forwards_and_be_at_most_366_days() -> None:
    data = live_dict()
    data["authorization"].update(not_before="2026-12-05T00:00:00Z", not_after="2026-12-04T23:59:59Z")
    refused(data, ErrorCode.SCOPE_004)
    data["authorization"].update(not_before="2026-12-04T23:59:59Z", not_after="2026-12-04T23:59:59Z")
    refused(data, ErrorCode.SCOPE_004)
    data["authorization"].update(not_before="2025-12-04T00:00:00Z", not_after="2026-12-06T00:00:00Z")
    refused(data, ErrorCode.SCOPE_004)  # 367 days
    data["authorization"].update(not_before="2025-12-04T00:00:00Z", not_after="2026-12-05T00:00:00Z")
    assert accepted(data)  # exactly 366 days


def test_unknown_keys_are_refused_in_both_blocks() -> None:
    data = live_dict()
    data["authorization"]["verified"] = True
    refused(data, ErrorCode.SCOPE_003)
    data = live_dict()
    data["egress"] = {"proxy": "http://proxy.example.invalid"}
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize("rate", [0, 11, -1, 2.5, "2", True])
def test_the_rate_is_one_to_ten_requests_a_second(rate: Any) -> None:
    data = live_dict()
    data["egress"] = {"max_requests_per_second": rate}
    with pytest.raises(ScopeError):
        parse_scope(dump(data), now=NOW)


def test_the_rate_defaults_to_two_and_the_edges_are_accepted() -> None:
    assert accepted(live_dict()).config.egress is None
    for rate in (1, 10):
        data = live_dict()
        data["egress"] = {"max_requests_per_second": rate}
        assert accepted(data).config.egress.max_requests_per_second == rate
    data = live_dict()
    data["egress"] = {}
    assert accepted(data).config.egress.max_requests_per_second == 2


@pytest.mark.parametrize(
    "networks",
    [
        ["10.20.0.1"],
        ["169.254.0.0/16"],
        ["0.0.0.0/0"],
        ["fe80::/10"],
        ["not a network"],
        [f"10.{i}.0.0/16" for i in range(33)],
    ],
)
def test_the_allowed_networks_are_validated_like_the_address_policy(networks: list[str]) -> None:
    data = live_dict()
    data["egress"] = {"allowed_networks": networks}
    with pytest.raises(ScopeError):
        parse_scope(dump(data), now=NOW)


def test_good_networks_are_kept_in_order() -> None:
    data = live_dict()
    data["egress"] = {"allowed_networks": ["10.20.0.0/16", "fd00::/8"]}
    assert accepted(data).config.egress.allowed_networks == ["10.20.0.0/16", "fd00::/8"]


def test_live_mode_names_at_most_ten_hosts() -> None:
    data = live_dict()
    data["allowed_targets"] = [
        {"host": f"h{i}.example.invalid", "schemes": ["https"], "ports": [443], "allowed_paths": ["/"]}
        for i in range(10)
    ]
    assert accepted(data)
    data["allowed_targets"].append(
        {"host": "h10.example.invalid", "schemes": ["https"], "ports": [443], "allowed_paths": ["/"]}
    )
    assert "at most 10 hosts" in str(refused(data, ErrorCode.SCOPE_007))


def test_the_same_host_in_a_web_ai_and_api_target_counts_once() -> None:
    data = live_dict("api-orders")
    data["allowed_targets"] = [
        {"host": "api.staging.example.invalid", "schemes": ["https"], "ports": [443], "allowed_paths": ["/"]}
    ]
    data["allowed_operations"] = ["http_metadata", "api_spec", "api_read", "api_options"]
    assert accepted(data)


def test_ai_probe_is_not_available_in_live_mode_in_this_version() -> None:
    data = live_dict("ai-support-bot")
    assert "ai_probe is not available in live mode" in str(refused(data, ErrorCode.SCOPE_011))
    data["ai_targets"][0].update(operations=["ai_metadata"], probe_path=None, probe_sets=[], test_categories=[])
    data["allowed_operations"] = ["ai_metadata"]
    assert accepted(data).config.ai_targets[0].operations == ["ai_metadata"]  # metadata alone is allowed
