"""The scope schema, its limits, expiry, hash and plan (docs/scope-format.md, D-E04 to D-E06, D-E22, D-E23)."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import PlannedOperation, load_scope, parse_scope
from tests.support import NOW, PACKS, SCOPE_FILES, dump, scope_dict, scope_text

pytestmark = pytest.mark.milestone("M1")


def refused(data: dict[str, Any], code: ErrorCode) -> ScopeError:
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert caught.value.code is code, f"{caught.value.code}: {caught.value}"
    return caught.value


def accepted(data: dict[str, Any]) -> Any:
    return parse_scope(dump(data), now=NOW)


# ---------------------------------------------------------------- the committed fixtures ----
@pytest.mark.parametrize("name", PACKS)
def test_every_committed_scope_fixture_validates(name: str) -> None:
    loaded = load_scope(SCOPE_FILES[name], now=NOW)
    assert loaded.config.mode == "offline" and loaded.config.follow_redirects is False


def test_the_healthy_plan_is_dns_tls_then_each_path_in_file_order() -> None:
    plan = parse_scope(scope_text("healthy"), now=NOW).planned
    host = "lab.example.invalid"
    assert plan == (
        PlannedOperation("dns_metadata", host, "https", 443, None),
        PlannedOperation("tls_metadata", host, "https", 443, None),
        PlannedOperation("http_metadata", host, "https", 443, "/.well-known/security.txt"),
        PlannedOperation("http_metadata", host, "https", 443, "/openapi.json"),
        PlannedOperation("http_metadata", host, "https", 443, "/robots.txt"),
    )


def test_the_misconfigured_plan_has_six_operations_including_the_root_path() -> None:
    plan = parse_scope(scope_text("misconfigured"), now=NOW).planned
    assert [op.kind for op in plan].count("http_metadata") == 4 and len(plan) == 6
    assert plan[2].path == "/"


def test_dns_is_planned_once_per_host_at_its_first_entry() -> None:
    data = scope_dict()
    data["allowed_targets"].append(
        {"host": "LAB.example.invalid.", "schemes": ["https"], "ports": [8443], "allowed_paths": ["/x"]}
    )
    plan = accepted(data).planned
    assert [op.kind for op in plan].count("dns_metadata") == 1
    assert [op.port for op in plan if op.kind == "dns_metadata"] == [443]
    assert [op.port for op in plan if op.kind == "tls_metadata"] == [443, 8443]


def test_an_http_only_entry_plans_no_tls_and_a_no_path_entry_plans_no_http() -> None:
    data = scope_dict()
    data["allowed_targets"] = [
        {"host": "a.example.invalid", "schemes": ["http"], "ports": [8080], "allowed_paths": ["/h"]},
        {"host": "b.example.invalid", "schemes": ["https"], "ports": [443]},
    ]
    kinds = [(op.host, op.kind) for op in accepted(data).planned]
    assert kinds == [
        ("a.example.invalid", "dns_metadata"),
        ("a.example.invalid", "http_metadata"),
        ("b.example.invalid", "dns_metadata"),
        ("b.example.invalid", "tls_metadata"),
    ]


def test_several_ports_expand_to_one_operation_each() -> None:
    data = scope_dict()
    data["allowed_targets"][0]["ports"] = [443, 8443]
    plan = accepted(data).planned
    assert sum(op.kind == "tls_metadata" for op in plan) == 2
    assert sum(op.kind == "http_metadata" for op in plan) == 6


# ---------------------------------------------------------------------------- required fields ----
@pytest.mark.parametrize(
    "field",
    ["engagement_id", "owner_approval_ref", "expires_at", "allowed_targets", "allowed_operations", "max_requests"],
)
def test_each_required_field_is_required(field: str) -> None:
    data = scope_dict()
    del data[field]
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize(
    ("field", "default"),
    [
        ("mode", "offline"),
        ("max_parallelism", 2),
        ("per_request_timeout_seconds", 5),
        ("max_response_bytes", 100000),
        ("follow_redirects", False),
    ],
)
def test_defaulted_fields_may_be_omitted_and_take_the_safe_default(field: str, default: Any) -> None:
    data = scope_dict()
    data.pop(field, None)
    assert getattr(accepted(data).config, field) == default


@pytest.mark.parametrize("where", ["top", "target"])
def test_unknown_keys_are_refused_at_every_level(where: str) -> None:
    data = scope_dict()
    (data if where == "top" else data["allowed_targets"][0])["extra_field"] = 1
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_requests", "12"),
        ("max_requests", 12.0),
        ("max_requests", True),
        ("mode", 1),
        ("follow_redirects", "false"),
    ],
)
def test_values_of_the_wrong_type_are_refused_not_coerced(field: str, value: Any) -> None:
    data = scope_dict()
    data[field] = value
    refused(data, ErrorCode.SCOPE_003)


def test_a_null_port_list_is_refused() -> None:
    data = scope_dict()
    data["allowed_targets"][0]["ports"] = None
    refused(data, ErrorCode.SCOPE_003)


# ------------------------------------------------------------------------------------ limits ----
@pytest.mark.parametrize(
    ("field", "low_bad", "low_ok", "high_ok", "high_bad"),
    [
        ("max_requests", 0, 1, 500, 501),
        ("max_parallelism", 0, 1, 4, 5),
        ("per_request_timeout_seconds", 0, 1, 30, 31),
        ("max_response_bytes", 1023, 1024, 1_000_000, 1_000_001),
    ],
)
def test_numeric_limits_are_inclusive_at_both_ends(
    field: str, low_bad: int, low_ok: int, high_ok: int, high_bad: int
) -> None:
    for ok in (low_ok, high_ok):
        data = scope_dict()
        data[field] = ok
        assert getattr(accepted(data).config, field) == ok
    for bad in (low_bad, high_bad, -1):
        data = scope_dict()
        data[field] = bad
        refused(data, ErrorCode.SCOPE_007)


def test_target_count_port_count_and_path_count_are_capped() -> None:
    data = scope_dict()
    data["allowed_targets"] = [
        {"host": f"h{i}.example.invalid", "schemes": ["https"], "ports": [443], "allowed_paths": ["/x"]}
        for i in range(20)
    ]
    assert len(accepted(data).config.allowed_targets) == 20
    data["allowed_targets"].append({"host": "h20.example.invalid", "schemes": ["https"], "ports": [443]})
    refused(data, ErrorCode.SCOPE_007)

    data = scope_dict()
    data["allowed_targets"][0]["ports"] = list(range(443, 443 + 8))
    assert len(accepted(data).config.allowed_targets[0].ports) == 8
    data["allowed_targets"][0]["ports"] = list(range(443, 443 + 9))
    refused(data, ErrorCode.SCOPE_007)

    data = scope_dict()
    data["allowed_targets"][0]["allowed_paths"] = [f"/p{i}" for i in range(20)]
    assert len(accepted(data).config.allowed_targets[0].allowed_paths) == 20
    data["allowed_targets"][0]["allowed_paths"] = [f"/p{i}" for i in range(21)]
    refused(data, ErrorCode.SCOPE_007)


def test_an_empty_target_list_is_refused() -> None:
    data = scope_dict()
    data["allowed_targets"] = []
    refused(data, ErrorCode.SCOPE_007)


@pytest.mark.parametrize("port", [0, -1, 65536, 99999])
def test_ports_outside_1_to_65535_are_refused(port: int) -> None:
    data = scope_dict()
    data["allowed_targets"][0]["ports"] = [port]
    refused(data, ErrorCode.SCOPE_006)


@pytest.mark.parametrize("port", [1, 65535])
def test_the_extreme_legal_ports_are_accepted(port: int) -> None:
    data = scope_dict()
    data["allowed_targets"][0]["ports"] = [port]
    accepted(data)


@pytest.mark.parametrize("schemes", [[], ["ftp"], ["HTTPS"], ["https", "https"], ["file"], ["https://"]])
def test_bad_scheme_lists_are_refused(schemes: list[str]) -> None:
    data = scope_dict()
    data["allowed_targets"][0]["schemes"] = schemes
    refused(data, ErrorCode.SCOPE_006)


def test_duplicate_ports_and_duplicate_paths_are_refused() -> None:
    data = scope_dict()
    data["allowed_targets"][0]["ports"] = [443, 443]
    refused(data, ErrorCode.SCOPE_006)
    data = scope_dict()
    data["allowed_targets"][0]["allowed_paths"] = ["/a", "/a"]
    refused(data, ErrorCode.SCOPE_006)


def test_one_entry_may_not_have_several_schemes_and_several_ports() -> None:
    data = scope_dict()
    data["allowed_targets"][0].update(schemes=["http", "https"], ports=[80, 443])
    refused(data, ErrorCode.SCOPE_006)
    for schemes, ports in ((["http", "https"], [8080]), (["https"], [443, 8443])):
        data = scope_dict()
        data["allowed_targets"][0].update(schemes=schemes, ports=ports)
        accepted(data)


def test_a_bad_host_in_an_entry_is_reported_with_its_path() -> None:
    data = scope_dict()
    data["allowed_targets"][0]["host"] = "*.example.invalid"
    error = refused(data, ErrorCode.SCOPE_005)
    assert error.path == "allowed_targets[0].host"


def test_two_entries_for_the_same_scheme_host_and_port_are_refused_not_merged() -> None:
    data = scope_dict()
    data["allowed_targets"].append(
        {"host": "LAB.example.invalid.", "schemes": ["https"], "ports": [443], "allowed_paths": ["/x"]}
    )
    refused(data, ErrorCode.SCOPE_005)


def test_follow_redirects_must_be_false() -> None:
    data = scope_dict()
    data["follow_redirects"] = True
    refused(data, ErrorCode.SCOPE_008)


def test_an_empty_operation_list_is_a_limit_error() -> None:
    data = scope_dict()
    data["allowed_operations"] = []
    refused(data, ErrorCode.SCOPE_007)


@pytest.mark.parametrize("operations", [["dns_metadata", "dns_metadata"], ["port_scan"], ["http_post"]])
def test_operations_must_be_known_and_unique(operations: list[str]) -> None:
    data = scope_dict()
    data["allowed_operations"] = operations
    refused(data, ErrorCode.SCOPE_003)


def test_an_operation_no_target_can_use_is_refused() -> None:
    data = scope_dict()
    data["allowed_targets"][0]["schemes"] = ["http"]
    data["allowed_targets"][0]["ports"] = [80]
    refused(data, ErrorCode.SCOPE_009)  # tls_metadata is allowed but nothing is https
    data = scope_dict()
    data["allowed_targets"][0]["allowed_paths"] = []
    refused(data, ErrorCode.SCOPE_009)  # http_metadata is allowed but no entry has a path


@pytest.mark.parametrize("value", ["ab", "A" * 3, "-abc", "a b c", "a" * 65, "abc/def", ""])
def test_engagement_ids_follow_the_pattern(value: str) -> None:
    data = scope_dict()
    data["engagement_id"] = value
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize("value", ["ab", "a" * 129, "has space", "semi;colon", ""])
def test_approval_references_follow_the_pattern(value: str) -> None:
    data = scope_dict()
    data["owner_approval_ref"] = value
    refused(data, ErrorCode.SCOPE_003)


def test_live_mode_parses_with_its_authorization_and_is_refused_without() -> None:
    from tests.unit.test_scope_live import live_dict  # noqa: PLC0415

    assert accepted(live_dict()).config.mode == "live"
    data = scope_dict()
    data["mode"] = "live"
    with pytest.raises(ScopeError):
        accepted(data)


def test_an_unknown_mode_is_refused() -> None:
    data = scope_dict()
    data["mode"] = "online"
    refused(data, ErrorCode.SCOPE_003)


# ------------------------------------------------------------------------------------ expiry ----
def test_a_scope_is_valid_only_while_now_is_before_expiry() -> None:
    data = scope_dict()
    data["expires_at"] = "2026-11-20T12:00:01Z"
    accepted(data)
    data["expires_at"] = "2026-11-20T12:00:00Z"  # equal to now: expired
    refused(data, ErrorCode.SCOPE_004)
    data["expires_at"] = "2020-01-01T00:00:00Z"
    refused(data, ErrorCode.SCOPE_004)


def test_expiry_may_be_at_most_366_days_ahead() -> None:
    data = scope_dict()
    data["expires_at"] = (NOW + timedelta(days=366)).strftime("%Y-%m-%dT%H:%M:%SZ")
    accepted(data)
    data["expires_at"] = (NOW + timedelta(days=366, seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    refused(data, ErrorCode.SCOPE_004)


@pytest.mark.parametrize(
    "value", ["2026-12-31", "2026-12-31T23:59:00", "tomorrow", "", "2026-13-40T00:00:00Z", 20261231]
)
def test_expiry_must_be_a_complete_utc_aware_timestamp(value: Any) -> None:
    data = scope_dict()
    data["expires_at"] = value
    refused(data, ErrorCode.SCOPE_004)


def test_expiry_with_an_offset_is_converted_to_utc() -> None:
    data = scope_dict()
    data["expires_at"] = "2026-12-31T23:59:00+02:00"
    assert accepted(data).config.expires_at.isoformat() == "2026-12-31T21:59:00+00:00"


# -------------------------------------------------------------------------------------- hash ----
def independent_hash(normalised: dict[str, Any]) -> str:
    text = json.dumps(normalised, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


HEALTHY_NORMALISED: dict[str, Any] = {
    "engagement_id": "lab-healthy-001",
    "owner_approval_ref": "local-lab-consent",
    "expires_at": "2026-12-31T23:59:00Z",
    "mode": "offline",
    "allowed_targets": [
        {
            "host": "lab.example.invalid",
            "schemes": ["https"],
            "ports": [443],
            "allowed_paths": ["/.well-known/security.txt", "/openapi.json", "/robots.txt"],
        }
    ],
    "allowed_operations": ["dns_metadata", "tls_metadata", "http_metadata"],
    "max_requests": 12,
    "max_parallelism": 2,
    "per_request_timeout_seconds": 5,
    "max_response_bytes": 100000,
    "follow_redirects": False,
}


def test_the_scope_hash_is_the_sha256_of_the_canonical_json_of_the_normalised_scope() -> None:
    loaded = parse_scope(scope_text("healthy"), now=NOW)
    assert loaded.sha256 == independent_hash(HEALTHY_NORMALISED)
    assert json.loads(loaded.canonical_json) == HEALTHY_NORMALISED
    assert loaded.canonical_json == json.dumps(HEALTHY_NORMALISED, sort_keys=True, separators=(",", ":"))


def test_formatting_case_defaults_and_offsets_do_not_change_the_hash() -> None:
    baseline = parse_scope(scope_text("healthy"), now=NOW).sha256
    reordered = dict(reversed(list(scope_dict().items())))
    assert parse_scope(dump(reordered), now=NOW).sha256 == baseline
    data = scope_dict()
    data["allowed_targets"][0]["host"] = "LAB.EXAMPLE.INVALID."
    data["expires_at"] = "2026-12-31T23:59:00+00:00"
    data["mode"] = "offline"  # an explicit default
    assert parse_scope(dump(data), now=NOW).sha256 == baseline
    assert parse_scope(scope_text("healthy") + "\n\n# a comment\n", now=NOW).sha256 == baseline


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["allowed_targets"][0]["allowed_paths"].append("/extra"),
        lambda d: d.update(max_requests=11),
        lambda d: d["allowed_targets"][0].update(ports=[8443]),
        lambda d: d["allowed_targets"][0].update(host="other.example.invalid"),
        lambda d: d.update(owner_approval_ref="someone-else"),
        lambda d: d.update(allowed_operations=["dns_metadata", "http_metadata"]),
        lambda d: d.update(expires_at="2026-12-30T23:59:00Z"),
        lambda d: d.update(
            mode="live", authorization={"engagement": "ACME-2026-114", "not_after": "2026-12-04T23:59:59Z"}
        ),
        lambda d: d["allowed_targets"][0]["allowed_paths"].reverse(),
    ],
)
def test_anything_that_changes_what_the_scope_allows_changes_the_hash(change: Any) -> None:
    baseline = parse_scope(scope_text("healthy"), now=NOW).sha256
    data = scope_dict()
    change(data)
    assert parse_scope(dump(data), now=NOW).sha256 != baseline


def test_the_hash_does_not_depend_on_the_clock() -> None:
    later = NOW + timedelta(days=30)
    assert parse_scope(scope_text(), now=NOW).sha256 == parse_scope(scope_text(), now=later).sha256


# ------------------------------------------------------------------------------- load_scope ----
def test_load_scope_reads_a_file_and_refuses_non_utf8_oversize_and_missing(tmp_path: Path) -> None:
    good = tmp_path / "s.yaml"
    good.write_text(scope_text(), encoding="utf-8")
    assert load_scope(good, now=NOW).config.engagement_id == "lab-healthy-001"
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(scope_text().encode() + b"\xff\xfe")
    big = tmp_path / "big.yaml"
    big.write_bytes(b"# " + b"a" * 70_000)
    for path in (bad, big, tmp_path / "missing.yaml"):
        with pytest.raises(ScopeError) as caught:
            load_scope(path, now=NOW)
        assert caught.value.code is ErrorCode.SCOPE_001


def test_load_scope_refuses_a_directory_and_a_fifo(tmp_path: Path) -> None:
    with pytest.raises(ScopeError):
        load_scope(tmp_path, now=NOW)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)  # reading a FIFO would block forever
    with pytest.raises(ScopeError):
        load_scope(fifo, now=NOW)


def test_dns_is_planned_at_the_first_scheme_and_port_of_the_first_entry() -> None:
    data = scope_dict()
    data["allowed_targets"][0].update(schemes=["http", "https"], ports=[8080], allowed_paths=["/h"])
    dns = next(op for op in accepted(data).planned if op.kind == "dns_metadata")
    assert (dns.scheme, dns.port) == ("http", 8080)
    data["allowed_targets"][0].update(schemes=["https"], ports=[8443, 443])
    dns = next(op for op in accepted(data).planned if op.kind == "dns_metadata")
    assert (dns.scheme, dns.port) == ("https", 8443)


@pytest.mark.parametrize(
    ("operations", "kinds"),
    [
        (["dns_metadata"], {"dns_metadata"}),
        (["tls_metadata"], {"tls_metadata"}),
        (["http_metadata"], {"http_metadata"}),
        (["dns_metadata", "http_metadata"], {"dns_metadata", "http_metadata"}),
        (["tls_metadata", "http_metadata"], {"tls_metadata", "http_metadata"}),
    ],
)
def test_the_plan_contains_only_the_allowed_operations(operations: list[str], kinds: set[str]) -> None:
    data = scope_dict()
    data["allowed_operations"] = operations
    assert {op.kind for op in accepted(data).planned} == kinds
