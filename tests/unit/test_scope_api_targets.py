"""D-E48 to D-E55 (docs/api-targets.md): scopes for testing APIs. Every rule has a refusal test and its code."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import PlannedOperation, normalised, parse_scope, resolve_path
from tests.support import API_PACK, NOW, SCOPE_FILES, dump, scope_dict

pytestmark = pytest.mark.milestone("M5")

HOST = "api.staging.example.invalid"
ORIGIN = "https://untrusted.example.invalid"


def api_dict() -> dict[str, Any]:
    return scope_dict(API_PACK)


def target(data: dict[str, Any]) -> dict[str, Any]:
    return data["api_targets"][0]  # type: ignore[no-any-return]


def endpoint(data: dict[str, Any], index: int = 0) -> dict[str, Any]:
    return target(data)["endpoints"][index]  # type: ignore[no-any-return]


def refused(data: dict[str, Any], code: ErrorCode) -> ScopeError:
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert caught.value.code is code, f"{caught.value.code}: {caught.value}"
    return caught.value


def accepted(data: dict[str, Any]) -> Any:
    return parse_scope(dump(data), now=NOW)


def wide(data: dict[str, Any]) -> None:
    """Room in both request limits, so a test can vary one other field at a time."""
    data["max_requests"] = 500
    target(data)["limits"]["max_api_requests"] = 400


# ------------------------------------------------------------------------------------------- the fixture ----
def test_the_fixture_validates_and_is_an_api_only_scope() -> None:
    loaded = parse_scope(SCOPE_FILES[API_PACK].read_text(encoding="utf-8"), now=NOW)
    assert loaded.config.allowed_targets == [] and loaded.config.ai_targets == []
    assert [t.id for t in loaded.config.api_targets] == ["orders-api"] and loaded.config.mode == "offline"


def test_the_plan_is_the_spec_then_each_endpoint_by_value_and_principal_then_the_options() -> None:
    plan = parse_scope(SCOPE_FILES[API_PACK].read_text(encoding="utf-8"), now=NOW).planned
    where = (HOST, "https", 443)
    one = (("project_id", "p-1001"),)
    two = (("project_id", "p-2002"),)

    def read(path: str, endpoint_id: str, principal: str, method: str = "GET", params: Any = ()) -> PlannedOperation:
        return PlannedOperation(
            "api_read",
            *where,
            path,
            "orders-api",
            principal=principal,
            endpoint_id=endpoint_id,
            method=method,
            params=params,
        )

    def options(path: str, endpoint_id: str, params: Any = ()) -> PlannedOperation:
        return PlannedOperation(
            "api_options",
            *where,
            path,
            "orders-api",
            principal="anonymous",
            endpoint_id=endpoint_id,
            method="OPTIONS",
            origin=ORIGIN,
            params=params,
        )

    assert plan == (
        PlannedOperation("api_spec", *where, "/openapi.json", "orders-api", principal="anonymous", method="GET"),
        read("/v1/projects", "list-projects", "anonymous"),
        read("/v1/projects", "list-projects", "tenant-a-user"),
        read("/v1/projects/p-1001", "get-project", "tenant-a-user", params=one),
        read("/v1/projects/p-1001", "get-project", "tenant-b-user", params=one),
        read("/v1/projects/p-2002", "get-project", "tenant-a-user", params=two),
        read("/v1/projects/p-2002", "get-project", "tenant-b-user", params=two),
        read("/v1/health", "health", "anonymous", "HEAD"),
        options("/v1/projects", "list-projects"),
        options("/v1/projects/p-1001", "get-project", one),  # the first listed value, so the request is exact
        options("/v1/health", "health"),
    )


def test_an_api_target_plans_no_dns_tls_or_http_operation() -> None:
    kinds = {op.kind for op in parse_scope(SCOPE_FILES[API_PACK].read_text(encoding="utf-8"), now=NOW).planned}
    assert kinds == {"api_spec", "api_read", "api_options"}


def test_a_scope_may_mix_web_ai_and_api_targets_and_the_api_entries_come_last() -> None:
    data = api_dict()
    web = scope_dict("healthy")
    data["allowed_targets"] = web["allowed_targets"]
    data["allowed_operations"] = ["dns_metadata", "api_spec", "api_read", "api_options"]
    kinds = [op.kind for op in accepted(data).planned]
    assert (
        kinds[0] == "dns_metadata"
        and kinds[-1] == "api_options"
        and kinds.index("api_spec") > kinds.index("dns_metadata")
    )


def test_the_same_host_may_be_a_web_and_an_api_target() -> None:
    data = api_dict()
    data["allowed_targets"] = [{"host": HOST, "schemes": ["https"], "ports": [443], "allowed_paths": ["/"]}]
    data["allowed_operations"] = ["http_metadata", "api_spec", "api_read", "api_options"]
    assert accepted(data).planned[0].kind == "http_metadata"


# --------------------------------------------------------------------------------------------- the hash ----
def test_api_targets_join_the_hash_and_a_scope_without_them_keeps_its_hash() -> None:
    plain = scope_dict("healthy")
    assert "api_targets" not in normalised(accepted(plain).config)
    assert "api_targets" in normalised(accepted(api_dict()).config)


def test_every_api_field_is_part_of_the_hash() -> None:
    base = accepted(api_dict()).sha256
    changes: list[Any] = [
        lambda d: target(d).update(base_path="/v2"),
        lambda d: target(d).update(environment="test"),
        lambda d: target(d)["principals"][0].update(label="Someone else"),
        lambda d: endpoint(d).update(expect_auth="unknown"),
        lambda d: endpoint(d, 1)["params"].update(project_id=["p-1001"]),
        lambda d: target(d).update(cors_origins=["https://other.example.invalid"]),
        lambda d: target(d)["limits"].update(max_response_bytes=50_000),
        lambda d: target(d).update(spec_paths=["/swagger.json"]),
    ]
    for change in changes:
        data = api_dict()
        change(data)
        assert accepted(data).sha256 != base


def test_the_order_of_the_params_keys_changes_neither_the_hash_nor_the_plan() -> None:
    first, second = api_dict(), api_dict()
    for data, order in ((first, ("a_id", "b_id")), (second, ("b_id", "a_id"))):
        wide(data)
        endpoint(data, 1).update(
            path="/projects/{a_id}/files/{b_id}", params={k: ["x1", "x2"] if k == "a_id" else ["y1"] for k in order}
        )
    one, two = accepted(first), accepted(second)
    assert one.sha256 == two.sha256 and one.planned == two.planned


def test_the_hash_is_the_sha256_of_the_canonical_json() -> None:
    loaded = accepted(api_dict())
    assert loaded.sha256 == hashlib.sha256(loaded.canonical_json.encode("ascii")).hexdigest()
    assert json.loads(loaded.canonical_json)["api_targets"][0]["endpoints"][1]["params"] == {
        "project_id": ["p-1001", "p-2002"]
    }


# -------------------------------------------------------------------------------------------- the rules ----
@pytest.mark.parametrize(
    "rule", ["state_changing_methods", "enumeration_or_fuzzing", "response_values_in_evidence", "spec_widens_scope"]
)
def test_every_rule_is_required(rule: str) -> None:
    data = api_dict()
    del target(data)["rules"][rule]
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize(
    "rule", ["state_changing_methods", "enumeration_or_fuzzing", "response_values_in_evidence", "spec_widens_scope"]
)
def test_allowed_is_not_available_and_anything_else_is_a_type_error(rule: str) -> None:
    data = api_dict()
    target(data)["rules"][rule] = "allowed"
    assert "not available in this version" in str(refused(data, ErrorCode.SCOPE_011))
    for other in ("Forbidden", "yes", "", True, 0):
        data = api_dict()
        target(data)["rules"][rule] = other
        refused(data, ErrorCode.SCOPE_003)


def test_an_unknown_key_is_refused_at_every_level() -> None:
    for place in (
        lambda d: target(d),
        lambda d: endpoint(d),
        lambda d: target(d)["principals"][0],
        lambda d: target(d)["limits"],
        lambda d: target(d)["rules"],
    ):
        data = api_dict()
        place(data)["surprise"] = 1
        refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize(
    "method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "get", "Get", "", "GET "]
)
def test_only_get_and_head_can_be_listed_for_an_endpoint(method: str) -> None:
    data = api_dict()
    endpoint(data)["method"] = method
    assert "not available in this version" in str(refused(data, ErrorCode.SCOPE_011))


def test_head_is_accepted() -> None:
    data = api_dict()
    endpoint(data)["method"] = "HEAD"
    assert accepted(data).planned[1].method == "HEAD"


def test_production_needs_a_reference_and_only_production_may_have_one() -> None:
    data = api_dict()
    target(data)["environment"] = "production"
    refused(data, ErrorCode.SCOPE_011)
    target(data)["production_approval_ref"] = "CHG-1234"
    assert accepted(data).config.api_targets[0].environment == "production"
    data = api_dict()
    target(data)["production_approval_ref"] = "CHG-1234"
    refused(data, ErrorCode.SCOPE_011)
    data = api_dict()
    target(data)["environment"] = "production"
    target(data)["production_approval_ref"] = "no spaces allowed"
    refused(data, ErrorCode.SCOPE_003)


def test_the_environment_is_a_closed_list_and_the_kind_is_rest() -> None:
    for field, value in (("environment", "prod"), ("kind", "graphql"), ("kind", "soap")):
        data = api_dict()
        target(data)[field] = value
        refused(data, ErrorCode.SCOPE_003)


# ------------------------------------------------------------------------- ids, hosts, ports and paths ----
@pytest.mark.parametrize("bad", ["", "a", "A-b", "-ab", "a_b", "a" * 41, "ab cd", "ab/cd"])
def test_ids_are_two_to_forty_lowercase_characters(bad: str) -> None:
    for place in (lambda d: target(d), lambda d: endpoint(d), lambda d: target(d)["principals"][0]):
        data = api_dict()
        place(data)["id"] = bad
        refused(data, ErrorCode.SCOPE_003)


def test_the_host_follows_the_same_canonical_rules_as_everywhere() -> None:
    for bad in ("*.example.invalid", "10.0.0.1", "api example.invalid", "xn--", "localhost"):
        data = api_dict()
        target(data)["host"] = bad
        with pytest.raises(ScopeError):
            parse_scope(dump(data), now=NOW)
    data = api_dict()
    target(data)["host"] = "API.Staging.Example.Invalid."
    assert accepted(data).config.api_targets[0].host == HOST


@pytest.mark.parametrize("port", [0, 65536, -1, "443", 443.5, True])
def test_the_port_is_an_integer_from_1_to_65535(port: Any) -> None:
    data = api_dict()
    target(data)["port"] = port
    with pytest.raises(ScopeError):
        parse_scope(dump(data), now=NOW)


@pytest.mark.parametrize(
    "path", ["v1", "/v1/../x", "/v1//x", "/v1?x=1", "/v1#f", "/v1/%2e", "/v 1", "/" + "a" * 256, "/v1/{x}"]
)
def test_the_base_path_is_an_exact_canonical_path(path: str) -> None:
    data = api_dict()
    target(data)["base_path"] = path
    refused(data, ErrorCode.SCOPE_006)


def test_a_base_path_of_slash_adds_no_extra_slash_and_a_trailing_slash_is_joined_once() -> None:
    for base, expected in (("/", "/projects"), ("/v1/", "/v1/projects"), ("/v1", "/v1/projects")):
        data = api_dict()
        target(data)["base_path"] = base
        assert accepted(data).planned[1].path == expected


@pytest.mark.parametrize(
    "path",
    [
        "projects",
        "/p//q",
        "/p/../q",
        "/p/./q",
        "/p?x=1",
        "/p#f",
        "/p/%41",
        "/p/{}",
        "/p/{Id}",
        "/p/{id",
        "/p/id}",
        "/p/x{id}",
        "/p/{id}x",
        "/p/{{id}}",
        "/p/{id}/{id}",
        "/p/{a b}",
        "/p/{1id}",
        "/p/{id-x}",
        "/" + "a" * 256,
    ],
)
def test_an_endpoint_path_is_canonical_and_a_placeholder_is_a_whole_segment(path: str) -> None:
    for params in ({"id": ["x1"]}, {}):  # with no list at all, only the path rules can refuse it
        data = api_dict()
        endpoint(data)["path"] = path
        endpoint(data)["params"] = params
        refused(data, ErrorCode.SCOPE_006)


def test_a_path_may_end_in_a_slash_and_a_placeholder_may_be_the_last_segment() -> None:
    data = api_dict()
    endpoint(data).update(path="/projects/{project_id}/", params={"project_id": ["p1"]})
    assert accepted(data).planned[1].path == "/v1/projects/p1/"


# ---------------------------------------------------------------------------------------------- params ----
def test_every_placeholder_needs_a_list_and_every_list_a_placeholder() -> None:
    data = api_dict()
    endpoint(data, 1)["params"] = {}
    refused(data, ErrorCode.SCOPE_006)
    data = api_dict()
    endpoint(data, 1)["params"]["extra"] = ["x1"]
    refused(data, ErrorCode.SCOPE_006)
    data = api_dict()
    endpoint(data, 1)["params"] = {"other": ["x1"]}
    refused(data, ErrorCode.SCOPE_006)
    data = api_dict()
    endpoint(data)["params"] = {"project_id": ["x1"]}  # the path has no placeholder
    refused(data, ErrorCode.SCOPE_006)


@pytest.mark.parametrize("values", [[], ["a1", "a2", "a3", "a4", "a5", "a6"], ["a1", "a1"]])
def test_a_parameter_lists_one_to_five_different_values(values: list[str]) -> None:
    data = api_dict()
    endpoint(data, 1)["params"]["project_id"] = values
    refused(data, ErrorCode.SCOPE_007)


def test_five_values_are_the_most_and_there_is_no_way_to_write_a_range() -> None:
    data = api_dict()
    endpoint(data, 1)["params"]["project_id"] = ["a1", "a2", "a3", "a4", "a5"]
    assert len([op for op in accepted(data).planned if op.kind == "api_read" and op.endpoint_id == "get-project"]) == 10
    data = api_dict()
    endpoint(data, 1)["params"]["project_id"] = [
        "1..100"
    ]  # dots are allowed, so this is one literal value, not a range
    assert len([op for op in accepted(data).planned if op.kind == "api_read" and op.endpoint_id == "get-project"]) == 2
    for spec in (["*"], ["[1-9]"], ["1,2"], ["a b"], ["a/b"], ["a%41"], ["a" * 65], [""], ["é"], ["{x}"], ["a\n"]):
        data = api_dict()
        endpoint(data, 1)["params"]["project_id"] = spec
        refused(data, ErrorCode.SCOPE_006)


def test_a_value_may_be_one_to_sixty_four_characters_of_letters_digits_and_dot_underscore_tilde_hyphen() -> None:
    data = api_dict()
    endpoint(data, 1)["params"]["project_id"] = ["A", "a" * 64, "0.9_~-"]
    assert len(accepted(data).planned) == 1 + 2 + 3 * 2 + 1 + 3


def test_a_value_must_be_text() -> None:
    for bad in ([1001], [None], [True], 5, "p1", {"a": 1}):
        data = api_dict()
        endpoint(data, 1)["params"]["project_id"] = bad
        with pytest.raises(ScopeError):
            parse_scope(dump(data), now=NOW)


def test_a_parameter_name_is_lowercase_and_there_are_at_most_four() -> None:
    data = api_dict()
    wide(data)
    endpoint(data, 1).update(path="/a/{Bad}", params={"Bad": ["x1"]})
    refused(data, ErrorCode.SCOPE_006)
    data = api_dict()
    wide(data)
    endpoint(data, 1).update(path="/a/{p1}/{p2}/{p3}/{p4}", params={f"p{i}": ["x1"] for i in range(1, 5)})
    assert accepted(data)
    data = api_dict()
    wide(data)
    endpoint(data, 1).update(path="/a/{p1}/{p2}/{p3}/{p4}/{p5}", params={f"p{i}": ["x1"] for i in range(1, 6)})
    refused(data, ErrorCode.SCOPE_007)


def test_parameters_vary_in_the_order_the_path_names_them_and_values_in_the_order_given() -> None:
    data = api_dict()
    wide(data)
    endpoint(data, 1).update(path="/o/{org}/p/{proj}", params={"proj": ["p2", "p1"], "org": ["o1", "o2"]})
    paths = [
        op.path for op in accepted(data).planned if op.endpoint_id == "get-project" and op.principal == "tenant-a-user"
    ]
    assert paths == ["/v1/o/o1/p/p2", "/v1/o/o1/p/p1", "/v1/o/o2/p/p2", "/v1/o/o2/p/p1"]


def test_resolve_path_fills_each_placeholder_and_nothing_else() -> None:
    assert resolve_path("/v1", "/a/{x}/b/{y}", (("x", "1"), ("y", "2"))) == "/v1/a/1/b/2"
    assert resolve_path("/", "/a", ()) == "/a"
    assert resolve_path("/v1/", "/a/", ()) == "/v1/a/"


def test_a_filled_in_path_may_not_pass_256_characters() -> None:
    data = api_dict()
    target(data)["base_path"] = "/" + "b" * 200
    endpoint(data, 1)["params"]["project_id"] = ["a" * 64, "a1"]
    refused(data, ErrorCode.SCOPE_006)
    endpoint(data, 1)["params"]["project_id"] = ["a" * 40, "a1"]
    assert accepted(data)


def test_the_host_path_and_origin_together_stay_within_the_recorded_request_line() -> None:
    data = api_dict()
    target(data)["host"] = ".".join(["a" * 60] * 3 + ["example", "invalid"])
    target(data)["base_path"] = "/" + "b" * 150
    target(data)["cors_origins"] = ["https://" + ".".join(["c" * 60] * 3 + ["example", "invalid"])]
    refused(data, ErrorCode.SCOPE_006)


# -------------------------------------------------------------------------------------- principals ----
def test_anonymous_always_exists_and_may_not_be_declared() -> None:
    data = api_dict()
    target(data)["principals"].append({"id": "anonymous", "label": "Nobody"})
    assert "always exists" in str(refused(data, ErrorCode.SCOPE_003))


def test_an_endpoint_may_name_anonymous_and_the_declared_principals_only() -> None:
    data = api_dict()
    endpoint(data)["principals"] = ["stranger"]
    refused(data, ErrorCode.SCOPE_009)
    data = api_dict()
    endpoint(data)["principals"] = ["anonymous", "anonymous"]
    refused(data, ErrorCode.SCOPE_009)
    data = api_dict()
    endpoint(data)["principals"] = ["anonymous"]
    assert accepted(data)


def test_two_principals_may_not_share_an_id_and_two_endpoints_may_not_either() -> None:
    data = api_dict()
    target(data)["principals"].append({"id": "tenant-a-user", "label": "Again"})
    refused(data, ErrorCode.SCOPE_009)
    data = api_dict()
    endpoint(data, 1)["id"] = "list-projects"
    refused(data, ErrorCode.SCOPE_005)


def test_an_endpoint_lists_one_to_four_principals() -> None:
    data = api_dict()
    endpoint(data)["principals"] = []
    refused(data, ErrorCode.SCOPE_007)
    data = api_dict()
    target(data)["principals"] = [{"id": f"user-{i}", "label": f"User {i}"} for i in range(4)]
    endpoint(data, 1)["principals"] = ["user-0"]
    endpoint(data)["principals"] = ["anonymous", *(f"user-{i}" for i in range(4))]
    refused(data, ErrorCode.SCOPE_007)
    endpoint(data)["principals"] = [f"user-{i}" for i in range(4)]
    assert accepted(data)


@pytest.mark.parametrize("label", ["", " x", "x" * 81, "a<b", "a\nb", "<script>", "Ünï", "a`b", "a|b", "a*b"])
def test_a_label_is_plain_short_text(label: str) -> None:
    data = api_dict()
    target(data)["principals"][0]["label"] = label
    refused(data, ErrorCode.SCOPE_003)


def test_a_label_may_hold_letters_digits_and_light_punctuation() -> None:
    data = api_dict()
    target(data)["principals"][0]["label"] = "Tenant A, editor (read/write): ok_1-2."
    assert accepted(data)


def test_at_most_ten_principals_and_forty_endpoints_and_ten_targets() -> None:
    data = api_dict()
    target(data)["principals"] = [{"id": f"user-{i:02d}", "label": "x"} for i in range(11)]
    refused(data, ErrorCode.SCOPE_007)
    data = api_dict()
    wide(data)
    target(data)["endpoints"] = [{**copy.deepcopy(endpoint(data)), "id": f"ep-{i:02d}"} for i in range(41)]
    refused(data, ErrorCode.SCOPE_007)


# -------------------------------------------------------------------------- operations and their fields ----
def test_each_field_needs_its_operation_and_each_operation_its_field() -> None:
    cases: list[Any] = [
        lambda d: d.pop("spec_paths"),  # api_spec without paths
        lambda d: d.update(operations=["api_read", "api_options"]),  # spec_paths without api_spec
        lambda d: d.pop("cors_origins"),  # api_options without origins
        lambda d: d.update(operations=["api_spec", "api_read"]),  # origins without api_options
        lambda d: d.update(endpoints=[]),  # api_read without endpoints
        lambda d: d.update(operations=["api_spec"]),  # endpoints without api_read or api_options
    ]
    for case in cases:
        data = api_dict()
        case(target(data))
        refused(data, ErrorCode.SCOPE_009)


def test_a_spec_only_target_needs_no_endpoints_and_an_options_only_target_needs_endpoints() -> None:
    data = api_dict()
    target(data).update(operations=["api_spec"], endpoints=[], cors_origins=[])
    data["allowed_operations"] = ["api_spec"]
    assert [op.kind for op in accepted(data).planned] == ["api_spec"]
    data = api_dict()
    target(data).update(operations=["api_options"], spec_paths=[])
    data["allowed_operations"] = ["api_options"]
    assert {op.kind for op in accepted(data).planned} == {"api_options"}


def test_the_operations_of_a_target_must_be_allowed_globally_and_every_allowed_one_used() -> None:
    data = api_dict()
    data["allowed_operations"] = ["api_spec", "api_read"]
    refused(data, ErrorCode.SCOPE_009)
    data = api_dict()
    target(data).update(operations=["api_spec", "api_read"], cors_origins=[])
    refused(data, ErrorCode.SCOPE_009)  # api_options is allowed but no target uses it


def test_an_operation_may_not_be_repeated() -> None:
    data = api_dict()
    target(data)["operations"] = ["api_read", "api_read"]
    refused(data, ErrorCode.SCOPE_003)
    data = api_dict()
    data["allowed_operations"] = ["api_spec", "api_read", "api_options", "api_read"]
    refused(data, ErrorCode.SCOPE_003)


def test_an_unknown_operation_is_refused() -> None:
    for bad in ("api_write", "api_fuzz", "api_enumerate", "API_READ"):
        data = api_dict()
        data["allowed_operations"].append(bad)
        refused(data, ErrorCode.SCOPE_003)


def test_spec_paths_are_exact_canonical_unique_and_at_most_five() -> None:
    data = api_dict()
    target(data)["spec_paths"] = ["/a", "/a"]
    refused(data, ErrorCode.SCOPE_006)
    target(data)["spec_paths"] = ["/a/../b"]
    refused(data, ErrorCode.SCOPE_006)
    data = api_dict()
    wide(data)
    target(data)["spec_paths"] = [f"/s{i}.json" for i in range(6)]
    refused(data, ErrorCode.SCOPE_007)
    target(data)["spec_paths"] = [f"/s{i}.json" for i in range(5)]
    assert len([op for op in accepted(data).planned if op.kind == "api_spec"]) == 5


# ------------------------------------------------------------------------------------------- origins ----
@pytest.mark.parametrize(
    "origin",
    [
        "http://x.example.invalid",
        "https://x.example.invalid/",
        "https://x.example.invalid/p",
        "https://x.example.invalid:443",
        "https://x.example.invalid:0",
        "https://x.example.invalid:99999",
        "https://u@x.example.invalid",
        "https://x.example.invalid?q=1",
        "x.example.invalid",
        "https://",
        "*",
        "null",
    ],
)
def test_an_origin_is_exactly_https_host_and_an_optional_port_other_than_443(origin: str) -> None:
    data = api_dict()
    target(data)["cors_origins"] = [origin]
    refused(data, ErrorCode.SCOPE_006)


@pytest.mark.parametrize(
    "origin",
    ["https://X.example.invalid", "https://x.example.invalid.", "https://10.0.0.1", "https://*.example.invalid"],
)
def test_an_origins_host_must_be_in_canonical_form_and_never_an_address_or_a_wildcard(origin: str) -> None:
    data = api_dict()
    target(data)["cors_origins"] = [origin]
    refused(data, ErrorCode.SCOPE_005)


def test_a_good_origin_with_a_port_is_accepted_and_at_most_three_are_listed_without_repeats() -> None:
    data = api_dict()
    target(data)["cors_origins"] = ["https://a.example.invalid", "https://b.example.invalid:8443"]
    assert len([op for op in accepted(data).planned if op.kind == "api_options"]) == 3 * 2
    target(data)["cors_origins"] = [f"https://o{i}.example.invalid" for i in range(4)]
    refused(data, ErrorCode.SCOPE_007)
    target(data)["cors_origins"] = [ORIGIN, ORIGIN]
    refused(data, ErrorCode.SCOPE_003)


# ------------------------------------------------------------------------------------------- limits ----
def test_the_plan_must_fit_max_api_requests_exactly() -> None:
    data = api_dict()
    target(data)["limits"]["max_api_requests"] = 11
    assert len(accepted(data).planned) == 11
    target(data)["limits"]["max_api_requests"] = 10
    assert "the plan needs 11 requests but max_api_requests is 10" in str(refused(data, ErrorCode.SCOPE_007))


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("max_api_requests", 0),
        ("max_api_requests", 401),
        ("max_response_bytes", 1023),
        ("max_response_bytes", 1_000_001),
    ],
)
def test_the_limits_have_ranges(field: str, bad: int) -> None:
    data = api_dict()
    target(data)["limits"][field] = bad
    refused(data, ErrorCode.SCOPE_007)


@pytest.mark.parametrize(
    ("field", "good"),
    [
        ("max_api_requests", 400),
        ("max_api_requests", 11),
        ("max_response_bytes", 1024),
        ("max_response_bytes", 1_000_000),
    ],
)
def test_the_limit_edges_are_accepted(field: str, good: int) -> None:
    data = api_dict()
    target(data)["limits"][field] = good
    assert accepted(data)


def test_both_limits_are_required() -> None:
    for field in ("max_api_requests", "max_response_bytes"):
        data = api_dict()
        del target(data)["limits"][field]
        refused(data, ErrorCode.SCOPE_003)


def test_a_smaller_global_max_requests_does_not_refuse_the_scope() -> None:
    data = api_dict()
    data["max_requests"] = 5
    assert len(accepted(data).planned) == 11  # the run will end incomplete; the scope is still valid


# ------------------------------------------------------------------------------------------- targets ----
def test_two_api_targets_may_not_share_an_id_or_an_endpoint() -> None:
    data = api_dict()
    second = copy.deepcopy(target(data))
    second["host"] = "other.example.invalid"
    data["api_targets"].append(second)
    refused(data, ErrorCode.SCOPE_005)  # same id
    second["id"] = "orders-two"
    second["host"] = HOST
    refused(data, ErrorCode.SCOPE_005)  # same scheme, host and port


def test_two_api_targets_on_different_ports_are_two_targets() -> None:
    data = api_dict()
    second = copy.deepcopy(target(data))
    second.update(id="orders-two", port=8443)
    data["api_targets"].append(second)
    assert len(accepted(data).planned) == 22


def test_at_most_ten_api_targets() -> None:
    data = api_dict()
    data["api_targets"] = [{**copy.deepcopy(target(data)), "id": f"t-{i:02d}", "port": 8000 + i} for i in range(11)]
    refused(data, ErrorCode.SCOPE_007)


def test_a_scope_with_only_api_targets_has_a_target_and_one_with_none_does_not() -> None:
    data = api_dict()
    del data["api_targets"]
    data["allowed_operations"] = ["dns_metadata"]
    refused(data, ErrorCode.SCOPE_007)


# --------------------------------------------------------------------------------------- the property ----
@settings(max_examples=60, deadline=None)
@given(
    first=st.lists(st.from_regex(r"[A-Za-z0-9._~-]{1,12}", fullmatch=True), min_size=1, max_size=5, unique=True),
    second=st.lists(st.from_regex(r"[A-Za-z0-9._~-]{1,12}", fullmatch=True), min_size=1, max_size=5, unique=True),
    principals=st.integers(min_value=1, max_value=3),
)
def test_the_plan_is_exactly_the_listed_values_times_the_principals_and_no_path_keeps_a_brace(
    first: list[str], second: list[str], principals: int
) -> None:
    data = api_dict()
    wide(data)
    target(data)["principals"] = [{"id": f"user-{i}", "label": "x"} for i in range(3)]
    endpoint(data)["principals"] = ["anonymous"]
    endpoint(data, 1).update(
        path="/o/{org}/p/{proj}",
        params={"org": first, "proj": second},
        principals=[f"user-{i}" for i in range(principals)],
    )
    loaded = accepted(data)
    reads = [op for op in loaded.planned if op.kind == "api_read" and op.endpoint_id == "get-project"]
    assert len(reads) == len(first) * len(second) * principals
    assert all("{" not in (op.path or "") and "}" not in (op.path or "") for op in loaded.planned)
    assert {dict(op.params)["org"] for op in reads} == set(first) and {dict(op.params)["proj"] for op in reads} == set(
        second
    )
    assert len(loaded.planned) == loaded.config.api_targets[0].request_count
