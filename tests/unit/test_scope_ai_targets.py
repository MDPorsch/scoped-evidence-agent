"""D-E28 to D-E36 (docs/ai-targets.md): scopes for pentesting AI systems. Every rule has a refusal test and its code."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import PlannedOperation, parse_scope
from tests.support import AI_PACK, NOW, SCOPE_FILES, ai_scope_dict, dump, scope_dict

pytestmark = pytest.mark.milestone("M1")

HOST = "assistant.example.invalid"
PATH = "/v1/chat/completions"


def refused(data: dict[str, Any], code: ErrorCode) -> ScopeError:
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert caught.value.code is code, f"{caught.value.code}: {caught.value}"
    return caught.value


def accepted(data: dict[str, Any]) -> Any:
    return parse_scope(dump(data), now=NOW)


def target(data: dict[str, Any]) -> dict[str, Any]:
    return data["ai_targets"][0]  # type: ignore[no-any-return]


def fit(data: dict[str, Any], *, total: int = 200_000, requests: int = 200) -> None:
    """Keep the consumption limits generous so a test can vary one other field at a time."""
    target(data)["limits"].update(max_total_tokens=total, max_model_requests=requests)


# ------------------------------------------------------------------------------------- the fixture ----
def test_the_ai_fixture_validates_and_is_an_ai_only_scope() -> None:
    loaded = parse_scope(SCOPE_FILES[AI_PACK].read_text(encoding="utf-8"), now=NOW)
    assert loaded.config.allowed_targets == [] and len(loaded.config.ai_targets) == 1
    assert loaded.config.ai_targets[0].id == "support-bot" and loaded.config.mode == "offline"


def test_the_plan_is_the_metadata_read_then_each_probe_in_set_order() -> None:
    plan = parse_scope(SCOPE_FILES[AI_PACK].read_text(encoding="utf-8"), now=NOW).planned
    probe = lambda s, i: PlannedOperation("ai_probe", HOST, "https", 443, PATH, "support-bot", s, i)  # noqa: E731
    assert plan == (
        PlannedOperation("ai_metadata", HOST, "https", 443, "/v1/models", "support-bot", None, None),
        probe("canary-echo-v1", 0),
        probe("canary-echo-v1", 1),
        probe("output-structure-v1", 0),
        probe("output-structure-v1", 1),
    )


def test_an_ai_target_plans_no_dns_tls_or_http_operation() -> None:
    kinds = {op.kind for op in parse_scope(SCOPE_FILES[AI_PACK].read_text(encoding="utf-8"), now=NOW).planned}
    assert kinds == {"ai_metadata", "ai_probe"}


def test_a_probe_set_contributes_one_operation_per_probe_and_probes_are_numbered_from_zero() -> None:
    data = ai_scope_dict()
    target(data).update(
        probe_sets=["canary-instruction-in-data-v1", "system-prompt-canary-v1"],
        test_categories=["prompt_injection", "system_prompt_leakage"],
    )
    probes = [(op.probe_set, op.probe_index) for op in accepted(data).planned if op.kind == "ai_probe"]
    assert probes == [
        ("canary-instruction-in-data-v1", 0),
        ("canary-instruction-in-data-v1", 1),
        ("canary-instruction-in-data-v1", 2),
        ("system-prompt-canary-v1", 0),
        ("system-prompt-canary-v1", 1),
    ]


def test_web_operations_come_first_then_the_ai_targets_in_file_order() -> None:
    data = ai_scope_dict()
    web = scope_dict()
    data["allowed_targets"] = web["allowed_targets"]
    data["allowed_operations"] = ["dns_metadata", "tls_metadata", "http_metadata", "ai_metadata", "ai_probe"]
    second = copy.deepcopy(target(data))
    second.update(id="second-bot", host="second.example.invalid")
    data["ai_targets"].append(second)
    plan = accepted(data).planned
    kinds = [op.kind for op in plan]
    assert kinds[:5] == ["dns_metadata", "tls_metadata", "http_metadata", "http_metadata", "http_metadata"]
    assert [op.target_id for op in plan if op.kind.startswith("ai_")] == ["support-bot"] * 5 + ["second-bot"] * 5


def test_the_same_host_may_be_listed_as_a_web_target_and_as_an_ai_target() -> None:
    data = ai_scope_dict()
    data["allowed_targets"] = [{"host": HOST, "schemes": ["https"], "ports": [443], "allowed_paths": ["/robots.txt"]}]
    data["allowed_operations"] = ["dns_metadata", "tls_metadata", "http_metadata", "ai_metadata", "ai_probe"]
    assert {op.kind for op in accepted(data).planned} == {
        "dns_metadata",
        "tls_metadata",
        "http_metadata",
        "ai_metadata",
        "ai_probe",
    }


# ------------------------------------------------------------------------------------------ hash ----
def independent_hash(normalised: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(normalised, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


AI_NORMALISED: dict[str, Any] = {
    "engagement_id": "lab-ai-support-bot-001",
    "owner_approval_ref": "local-lab-consent",
    "expires_at": "2026-12-31T23:59:00Z",
    "mode": "offline",
    "allowed_targets": [],
    "allowed_operations": ["ai_metadata", "ai_probe"],
    "max_requests": 12,
    "max_parallelism": 2,
    "per_request_timeout_seconds": 5,
    "max_response_bytes": 100000,
    "follow_redirects": False,
    "ai_targets": [
        {
            "id": "support-bot",
            "kind": "chat_endpoint",
            "layer": "application",
            "environment": "test",
            "production_approval_ref": None,
            "host": HOST,
            "scheme": "https",
            "port": 443,
            "api_style": "openai_compatible",
            "operations": ["ai_metadata", "ai_probe"],
            "metadata_paths": ["/v1/models"],
            "probe_path": PATH,
            "probe_sets": ["canary-echo-v1", "output-structure-v1"],
            "test_categories": ["prompt_injection", "output_handling"],
            "limits": {
                "max_model_requests": 8,
                "max_input_tokens": 500,
                "max_output_tokens": 300,
                "max_total_tokens": 6400,
            },
            "rules": {
                "tool_invocation": "forbidden",
                "persistent_state_writes": "forbidden",
                "personal_data_in_probes": "forbidden",
                "target_output_to_assistant_model": "forbidden",
            },
        }
    ],
}


def test_the_ai_scope_hash_is_the_sha256_of_the_canonical_json_of_the_normalised_scope() -> None:
    loaded = parse_scope(SCOPE_FILES[AI_PACK].read_text(encoding="utf-8"), now=NOW)
    assert json.loads(loaded.canonical_json) == AI_NORMALISED and loaded.sha256 == independent_hash(AI_NORMALISED)


def test_a_scope_without_ai_targets_has_no_ai_key_so_old_scopes_keep_their_hash() -> None:
    assert "ai_targets" not in json.loads(parse_scope(dump(scope_dict()), now=NOW).canonical_json)


@pytest.mark.parametrize(
    "change",
    [
        lambda t: t["limits"].update(max_output_tokens=299),
        lambda t: t["limits"].update(max_model_requests=7),
        lambda t: t.update(probe_sets=["canary-echo-v1"]),
        lambda t: t.update(test_categories=["output_handling", "prompt_injection"]),
        lambda t: t.update(environment="staging"),
        lambda t: t.update(host="other.example.invalid"),
        lambda t: t.update(id="other-bot"),
        lambda t: t.update(kind="agent"),
        lambda t: t.update(api_style="messages"),
        lambda t: t.update(metadata_paths=["/v1/models", "/v1/info"]),
        lambda t: t.update(probe_path="/v1/other"),
    ],
)
def test_anything_that_changes_what_an_ai_target_may_do_changes_the_hash(change: Any) -> None:
    baseline = parse_scope(SCOPE_FILES[AI_PACK].read_text(encoding="utf-8"), now=NOW).sha256
    data = ai_scope_dict()
    change(target(data))
    assert accepted(data).sha256 != baseline


# ------------------------------------------------------------------ layer, rules, environment ----
@pytest.mark.parametrize("layer", ["model_provider", "provider", "model", "foundation_model"])
def test_only_the_application_layer_can_be_tested(layer: str) -> None:
    data = ai_scope_dict()
    target(data)["layer"] = layer
    error = refused(data, ErrorCode.SCOPE_011)
    assert error.path == "ai_targets[0].layer"


def test_the_layer_is_required() -> None:
    data = ai_scope_dict()
    del target(data)["layer"]
    refused(data, ErrorCode.SCOPE_003)


RULES = ["tool_invocation", "persistent_state_writes", "personal_data_in_probes", "target_output_to_assistant_model"]


@pytest.mark.parametrize("rule", RULES)
def test_every_rule_is_required(rule: str) -> None:
    data = ai_scope_dict()
    del target(data)["rules"][rule]
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize("rule", RULES)
def test_a_rule_set_to_allowed_is_refused_as_not_available_in_this_version(rule: str) -> None:
    data = ai_scope_dict()
    target(data)["rules"][rule] = "allowed"
    error = refused(data, ErrorCode.SCOPE_011)
    assert error.path == f"ai_targets[0].rules.{rule}" and "not available in this version" in str(error)


@pytest.mark.parametrize("value", ["yes", "Forbidden", "", "forbid", True, False, None, 1])
def test_a_rule_must_say_exactly_forbidden(value: Any) -> None:
    data = ai_scope_dict()
    target(data)["rules"]["tool_invocation"] = value
    refused(data, ErrorCode.SCOPE_003)


def test_the_rules_object_is_required_and_takes_no_extra_keys() -> None:
    data = ai_scope_dict()
    del target(data)["rules"]
    refused(data, ErrorCode.SCOPE_003)
    data = ai_scope_dict()
    target(data)["rules"]["extra_rule"] = "forbidden"
    refused(data, ErrorCode.SCOPE_003)


def test_production_needs_an_approval_reference_and_only_production_may_have_one() -> None:
    data = ai_scope_dict()
    target(data)["environment"] = "production"
    refused(data, ErrorCode.SCOPE_011)
    target(data)["production_approval_ref"] = "change-4821"
    assert accepted(data).config.ai_targets[0].production_approval_ref == "change-4821"
    for env in ("test", "staging"):
        target(data)["environment"] = env
        refused(data, ErrorCode.SCOPE_011)


@pytest.mark.parametrize("ref", ["ab", "has space", "semi;colon", "a" * 129, ""])
def test_the_production_reference_follows_the_approval_reference_pattern(ref: str) -> None:
    data = ai_scope_dict()
    target(data).update(environment="production", production_approval_ref=ref)
    refused(data, ErrorCode.SCOPE_003)


# ---------------------------------------------------------------------- closed vocabularies, ids ----
@pytest.mark.parametrize(
    ("field", "value"), [("kind", "chatbot"), ("api_style", "grpc"), ("environment", "prod"), ("scheme", "ftp")]
)
def test_closed_vocabularies_refuse_unknown_values(field: str, value: str) -> None:
    data = ai_scope_dict()
    target(data)[field] = value
    refused(data, ErrorCode.SCOPE_003)


@pytest.mark.parametrize("kind", ["chat_endpoint", "agent", "rag_service", "mcp_server"])
@pytest.mark.parametrize("api_style", ["openai_compatible", "messages", "custom_json"])
def test_every_documented_kind_and_api_style_is_accepted(kind: str, api_style: str) -> None:
    data = ai_scope_dict()
    target(data).update(kind=kind, api_style=api_style)
    accepted(data)


@pytest.mark.parametrize("value", ["A", "a", "-ab", "a b", "a" * 41, "", "a_b", "ab/c"])
def test_an_ai_target_id_follows_the_pattern(value: str) -> None:
    data = ai_scope_dict()
    target(data)["id"] = value
    refused(data, ErrorCode.SCOPE_003)


def test_the_longest_and_shortest_ids_are_accepted() -> None:
    for value in ("ab", "a" + "b" * 39):
        data = ai_scope_dict()
        target(data)["id"] = value
        accepted(data)


def test_two_ai_targets_with_the_same_id_are_refused() -> None:
    data = ai_scope_dict()
    clone = copy.deepcopy(target(data))
    clone["host"] = "second.example.invalid"
    data["ai_targets"].append(clone)
    refused(data, ErrorCode.SCOPE_005)


def test_two_ai_targets_at_the_same_endpoint_are_refused_not_merged() -> None:
    data = ai_scope_dict()
    clone = copy.deepcopy(target(data))
    clone.update(id="second-bot", host=HOST.upper() + ".")
    data["ai_targets"].append(clone)
    refused(data, ErrorCode.SCOPE_005)


def test_the_host_follows_the_canonical_rules_and_is_reported_with_its_path() -> None:
    data = ai_scope_dict()
    target(data)["host"] = "*.example.invalid"
    assert refused(data, ErrorCode.SCOPE_005).path == "ai_targets[0].host"
    target(data)["host"] = "192.0.2.10"
    refused(data, ErrorCode.SCOPE_005)


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_the_port_is_range_checked(port: int) -> None:
    data = ai_scope_dict()
    target(data)["port"] = port
    refused(data, ErrorCode.SCOPE_006)


def test_unknown_keys_and_wrong_types_are_refused() -> None:
    data = ai_scope_dict()
    target(data)["surprise"] = 1
    refused(data, ErrorCode.SCOPE_003)
    data = ai_scope_dict()
    target(data)["port"] = "443"
    refused(data, ErrorCode.SCOPE_003)


def test_the_ai_target_count_is_capped_at_ten() -> None:
    data = ai_scope_dict()
    base = target(data)
    data["ai_targets"] = [{**copy.deepcopy(base), "id": f"bot-{i}", "host": f"h{i}.example.invalid"} for i in range(10)]
    assert len(accepted(data).config.ai_targets) == 10
    data["ai_targets"].append({**copy.deepcopy(base), "id": "bot-10", "host": "h10.example.invalid"})
    refused(data, ErrorCode.SCOPE_007)


# ----------------------------------------------------------------------- operations and coupling ----
def test_an_ai_target_may_not_name_a_web_operation() -> None:
    data = ai_scope_dict()
    target(data)["operations"] = ["dns_metadata"]
    refused(data, ErrorCode.SCOPE_003)


def test_an_empty_or_repeated_operation_list_is_refused() -> None:
    data = ai_scope_dict()
    target(data)["operations"] = []
    refused(data, ErrorCode.SCOPE_007)
    target(data)["operations"] = ["ai_metadata", "ai_metadata"]
    refused(data, ErrorCode.SCOPE_003)


def test_a_target_operation_the_scope_does_not_allow_globally_is_refused() -> None:
    data = ai_scope_dict()
    data["allowed_operations"] = ["ai_metadata"]
    refused(data, ErrorCode.SCOPE_009)  # the target still asks for ai_probe


def test_an_allowed_ai_operation_that_no_ai_target_uses_is_refused() -> None:
    data = ai_scope_dict()
    target(data).update(operations=["ai_metadata"], probe_path=None, probe_sets=[], test_categories=[])
    del target(data)["probe_path"]
    refused(data, ErrorCode.SCOPE_009)  # ai_probe is allowed globally and nobody uses it


def test_ai_targets_with_no_ai_operation_allowed_are_refused() -> None:
    data = ai_scope_dict()
    data["allowed_operations"] = ["dns_metadata"]
    data["allowed_targets"] = [{"host": HOST, "schemes": ["https"], "ports": [443]}]
    refused(data, ErrorCode.SCOPE_009)


def test_a_web_scope_may_not_allow_an_ai_operation_without_an_ai_target() -> None:
    data = scope_dict()
    data["allowed_operations"] = ["dns_metadata", "tls_metadata", "http_metadata", "ai_metadata"]
    refused(data, ErrorCode.SCOPE_009)


def test_dns_allowed_but_no_web_target_is_refused() -> None:
    data = ai_scope_dict()
    data["allowed_operations"] = ["dns_metadata", "ai_metadata", "ai_probe"]
    refused(data, ErrorCode.SCOPE_009)


def test_a_scope_with_no_target_of_either_kind_is_refused() -> None:
    data = ai_scope_dict()
    data["ai_targets"] = []
    data["allowed_operations"] = ["dns_metadata"]
    refused(data, ErrorCode.SCOPE_007)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.pop("metadata_paths"),
        lambda t: t.update(metadata_paths=[]),
        lambda t: t.pop("probe_path"),
        lambda t: t.pop("probe_sets"),
        lambda t: t.update(probe_sets=[]),
        lambda t: t.pop("test_categories"),
        lambda t: t.update(test_categories=[]),
    ],
)
def test_each_operation_needs_its_own_fields(mutate: Any) -> None:
    data = ai_scope_dict()
    mutate(target(data))
    refused(data, ErrorCode.SCOPE_009)


@pytest.mark.parametrize(
    "fields", [["probe_path"], ["probe_sets"], ["test_categories"], ["probe_path", "probe_sets", "test_categories"]]
)
def test_probe_fields_are_valid_only_with_the_probe_operation(fields: list[str]) -> None:
    data = ai_scope_dict()
    t = target(data)
    t["operations"] = ["ai_metadata"]
    data["allowed_operations"] = ["ai_metadata"]
    for name in ("probe_path", "probe_sets", "test_categories"):
        if name not in fields:
            t.pop(name)
    refused(data, ErrorCode.SCOPE_009)


def test_metadata_paths_are_valid_only_with_the_metadata_operation() -> None:
    data = ai_scope_dict()
    target(data)["operations"] = ["ai_probe"]
    data["allowed_operations"] = ["ai_probe"]
    refused(data, ErrorCode.SCOPE_009)  # metadata_paths is still there


@pytest.mark.parametrize("path", ["", "v1/models", "/a?b=1", "/a/../b", "//a", "/a b"])
def test_metadata_and_probe_paths_are_exact_canonical_paths(path: str) -> None:
    data = ai_scope_dict()
    target(data)["metadata_paths"] = [path]
    refused(data, ErrorCode.SCOPE_006)
    data = ai_scope_dict()
    target(data)["probe_path"] = path
    refused(data, ErrorCode.SCOPE_006)


def test_metadata_paths_are_unique_and_at_most_five() -> None:
    data = ai_scope_dict()
    target(data)["metadata_paths"] = ["/a", "/a"]
    refused(data, ErrorCode.SCOPE_006)
    target(data)["metadata_paths"] = [f"/m{i}" for i in range(5)]
    assert len(accepted(data).config.ai_targets[0].metadata_paths) == 5
    target(data)["metadata_paths"] = [f"/m{i}" for i in range(6)]
    refused(data, ErrorCode.SCOPE_007)


# ---------------------------------------------------------------------- probe sets and categories ----
def test_a_probe_set_that_is_not_in_the_library_is_refused() -> None:
    data = ai_scope_dict()
    target(data)["probe_sets"] = ["canary-echo-v1", "my-own-probe-v1"]
    error = refused(data, ErrorCode.SCOPE_011)
    assert "library" in str(error)


def test_a_probe_set_whose_category_is_not_authorized_is_refused() -> None:
    data = ai_scope_dict()
    target(data)["test_categories"] = ["prompt_injection"]  # output-structure-v1 is output_handling
    refused(data, ErrorCode.SCOPE_011)


def test_authorizing_more_categories_than_the_sets_use_is_allowed() -> None:
    data = ai_scope_dict()
    target(data)["test_categories"] = ["prompt_injection", "output_handling", "system_prompt_leakage"]
    accepted(data)


def test_probe_sets_and_categories_must_be_unique_and_known() -> None:
    data = ai_scope_dict()
    target(data)["probe_sets"] = ["canary-echo-v1", "canary-echo-v1"]
    refused(data, ErrorCode.SCOPE_003)
    data = ai_scope_dict()
    target(data)["test_categories"] = ["prompt_injection", "prompt_injection", "output_handling"]
    refused(data, ErrorCode.SCOPE_003)
    data = ai_scope_dict()
    target(data)["test_categories"] = ["prompt_injection", "jailbreak"]
    refused(data, ErrorCode.SCOPE_003)


# ----------------------------------------------------------------------------------------- limits ----
@pytest.mark.parametrize(
    ("field", "low_bad", "high_ok", "high_bad"),
    [
        ("max_model_requests", 0, 200, 201),
        ("max_input_tokens", 0, 4000, 4001),
        ("max_output_tokens", 0, 2000, 2001),
        ("max_total_tokens", 0, 200_000, 200_001),
    ],
)
def test_each_limit_is_refused_outside_its_range_and_accepted_at_the_top(
    field: str, low_bad: int, high_ok: int, high_bad: int
) -> None:
    for bad in (low_bad, high_bad, -5):
        data = ai_scope_dict()
        fit(data)
        target(data)["limits"][field] = bad
        refused(data, ErrorCode.SCOPE_007)
    data = ai_scope_dict()
    fit(data)
    target(data)["limits"][field] = high_ok
    accepted(data)


def test_the_limits_object_is_required_complete_and_strict() -> None:
    data = ai_scope_dict()
    del target(data)["limits"]
    refused(data, ErrorCode.SCOPE_003)
    for key in ("max_model_requests", "max_input_tokens", "max_output_tokens", "max_total_tokens"):
        data = ai_scope_dict()
        del target(data)["limits"][key]
        refused(data, ErrorCode.SCOPE_003)
    data = ai_scope_dict()
    target(data)["limits"]["max_cost_usd"] = 5
    refused(data, ErrorCode.SCOPE_003)
    data = ai_scope_dict()
    target(data)["limits"]["max_input_tokens"] = 500.0
    refused(data, ErrorCode.SCOPE_003)


def test_the_planned_probes_must_fit_the_request_cap_exactly() -> None:
    data = ai_scope_dict()  # four probes
    target(data)["limits"]["max_model_requests"] = 4
    accepted(data)
    target(data)["limits"]["max_model_requests"] = 3
    assert "requests" in str(refused(data, ErrorCode.SCOPE_007)).lower()


def test_the_worst_case_token_use_must_fit_the_total_exactly() -> None:
    data = ai_scope_dict()  # 4 probes * (500 + 300) = 3200
    target(data)["limits"]["max_total_tokens"] = 3200
    accepted(data)
    target(data)["limits"]["max_total_tokens"] = 3199
    assert "tokens" in str(refused(data, ErrorCode.SCOPE_007)).lower()


def test_a_metadata_only_target_consumes_no_model_requests_so_any_valid_limits_fit() -> None:
    data = ai_scope_dict()
    t = target(data)
    t.update(operations=["ai_metadata"])
    for name in ("probe_path", "probe_sets", "test_categories"):
        del t[name]
    data["allowed_operations"] = ["ai_metadata"]
    t["limits"] = {"max_model_requests": 1, "max_input_tokens": 1, "max_output_tokens": 1, "max_total_tokens": 1}
    assert [op.kind for op in accepted(data).planned] == ["ai_metadata"]  # all four limits at their minimum of 1


def test_the_global_request_budget_may_still_be_smaller_than_the_plan() -> None:
    data = ai_scope_dict()
    data["max_requests"] = 2  # five operations planned: the run will simply be incomplete, as for web scopes
    assert len(accepted(data).planned) == 5


def test_live_mode_parses_for_an_ai_scope_too() -> None:
    data = ai_scope_dict()
    data["mode"] = "live"
    assert accepted(data).config.mode == "live"


def test_a_web_scope_with_its_targets_removed_is_still_refused() -> None:
    # a regression guard: adding ai_targets must not loosen the web rules for a scope that has none
    data = scope_dict()
    data["allowed_targets"] = []
    refused(data, ErrorCode.SCOPE_007)


def test_a_probe_only_target_plans_probes_and_no_metadata_read() -> None:
    data = ai_scope_dict()
    t = target(data)
    t["operations"] = ["ai_probe"]
    del t["metadata_paths"]
    data["allowed_operations"] = ["ai_probe"]
    plan = accepted(data).planned
    assert [op.kind for op in plan] == ["ai_probe"] * 4
    assert all(op.path == PATH and op.target_id == "support-bot" for op in plan)


def test_a_metadata_only_target_plans_one_read_per_path_in_file_order() -> None:
    data = ai_scope_dict()
    t = target(data)
    t.update(operations=["ai_metadata"], metadata_paths=["/v1/models", "/v1/info", "/health"])
    for name in ("probe_path", "probe_sets", "test_categories"):
        del t[name]
    data["allowed_operations"] = ["ai_metadata"]
    assert [(op.kind, op.path, op.probe_set) for op in accepted(data).planned] == [
        ("ai_metadata", "/v1/models", None),
        ("ai_metadata", "/v1/info", None),
        ("ai_metadata", "/health", None),
    ]
