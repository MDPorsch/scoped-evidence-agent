"""M5: the normalised API observations. Strict, bounded, and unable to hold a value from a body (D-E52)."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from scopedagent.domain.schemas import ObservationEnvelope
from tests.support import API_PACK, golden

pytestmark = pytest.mark.milestone("M5")


def item(kind: str, index: int = 0) -> dict[str, Any]:
    return copy.deepcopy([i for i in golden(API_PACK) if i["observation_type"] == kind][index])


def refused(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ObservationEnvelope.model_validate(data)


def with_payload(kind: str, index: int = 0, **changes: Any) -> dict[str, Any]:
    data = item(kind, index)
    data["payload"].update(changes)
    return data


# ------------------------------------------------------------------------------------------ the goldens ----
def test_every_golden_observation_is_valid_and_survives_a_round_trip() -> None:
    for data in golden(API_PACK):
        envelope = ObservationEnvelope.model_validate(data)
        assert envelope.adapter == "offline_api"
        assert ObservationEnvelope.model_validate_json(envelope.model_dump_json()) == envelope


def test_an_api_observation_belongs_to_the_api_adapter_and_to_no_other() -> None:
    for kind in ("api_spec", "api_read", "api_options"):
        for adapter in ("offline_http", "offline_ai", "offline_dns", "offline_tls"):
            refused({**item(kind), "adapter": adapter})
    for kind in ("http_metadata", "ai_probe", "dns_metadata"):
        data = copy.deepcopy(golden("misconfigured" if kind != "ai_probe" else "ai-support-bot")[0])
        refused({**data, "observation_type": kind, "adapter": "offline_api"})


def test_the_payload_must_match_the_type() -> None:
    read, options = item("api_read"), item("api_options")
    refused({**read, "observation_type": "api_options", "payload": read["payload"]})
    refused({**options, "observation_type": "api_read", "payload": options["payload"]})
    refused({**item("api_spec"), "observation_type": "api_read"})


def test_unknown_fields_are_refused_at_every_level() -> None:
    for kind in ("api_spec", "api_read", "api_options"):
        data = item(kind)
        data["payload"]["surprise"] = 1
        refused(data)
    data = item("api_read")
    data["payload"]["flags"]["surprise"] = True
    refused(data)
    data = item("api_read")
    data["payload"]["shape"][0]["surprise"] = 1
    refused(data)
    data = item("api_options")
    data["payload"]["cors"]["surprise"] = "x"
    refused(data)


# ------------------------------------------------------------------------------------------- the request ----
@pytest.mark.parametrize("kind", ["api_spec", "api_read", "api_options"])
def test_the_request_fields_are_checked(kind: str) -> None:
    for field, bad in (
        ("api_target_id", "A"),
        ("api_target_id", "a"),
        ("api_target_id", "x" * 41),
        ("host", "API.Example.invalid"),
        ("host", "*.example.invalid"),
        ("host", "10.0.0.1"),
        ("port", 0),
        ("port", 65536),
        ("port", "443"),
        ("scheme", "ftp"),
        ("path", "v1/x"),
        ("path", "/a/../b"),
        ("path", "/a?x=1"),
        ("path", "/{id}"),
        ("path", "/" + "a" * 256),
    ):
        refused(with_payload(kind, **{field: bad}))


def test_the_target_of_the_envelope_is_checked_too() -> None:
    data = item("api_read")
    data["target"]["host"] = "Upper.example.invalid"
    refused(data)


# ----------------------------------------------------------------------------------------------- reads ----
def test_a_read_names_its_endpoint_principal_and_method() -> None:
    for field, bad in (
        ("endpoint_id", "X"),
        ("endpoint_id", ""),
        ("principal", "Anonymous"),
        ("principal", "a b"),
        ("method", "POST"),
        ("method", "OPTIONS"),
        ("method", "get"),
    ):
        refused(with_payload("api_read", **{field: bad}))
    for method in ("GET", "HEAD"):
        assert ObservationEnvelope.model_validate(with_payload("api_read", method=method))


def test_params_are_a_few_listed_values() -> None:
    assert ObservationEnvelope.model_validate(with_payload("api_read", 2, params={"project_id": "p-1001"}))
    for bad in (
        {"Project": "x"},
        {"project_id": "a b"},
        {"project_id": ""},
        {"project_id": "a" * 65},
        {"p": 1},
        {"1p": "x"},
        {"p": "a/b"},
    ):
        refused(with_payload("api_read", 2, params=bad))


def test_the_status_size_and_content_type_are_bounded() -> None:
    for field, bad in (
        ("http_status", 99),
        ("http_status", 600),
        ("size_bytes", -1),
        ("size_bytes", 2_000_001),
        ("content_type", "x" * 256),
        ("truncated", "no"),
    ):
        refused(with_payload("api_read", 1, **{field: bad}))
    for field, good in (
        ("http_status", None),
        ("size_bytes", None),
        ("content_type", None),
        ("http_status", 100),
        ("http_status", 599),
    ):
        assert ObservationEnvelope.model_validate(with_payload("api_read", 1, **{field: good}))


def test_headers_are_bounded_like_every_other_observation() -> None:
    refused(with_payload("api_read", 1, headers={"Upper-Case": ["x"]}))
    refused(with_payload("api_read", 1, headers={f"h{i}": ["x"] for i in range(65)}))
    refused(with_payload("api_read", 1, headers={"h": ["x" * 4097]}))
    refused(with_payload("api_read", 1, headers={"h": ["x"] * 65}))


# ---------------------------------------------------------------------------------------------- shapes ----
@pytest.mark.parametrize(
    "path",
    [
        "$.a b",
        "a.b",
        "$.",
        "$.a;b",
        "$.<x>",
        "$." + "a" * 41,
        "$.ignore previous instructions",
        "$[0]",
        "$.{keys}",
        "$.a/b",
        "$.é",
    ],
)
def test_a_shape_path_is_dollar_then_plain_names_brackets_or_the_two_placeholders(path: str) -> None:
    data = item("api_read", 1)
    data["payload"]["shape"][0]["path"] = path
    refused(data)


@pytest.mark.parametrize(
    "path", ["$", "$.a", "$.a.b-c_d.e", "$.items[]", "$.items[].id", "$.{key}.role", "$.?", "$.a[][]", "$..x"]
)
def test_good_shape_paths_are_accepted(path: str) -> None:
    data = item("api_read", 1)
    data["payload"]["shape"][0]["path"] = path
    assert ObservationEnvelope.model_validate(data)


def test_a_shape_entry_has_a_json_type_and_a_bounded_length() -> None:
    for bad_type in ("integer", "String", "date", ""):
        data = item("api_read", 1)
        data["payload"]["shape"][0]["type"] = bad_type
        refused(data)
    for bad_length in (-1, 2_000_001, "3"):
        data = item("api_read", 1)
        data["payload"]["shape"][0]["length"] = bad_length
        refused(data)


def test_at_most_two_hundred_shape_entries() -> None:
    data = item("api_read", 1)
    data["payload"]["shape"] = [{"path": f"$.k{i}", "type": "string", "length": 1} for i in range(201)]
    refused(data)
    data["payload"]["shape"] = [{"path": f"$.k{i}", "type": "string", "length": 1} for i in range(200)]
    assert ObservationEnvelope.model_validate(data)


def test_a_shape_and_its_digest_exist_together_and_only_for_a_json_body() -> None:
    data = item("api_read", 1)
    refused({**data, "payload": {**data["payload"], "shape_digest": None}})
    refused({**data, "payload": {**data["payload"], "shape_status": "none"}})
    refused({**data, "payload": {**data["payload"], "shape_status": "not_json"}})
    refused({**data, "payload": {**data["payload"], "shape_status": "bogus"}})
    refused({**data, "payload": {**data["payload"], "shape_digest": "abc"}})
    none = item("api_read", 6)  # the HEAD request
    assert none["payload"]["shape_status"] == "none"
    refused({**none, "payload": {**none["payload"], "shape_digest": "a" * 64}})
    refused({**none, "payload": {**none["payload"], "shape": data["payload"]["shape"]}})
    refused({**none, "payload": {**none["payload"], "shape_status": "ok"}})
    assert ObservationEnvelope.model_validate({**none, "payload": {**none["payload"], "shape_status": "not_json"}})


def test_the_three_flags_are_required_booleans() -> None:
    for flag in ("has_stack_trace_markers", "has_debug_markers", "echoes_request_headers"):
        data = item("api_read", 1)
        del data["payload"]["flags"][flag]
        refused(data)
        data = item("api_read", 1)
        data["payload"]["flags"][flag] = "yes"
        refused(data)


def test_a_read_cannot_carry_a_body_or_an_artifact() -> None:
    for field, value in (
        ("body", {"size_bytes": 1}),
        ("artifact_sha256", "a" * 64),
        ("values", {"id": "x"}),
        ("text", "x"),
    ):
        refused(with_payload("api_read", 1, **{field: value}))


# --------------------------------------------------------------------------------------------- the spec ----
def test_a_spec_observation_holds_headers_and_a_bounded_inventory() -> None:
    assert ObservationEnvelope.model_validate(item("api_spec"))
    refused(with_payload("api_spec", http_status=600))
    refused(with_payload("api_spec", headers={"Bad Name": ["x"]}))
    data = item("api_spec")
    data["payload"]["body"]["parsed"] = {"k": "x" * 9000}
    refused(data)
    data = item("api_spec")
    data["payload"]["body"]["artifact_sha256"] = "short"
    refused(data)


# ------------------------------------------------------------------------------------------- options ----
def test_an_options_observation_has_an_origin_methods_and_cors_headers() -> None:
    for field, bad in (
        ("origin", "x" * 301),
        ("allow", ["get"]),
        ("allow", ["GE"]),
        ("allow", ["TOOLONGMETHODX"]),
        ("allow", ["GET"] * 13),
        ("allow", "GET"),
        ("endpoint_id", "X"),
        ("http_status", 700),
    ):
        refused(with_payload("api_options", **{field: bad}))
    for field, bad in (
        ("allow_origin", "x" * 256),
        ("allow_credentials", "x" * 17),
        ("allow_methods", "x" * 256),
        ("allow_headers", "x" * 1025),
        ("allow_origin", 5),
    ):
        data = item("api_options")
        data["payload"]["cors"][field] = bad
        refused(data)
    assert ObservationEnvelope.model_validate(with_payload("api_options", 1, cors=None, allow=[]))


def test_every_cors_field_must_be_present_even_when_empty() -> None:
    data = item("api_options")
    del data["payload"]["cors"]["allow_headers"]
    refused(data)
