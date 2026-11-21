"""X-07 and AE-13: every golden conforms and round-trips exactly; hostile or oversized payloads are refused."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from scopedagent.domain.schemas import ObservationEnvelope
from tests.support import PACKS, golden

pytestmark = pytest.mark.milestone("M1")


@pytest.mark.parametrize("pack", PACKS)
def test_every_golden_observation_conforms_and_round_trips_exactly(pack: str) -> None:
    items = golden(pack)
    assert items, "a golden file is never empty"
    for item in items:
        envelope = ObservationEnvelope.model_validate(item)
        assert envelope.model_dump(mode="json") == item


def test_the_goldens_have_the_documented_counts_and_order() -> None:
    assert [len(golden(p)) for p in PACKS] == [5, 6, 5]
    for pack in PACKS:
        types = [i["observation_type"] for i in golden(pack)]
        assert types[:2] == ["dns_metadata", "tls_metadata"] and set(types[2:]) == {"http_metadata"}


def first(pack: str, kind: str) -> dict[str, Any]:
    return copy.deepcopy(next(i for i in golden(pack) if i["observation_type"] == kind))


def refuses(item: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ObservationEnvelope.model_validate(item)


@pytest.mark.parametrize("kind", ["dns_metadata", "tls_metadata", "http_metadata"])
def test_unknown_fields_are_refused_in_the_envelope_and_in_the_payload(kind: str) -> None:
    item = first("healthy", kind)
    item["surprise"] = 1
    refuses(item)
    item = first("healthy", kind)
    item["payload"]["surprise"] = 1
    refuses(item)


def test_the_adapter_must_match_the_observation_type() -> None:
    item = first("healthy", "dns_metadata")
    item["adapter"] = "offline_http"
    refuses(item)
    item = first("healthy", "http_metadata")
    item["observation_type"] = "dns_metadata"
    refuses(item)


def test_a_payload_of_the_wrong_shape_for_its_type_is_refused() -> None:
    item = first("healthy", "dns_metadata")
    item["payload"] = first("healthy", "http_metadata")["payload"]
    refuses(item)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(status="weird"),
        lambda p: p["records"].update(SRV=["x"]),
        lambda p: p["records"].update(A=[f"192.0.2.{i}" for i in range(33)]),
        lambda p: p["records"].update(TXT=["x" * 256]),
        lambda p: p.update(host="UPPER.example.invalid"),
        lambda p: p.update(host="*.example.invalid"),
    ],
)
def test_dns_payload_limits(mutate: Any) -> None:
    item = first("healthy", "dns_metadata")
    mutate(item["payload"])
    refuses(item)


def test_dns_payload_limits_accept_the_boundary() -> None:
    item = first("healthy", "dns_metadata")
    item["payload"]["records"].update(A=[f"192.0.2.{i}" for i in range(32)], TXT=["x" * 255])
    ObservationEnvelope.model_validate(item)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(port=0),
        lambda p: p.update(port=65536),
        lambda p: p.update(tls_version="SSLv3"),
        lambda p: p.update(status="ok-ish"),
        lambda p: p["certificate"].update(public_key={"type": "magic", "bits": 1}),
        lambda p: p["certificate"].update(public_key={"type": "rsa", "bits": -1}),
        lambda p: p["certificate"].update(sha256_fingerprint="xyz"),
        lambda p: p["certificate"].update(not_before="2026-06-01T00:00:00"),  # naive
        lambda p: p["certificate"].update(san_dns=["x"] * 101),
    ],
)
def test_tls_payload_limits(mutate: Any) -> None:
    item = first("healthy", "tls_metadata")
    mutate(item["payload"])
    refuses(item)


def test_a_failed_handshake_has_no_certificate_and_no_version() -> None:
    item = first("healthy", "tls_metadata")
    item["error_status"] = "tls_failure"
    item["payload"].update(status="handshake_failed", tls_version=None, certificate=None)
    envelope = ObservationEnvelope.model_validate(item)
    assert envelope.model_dump(mode="json")["payload"]["certificate"] is None


def http_item() -> dict[str, Any]:
    return first("healthy", "http_metadata")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(method="POST"),
        lambda p: p.update(method="get"),
        lambda p: p.update(http_status=99),
        lambda p: p.update(http_status=600),
        lambda p: p.update(path="no-slash"),
        lambda p: p.update(path="/a?b=1"),
        lambda p: p.update(scheme="ftp"),
        lambda p: p.update(port=0),
        lambda p: p["headers"].update({"Bad-Case": ["x"]}),
        lambda p: p["headers"].update({"bad header": ["x"]}),
        lambda p: p["headers"].update({"x-long": ["a" * 4097]}),
        lambda p: p.update(headers={f"h{i}": ["v"] for i in range(65)}),
        lambda p: p["headers"].update({"x-many": ["v"] * 65}),
        lambda p: p["body"].update(size_bytes=-1),
        lambda p: p["body"].update(size_bytes=2_000_001),
        lambda p: p["body"].update(artifact_sha256="not-a-hash"),
        lambda p: p["body"].update(parsed={"a": {"b": {"c": {"d": {"e": 1}}}}}),
        lambda p: p["body"].update(parsed={f"k{i}": 1 for i in range(65)}),
        lambda p: p["body"].update(parsed={"k": "x" * 9000}),
        lambda p: p.update(redirect_location="x" * 2049),
    ],
)
def test_http_payload_limits(mutate: Any) -> None:
    item = http_item()
    mutate(item["payload"])
    refuses(item)


def test_http_payload_limits_accept_the_boundary() -> None:
    item = http_item()
    item["payload"]["headers"] = {f"h{i}": ["v"] for i in range(64)}
    item["payload"]["headers"]["x-edge"] = ["a" * 4096]
    del item["payload"]["headers"]["h0"]
    item["payload"]["body"]["size_bytes"] = 2_000_000
    ObservationEnvelope.model_validate(item)


def test_an_error_observation_is_valid_and_carries_its_status() -> None:
    item = http_item()
    item["error_status"] = "timeout"
    item["payload"].update(http_status=None, headers={}, redirect_location=None, body=None)
    assert ObservationEnvelope.model_validate(item).error_status.value == "timeout"


def test_an_unknown_error_status_is_refused() -> None:
    item = http_item()
    item["error_status"] = "clean"
    refuses(item)


def test_the_target_is_canonical() -> None:
    for bad in (
        {"host": "UPPER.example.invalid", "scheme": "https", "port": 443},
        {"host": "lab.example.invalid", "scheme": "ftp", "port": 443},
        {"host": "lab.example.invalid", "scheme": "https", "port": 0},
    ):
        item = http_item()
        item["target"] = bad
        refuses(item)


def test_json_that_is_not_an_object_is_refused() -> None:
    for bad in ("[]", '"text"', "5", "null"):
        with pytest.raises(ValidationError):
            ObservationEnvelope.model_validate_json(bad)


def test_the_models_are_immutable() -> None:
    envelope = ObservationEnvelope.model_validate(json.loads(json.dumps(http_item())))
    with pytest.raises(ValidationError):
        envelope.error_status = "ok"  # type: ignore[assignment]


@pytest.mark.parametrize(
    "bad", ["a" * 64 + "\n", "\n" + "a" * 64, "a" * 64 + " ", "A" * 64, "a" * 63, "a" * 65, "g" * 64]
)
def test_a_sha256_is_exactly_64_lower_case_hex_digits_with_nothing_around_it(bad: str) -> None:
    item = http_item()
    item["payload"]["body"]["artifact_sha256"] = bad
    refuses(item)
    cert = first("healthy", "tls_metadata")
    cert["payload"]["certificate"]["sha256_fingerprint"] = bad
    refuses(cert)


def test_a_body_may_have_no_parsed_document() -> None:
    item = http_item()
    item["payload"]["body"]["parsed"] = None
    assert ObservationEnvelope.model_validate(item).model_dump(mode="json")["payload"]["body"]["parsed"] is None


def test_an_unknown_observation_type_is_refused() -> None:
    item = first("healthy", "dns_metadata")
    item["observation_type"] = "port_scan"
    refuses(item)


def test_a_payload_object_of_the_wrong_kind_is_refused_even_when_built_directly() -> None:
    from scopedagent.domain.schemas import DnsPayload, HttpPayload  # noqa: PLC0415

    http = HttpPayload.model_validate(first("healthy", "http_metadata")["payload"])
    item = first("healthy", "dns_metadata")
    item["payload"] = http
    refuses(item)
    dns = DnsPayload.model_validate(first("healthy", "dns_metadata")["payload"])
    item = first("healthy", "http_metadata")
    item["payload"] = dns
    refuses(item)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda i: i["payload"].update(port="443"),
        lambda i: i["payload"].update(http_status="200"),
        lambda i: i["payload"].update(headers={"x": "not-a-list"}),
        lambda i: i["payload"]["body"].update(size_bytes="10"),
        lambda i: i["payload"]["body"].update(truncated="false"),
        lambda i: i["target"].update(port="443"),
    ],
)
def test_values_of_the_wrong_type_are_refused_not_coerced(mutate: Any) -> None:
    item = http_item()
    mutate(item)
    refuses(item)


def test_the_models_do_not_coerce_numbers_in_other_payloads_either() -> None:
    tls = first("healthy", "tls_metadata")
    tls["payload"]["port"] = "443"
    refuses(tls)
    cert = first("healthy", "tls_metadata")
    cert["payload"]["certificate"]["self_signed"] = "false"
    refuses(cert)


def test_a_parsed_document_is_bounded_inside_lists_too() -> None:
    deep_in_a_list = {"a": [{"b": {"c": {"d": {"e": 1}}}}]}
    wide_in_a_list = {"a": [{f"k{i}": 1 for i in range(65)}]}
    for parsed in (deep_in_a_list, wide_in_a_list):
        item = http_item()
        item["payload"]["body"]["parsed"] = parsed
        refuses(item)


@pytest.mark.parametrize("title", ["abcd", "abc", "", "x" * 161])
def test_a_draft_title_must_be_5_to_160_characters(title: str) -> None:
    from scopedagent.domain.schemas import FindingDraftCreate  # noqa: PLC0415

    with pytest.raises(ValidationError):
        FindingDraftCreate.model_validate({"title": title, "category": "headers", "confidence": 0.5})
    FindingDraftCreate.model_validate({"title": "abcde", "category": "headers", "confidence": 0.5})
    FindingDraftCreate.model_validate({"title": "x" * 160, "category": "headers", "confidence": 0.5})


def test_a_draft_input_does_not_coerce_its_numbers() -> None:
    from scopedagent.domain.schemas import FindingDraftCreate  # noqa: PLC0415

    with pytest.raises(ValidationError):
        FindingDraftCreate.model_validate({"title": "Missing headers", "category": "headers", "confidence": "0.5"})
