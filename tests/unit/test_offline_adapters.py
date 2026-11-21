"""The offline adapters answered one entry at a time: every malformed or odd entry is a recorded error, never an empty success (AE-10, AE-13)."""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import pytest

from scopedagent.adapters.offline import (
    OfflineAiMetadata,
    OfflineAiProbe,
    OfflineDns,
    OfflineHttp,
    OfflineTls,
    build_adapters,
    error_result,
    normalized_input,
)
from scopedagent.adapters.pack import Pack
from scopedagent.domain.outcome import ErrorStatus
from scopedagent.pipeline.redact import REDACTED
from scopedagent.policy.scope import PlannedOperation, parse_scope
from tests.support import AI_PACK, NOW, assemble, scope_text

pytestmark = pytest.mark.milestone("M2")

HOST = "lab.example.invalid"
AI_HOST = "assistant.example.invalid"
HTTP_OP = PlannedOperation("http_metadata", HOST, "https", 443, "/")
DNS_OP = PlannedOperation("dns_metadata", HOST, "https", 443, None)
TLS_OP = PlannedOperation("tls_metadata", HOST, "https", 443, None)
META_OP = PlannedOperation("ai_metadata", AI_HOST, "https", 443, "/v1/models", "support-bot")
PROBE_OP = PlannedOperation(
    "ai_probe", AI_HOST, "https", 443, "/v1/chat/completions", "support-bot", "canary-echo-v1", 0
)
PROBE_KEY = "probe:support-bot:canary-echo-v1:0"
LIMIT = 100_000

CERT: dict[str, Any] = {
    "subject_cn": HOST,
    "issuer_cn": "Example Lab CA",
    "san_dns": [HOST],
    "not_before": "2026-06-01T00:00:00Z",
    "not_after": "2027-06-01T00:00:00Z",
    "signature_algorithm": "ecdsa-with-SHA256",
    "public_key": {"type": "ec", "bits": 256},
    "self_signed": False,
    "sha256_fingerprint": "f1ff2f8414b817f42594189efaf55017f2630cb4002194604b59e5ce41d0553b",
}


def pack_of(**sections: dict[str, dict[str, Any]]) -> Pack:
    return Pack(
        "t",
        sections.get("dns", {}),
        sections.get("tls", {}),
        sections.get("http", {}),
        sections.get("ai", {}),
        sections.get("api", {}),
    )


def http_entry(**fields: Any) -> dict[str, Any]:
    return {"status": 200, "headers": {"content-type": ["text/plain"]}, **fields}


def collect(adapter: Any, op: PlannedOperation) -> Any:
    return asyncio.run(adapter.collect(op))


def http(entry: dict[str, Any] | None, *, limit: int = LIMIT) -> Any:
    entries = {} if entry is None else {f"https://{HOST}:443/": entry}
    return collect(OfflineHttp(pack_of(http=entries), limit), HTTP_OP)


def status_of(result: Any) -> str:
    return str(
        result.envelope.error_status.value
        if hasattr(result.envelope.error_status, "value")
        else result.envelope.error_status
    )


# ------------------------------------------------------------------------------------------------ HTTP entries ----
@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (None, "adapter_error"),
        (http_entry(status=True), "parse_error"),
        (http_entry(status="200"), "parse_error"),
        (http_entry(status=99), "parse_error"),
        (http_entry(status=600), "parse_error"),
        ({"status": 200, "headers": ["content-type"]}, "parse_error"),
        ({"status": 200, "headers": {"content-type": "text/plain"}}, "parse_error"),
        ({"status": 200, "headers": {"content-type": [1]}}, "parse_error"),
        ({"status": 200, "headers": {1: ["x"]}}, "parse_error"),
        ({"status": 200, "headers": {"bad name": ["x"]}}, "parse_error"),
        (http_entry(body="a", body_base64="YQ=="), "parse_error"),
        (http_entry(body=5), "parse_error"),
        (http_entry(body_base64=5), "parse_error"),
        (http_entry(body_base64="not base64!!"), "parse_error"),
        (http_entry(error="timeout"), "timeout"),
        (http_entry(error="ok"), "parse_error"),
        (http_entry(error="nonsense"), "parse_error"),
    ],
)
def test_an_odd_http_entry_is_a_recorded_error(entry: dict[str, Any] | None, expected: str) -> None:
    assert status_of(http(entry)) == expected


def test_too_many_or_too_long_headers_are_a_size_limit_not_a_crash() -> None:
    many = {"status": 200, "headers": {f"x-h{i}": ["v"] for i in range(65)}}
    long_value = {"status": 200, "headers": {"x-long": ["v" * 4097]}}
    many_values = {"status": 200, "headers": {"x-multi": ["v"] * 65}}
    assert status_of(http(many)) == "size_limit"
    assert status_of(http(long_value)) == "size_limit"
    assert status_of(http(many_values)) == "size_limit"


def test_repeated_header_names_in_different_case_merge() -> None:
    result = http({"status": 200, "headers": {"X-Thing": ["a"], "x-thing": ["b"]}})
    assert result.envelope.payload.headers["x-thing"] == ["a", "b"]


def test_a_redirect_location_is_kept_only_for_a_redirect_status() -> None:
    redirect = http({"status": 301, "headers": {"location": ["https://lab.example.invalid/next"]}})
    plain = http({"status": 200, "headers": {"location": ["https://lab.example.invalid/next"]}})
    assert redirect.envelope.payload.redirect_location == "https://lab.example.invalid/next"
    assert plain.envelope.payload.redirect_location is None


def test_a_body_over_the_limit_is_cut_and_recorded_as_a_size_limit() -> None:
    result = http(http_entry(body="a" * 5000), limit=1024)
    assert status_of(result) == "size_limit"
    assert result.envelope.payload.body.truncated is True
    assert result.envelope.payload.body.size_bytes == 1024


def test_a_cut_inside_a_multibyte_character_still_stores_text() -> None:
    result = http(http_entry(body="é" * 2000), limit=1025)  # 1025 bytes ends in the middle of a character
    assert result.body_status == "redacted"
    assert result.body is not None


def test_a_body_that_is_not_text_is_a_placeholder_and_never_stored() -> None:
    result = http(http_entry(body_base64=base64.b64encode(bytes(range(128, 200))).decode()))
    assert result.body_status == "metadata_only"
    assert result.body == b"[binary content: 72 bytes, not stored]"
    assert result.body_mime == "text/plain"


def test_a_cut_binary_body_is_a_placeholder_too() -> None:
    result = http(http_entry(body_base64=base64.b64encode(b"\xff" * 5000).decode()), limit=1024)
    assert result.body_status == "metadata_only"


def test_a_compressed_body_is_never_decompressed() -> None:
    import gzip  # noqa: PLC0415

    zipped = gzip.compress(b"user-agent: *\ndisallow: /secret\n")
    entry = {"status": 200, "headers": {"content-encoding": ["gzip"]}, "body_base64": base64.b64encode(zipped).decode()}
    result = http(entry)
    assert result.body_status == "metadata_only"
    assert b"secret" not in (result.body or b"")


def test_an_identity_content_encoding_is_plain_text() -> None:
    result = http({"status": 200, "headers": {"content-encoding": ["identity"]}, "body": "hello"})
    assert result.body == b"hello"


def test_a_content_type_that_is_not_a_media_type_is_stored_as_octet_stream() -> None:
    result = http({"status": 200, "headers": {"content-type": ["not a media type"]}, "body": "hello"})
    assert result.body_mime == "application/octet-stream"


def test_a_document_that_does_not_parse_is_a_parse_error_with_the_body_still_stored() -> None:
    op = PlannedOperation("http_metadata", HOST, "https", 443, "/openapi.json")
    entries = {f"https://{HOST}:443/openapi.json": http_entry(body="{not json")}
    result = collect(OfflineHttp(pack_of(http=entries), LIMIT), op)
    assert status_of(result) == "parse_error"
    assert result.body == b"{not json"


def test_an_empty_body_is_not_a_stored_artifact() -> None:
    result = http(http_entry(body=""))
    assert result.body is None
    assert result.envelope.payload.body is None


# --------------------------------------------------------------------------------------------------- DNS and TLS ----
def dns(entry: dict[str, Any] | None) -> Any:
    entries = {} if entry is None else {HOST: entry}
    return collect(OfflineDns(pack_of(dns=entries)), DNS_OP)


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (None, "adapter_error"),
        ({"status": "weird", "records": {}}, "parse_error"),
        ({"status": "ok", "records": []}, "parse_error"),
        ({"status": "ok", "records": {"A": "192.0.2.1"}}, "parse_error"),
        ({"status": "ok", "records": {"A": [5]}}, "parse_error"),
        ({"status": "ok", "records": {"BOGUS": ["x"]}}, "parse_error"),
        ({"status": "ok", "records": {"A": ["x" * 300]}}, "parse_error"),
        ({"status": "timeout", "records": {}}, "timeout"),
        ({"status": "error", "records": {}}, "dns_failure"),
        ({"status": "nxdomain", "records": {}}, "ok"),
    ],
)
def test_a_dns_entry_is_answered_or_recorded_as_an_error(entry: dict[str, Any] | None, expected: str) -> None:
    assert status_of(dns(entry)) == expected


def test_dns_records_are_redacted_and_counted() -> None:
    token = assemble("gh", "p_", "A" * 36)
    result = dns({"status": "ok", "records": {"TXT": [f"v=x token={token}"]}})
    assert token not in json.dumps(result.envelope.payload.model_dump(mode="json"))
    assert result.redactions == 1


def tls(entry: dict[str, Any] | None) -> Any:
    entries = {} if entry is None else {f"{HOST}:443": entry}
    return collect(OfflineTls(pack_of(tls=entries)), TLS_OP)


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (None, "adapter_error"),
        ({"status": "weird"}, "parse_error"),
        ({"status": "ok", "version": "TLSv1.3", "certificate": "text"}, "parse_error"),
        ({"status": "ok", "version": "SSLv2", "certificate": CERT}, "parse_error"),
        ({"status": "ok", "version": "TLSv1.3", "certificate": {**CERT, "self_signed": "no"}}, "parse_error"),
        ({"status": "handshake_failed", "version": None, "certificate": None}, "tls_failure"),
        ({"status": "timeout", "version": None, "certificate": None}, "timeout"),
        ({"status": "error", "version": None, "certificate": None}, "adapter_error"),
        ({"status": "ok", "version": "TLSv1.3", "certificate": CERT}, "ok"),
    ],
)
def test_a_tls_entry_is_answered_or_recorded_as_an_error(entry: dict[str, Any] | None, expected: str) -> None:
    assert status_of(tls(entry)) == expected


def test_certificate_text_fields_are_redacted_and_counted() -> None:
    token = assemble("gh", "p_", "B" * 36)
    cert = {**CERT, "subject_cn": f"x token={token}", "san_dns": [HOST, f"y token={token}", 7]}
    result = tls({"status": "ok", "version": "TLSv1.3", "certificate": cert})
    # a non-string SAN entry is not valid, so the whole entry is a recorded parse error, never a crash
    assert status_of(result) == "parse_error"
    assert token not in json.dumps(result.envelope.payload.model_dump(mode="json"))
    assert token not in result.source_bytes.decode()


def test_a_certificate_subject_with_a_secret_is_redacted() -> None:
    token = assemble("gh", "p_", "E" * 36)
    cert = {**CERT, "subject_cn": f"x token={token}"}
    result = tls({"status": "ok", "version": "TLSv1.3", "certificate": cert})
    assert status_of(result) == "ok"
    assert result.redactions == 1
    assert token not in result.source_bytes.decode()


def test_certificate_san_names_are_redacted_and_counted() -> None:
    token = assemble("gh", "p_", "C" * 36)
    cert = {**CERT, "san_dns": [HOST, f"y token={token}"]}
    result = tls({"status": "ok", "version": "TLSv1.3", "certificate": cert})
    assert status_of(result) == "ok"
    assert result.redactions == 1
    assert token not in json.dumps(result.envelope.payload.model_dump(mode="json"))


# ------------------------------------------------------------------------------------------------- AI adapters ----
def reply(content: Any = "Sure. CANARY-1", **fields: Any) -> str:
    body = {
        "id": "x",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
    }
    body.update(fields)
    return json.dumps(body)


def probe_entry(**fields: Any) -> dict[str, Any]:
    return {"canary": "CANARY-1", "status": 200, "headers": {}, "body": reply(), **fields}


def probe(entry: dict[str, Any] | None, *, limit: int = LIMIT) -> Any:
    config = parse_scope(scope_text(AI_PACK), now=NOW).config
    entries = {} if entry is None else {PROBE_KEY: entry}
    return collect(OfflineAiProbe(pack_of(ai=entries), config, limit), PROBE_OP)


def test_a_probe_with_no_recorded_answer_is_an_adapter_error() -> None:
    assert status_of(probe(None)) == "adapter_error"


def test_a_probe_answer_is_summarised_and_the_canary_found() -> None:
    result = probe(probe_entry())
    payload = result.envelope.payload
    assert (payload.canary_present, payload.output_chars, payload.finish_reason) == (True, 14, "stop")
    assert (payload.input_tokens, payload.output_tokens) == (1, 2)
    assert result.body == b"Sure. CANARY-1"


def test_a_probe_without_a_canary_records_none_for_the_canary_fact() -> None:
    assert probe(probe_entry(canary=None)).envelope.payload.canary_present is None


def test_a_reply_without_the_canary_records_false() -> None:
    assert probe(probe_entry(body=reply("nothing here"))).envelope.payload.canary_present is False


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (probe_entry(status=500), "http_error"),
        (probe_entry(status=302), "http_error"),
        (probe_entry(canary=5), "parse_error"),
        (probe_entry(body="not json"), "parse_error"),
        (probe_entry(body=json.dumps({"choices": []})), "parse_error"),
        (probe_entry(body=None), "parse_error"),
        (probe_entry(body_base64=base64.b64encode(b"\xff\xfe\xfd").decode(), body=None), "parse_error"),
        (probe_entry(error="timeout"), "timeout"),
        (probe_entry(error="bogus"), "parse_error"),
        (probe_entry(status="200"), "parse_error"),
    ],
)
def test_an_odd_probe_answer_is_a_recorded_error(entry: dict[str, Any], expected: str) -> None:
    assert status_of(probe(entry)) == expected


def test_an_oversize_probe_reply_is_a_size_limit_and_nothing_is_stored() -> None:
    result = probe(probe_entry(body=reply("a" * 3000)), limit=1024)
    assert status_of(result) == "size_limit"
    assert result.body is None


def test_a_probe_reply_with_a_secret_is_redacted_before_it_is_stored() -> None:
    token = assemble("gh", "p_", "D" * 36)
    result = probe(probe_entry(body=reply(f"your token={token} CANARY-1")))
    assert token not in (result.body or b"").decode()
    assert result.redactions >= 1
    assert result.envelope.payload.canary_present is True


def test_an_empty_probe_reply_is_ok_with_no_artifact() -> None:
    result = probe(probe_entry(body=reply("")))
    assert status_of(result) == "ok"
    assert result.body is None
    assert result.envelope.payload.artifact_sha256 is None
    assert result.envelope.payload.output_chars == 0


def meta(entry: dict[str, Any] | None) -> Any:
    entries = {} if entry is None else {f"https://{AI_HOST}:443/v1/models": entry}
    return collect(OfflineAiMetadata(pack_of(ai=entries), LIMIT), META_OP)


def test_the_model_list_is_summarised() -> None:
    body = json.dumps({"object": "list", "data": [{"id": "m1"}, {"id": "m2"}]})
    result = meta({"status": 200, "headers": {"content-type": ["application/json"]}, "body": body})
    assert result.envelope.payload.model_ids == ["m1", "m2"]


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (None, "adapter_error"),
        ({"status": 200, "headers": {}, "error": "timeout"}, "timeout"),
        ({"status": "x"}, "parse_error"),
        ({"status": 200, "headers": {}, "body": "not json"}, "parse_error"),
        ({"status": 200, "headers": {}, "body": "a" * 5000}, "parse_error"),
    ],
)
def test_an_odd_model_list_is_a_recorded_error(entry: dict[str, Any] | None, expected: str) -> None:
    assert status_of(meta(entry)) == expected


def test_an_oversize_model_list_is_a_size_limit() -> None:
    entries = {f"https://{AI_HOST}:443/v1/models": {"status": 200, "headers": {}, "body": "a" * 3000}}
    result = collect(OfflineAiMetadata(pack_of(ai=entries), 1024), META_OP)
    assert status_of(result) == "size_limit"


# ------------------------------------------------------------------------------------------------ the helpers ----
@pytest.mark.parametrize(
    ("op", "status", "kind"),
    [
        (DNS_OP, ErrorStatus.TIMEOUT, "dns_metadata"),
        (DNS_OP, ErrorStatus.ADAPTER_ERROR, "dns_metadata"),
        (TLS_OP, ErrorStatus.TIMEOUT, "tls_metadata"),
        (TLS_OP, ErrorStatus.TLS_FAILURE, "tls_metadata"),
        (TLS_OP, ErrorStatus.ADAPTER_ERROR, "tls_metadata"),
        (HTTP_OP, ErrorStatus.PARSE_ERROR, "http_metadata"),
        (META_OP, ErrorStatus.SIZE_LIMIT, "ai_metadata"),
        (PROBE_OP, ErrorStatus.TIMEOUT, "ai_probe"),
    ],
)
def test_an_error_result_is_a_valid_observation_that_says_what_failed(
    op: PlannedOperation, status: ErrorStatus, kind: str
) -> None:
    result = error_result(op, status)
    assert result.envelope.observation_type == kind
    assert result.envelope.error_status == status
    assert result.body is None
    assert json.loads(result.source_bytes) == {"error": status.value, "input": normalized_input(op)}


def test_the_normalised_input_names_the_request() -> None:
    assert normalized_input(DNS_OP) == f"dns {HOST}"
    assert normalized_input(TLS_OP) == f"tls {HOST}:443"
    assert normalized_input(HTTP_OP) == f"GET https://{HOST}:443/"
    assert normalized_input(PROBE_OP) == "PROBE support-bot canary-echo-v1 0"


def test_one_adapter_per_operation_kind() -> None:
    config = parse_scope(scope_text(AI_PACK), now=NOW).config
    adapters = build_adapters(pack_of(), config)
    assert set(adapters) == {
        "dns_metadata",
        "tls_metadata",
        "http_metadata",
        "ai_metadata",
        "ai_probe",
        "api_spec",
        "api_read",
        "api_options",
    }
    assert all(adapters[kind].operation == kind for kind in adapters)


# ----------------------------------------------------------------------------------------- the safety nets ----
def test_a_certificate_missing_a_text_field_is_a_recorded_parse_error() -> None:
    cert = {k: v for k, v in CERT.items() if k != "issuer_cn"}
    assert status_of(tls({"status": "ok", "version": "TLSv1.3", "certificate": cert})) == "parse_error"


def test_a_certificate_whose_names_are_not_a_list_is_a_recorded_parse_error() -> None:
    cert = {**CERT, "san_dns": HOST}
    assert status_of(tls({"status": "ok", "version": "TLSv1.3", "certificate": cert})) == "parse_error"


def test_a_parser_that_returns_more_than_the_schema_allows_becomes_a_parse_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scopedagent.adapters.offline._parse_known", lambda path, text: {"x": "a" * 9000})
    assert status_of(http(http_entry(body="hello"))) == "parse_error"


def test_a_model_list_parser_that_returns_too_much_becomes_a_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scopedagent.adapters.offline.models_summary", lambda text: ([], {"x": "a" * 9000}))
    assert status_of(meta({"status": 200, "headers": {}, "body": "{}"})) == "parse_error"


def test_an_absurd_token_count_is_dropped_not_trusted() -> None:
    body = reply(usage={"prompt_tokens": 5_000_000, "completion_tokens": 1, "total_tokens": 5_000_001})
    payload = probe(probe_entry(body=body)).envelope.payload
    assert (payload.input_tokens, payload.output_tokens) == (None, 1)


def test_a_probe_reply_the_schema_refuses_becomes_a_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from scopedagent.adapters.parse import ChatReply  # noqa: PLC0415

    monkeypatch.setattr(
        "scopedagent.adapters.offline.chat_completion", lambda text, style: ChatReply("hi", "f" * 100, None, None)
    )
    assert status_of(probe(probe_entry())) == "parse_error"


def test_a_large_but_valid_robots_file_is_collected_not_refused() -> None:
    body = "User-agent: *\n" + "".join(f"Disallow: /{i:02d}/{'a' * 240}\n" for i in range(50))
    op = PlannedOperation("http_metadata", HOST, "https", 443, "/robots.txt")
    entries = {f"https://{HOST}:443/robots.txt": http_entry(body=body)}
    result = collect(OfflineHttp(pack_of(http=entries), LIMIT), op)
    assert status_of(result) == "ok"
    assert result.envelope.payload.body.parsed["disallow"]


def test_base64_with_stray_characters_is_refused_not_cleaned_up() -> None:
    assert status_of(http(http_entry(body_base64="YW Jj"))) == "parse_error"
    assert status_of(http(http_entry(body_base64="YWJj"))) == "ok"


def test_a_header_value_over_2048_characters_is_a_location_cut_short_not_a_failure() -> None:
    entry = {"status": 301, "headers": {"location": ["https://lab.example.invalid/" + "a" * 3000]}}
    result = http(entry)
    assert status_of(result) == "ok"
    assert len(result.envelope.payload.redirect_location) == 2048


def test_a_text_body_that_claims_to_be_compressed_is_not_trusted_as_text() -> None:
    result = http({"status": 200, "headers": {"content-encoding": ["gzip"]}, "body": "User-agent: *"})
    assert result.body_status == "metadata_only"
    assert b"User-agent" not in (result.body or b"")


def test_a_truncated_document_is_not_parsed() -> None:
    op = PlannedOperation("http_metadata", HOST, "https", 443, "/robots.txt")
    entries = {f"https://{HOST}:443/robots.txt": http_entry(body="User-agent: *\nDisallow: /x\n" * 200)}
    result = collect(OfflineHttp(pack_of(http=entries), 1024), op)
    assert status_of(result) == "size_limit"
    assert result.envelope.payload.body.parsed is None


def test_a_truncated_model_list_is_not_parsed() -> None:
    body = json.dumps({"object": "list", "data": [{"id": f"model-{i}"} for i in range(200)]})
    entries = {f"https://{AI_HOST}:443/v1/models": {"status": 200, "headers": {}, "body": body}}
    result = collect(OfflineAiMetadata(pack_of(ai=entries), 1024), META_OP)
    assert status_of(result) == "size_limit"
    assert result.envelope.payload.model_ids == [] and result.envelope.payload.body.parsed is None


def test_the_probe_reply_is_read_in_the_api_style_the_target_declares() -> None:
    from tests.support import ai_scope_dict, dump  # noqa: PLC0415

    data = ai_scope_dict()
    data["ai_targets"][0]["api_style"] = "messages"
    config = parse_scope(dump(data), now=NOW).config
    result = collect(OfflineAiProbe(pack_of(ai={PROBE_KEY: probe_entry()}), config, LIMIT), PROBE_OP)
    assert status_of(result) == "parse_error"


def test_the_source_of_an_observation_never_holds_a_secret_that_was_in_the_body() -> None:
    token = assemble("gh", "p_", "F" * 36)
    result = http(http_entry(body=f"secret token={token}"))
    assert token not in result.source_bytes.decode()
    assert REDACTED in result.source_bytes.decode()
