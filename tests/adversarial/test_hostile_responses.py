"""AE-06, AE-13, AE-20: a hostile response is data. It cannot widen the scope, crash a parser, forge structure or hide in a log."""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
import time
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from scopedagent.adapters.pack import load_pack
from scopedagent.domain.outcome import ExitCode
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.pipeline.orchestrator import execute_run
from scopedagent.policy.scope import parse_scope
from tests.support import (
    FIXTURES,
    NOW,
    artifact_hashes,
    dump,
    everything_stored,
    make_env,
    observation_rows,
    pack_variant,
    scope_dict,
    scope_text,
)

pytestmark = pytest.mark.milestone("M2")

HUMAN = Actor(ActorType.HUMAN, "alice")
HOST = "lab.example.invalid"
ROBOTS = f"https://{HOST}:443/robots.txt"
PAYLOADS = sorted((FIXTURES / "poisoned_text").glob("*.txt"))


@pytest.fixture
def env(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


def run(env: Any, path: Path, name: str = "healthy", scope: dict[str, Any] | None = None) -> Any:
    db, store, _ = env
    loaded = parse_scope(dump(scope) if scope else scope_text(name), now=NOW)
    return asyncio.run(execute_run(db, store, loaded=loaded, pack=load_pack(path), human=HUMAN, now=NOW))


def payload_of(env: Any, result: Any, index: int) -> dict[str, Any]:
    return json.loads(observation_rows(env[0], result.run_id)[index]["normalized_json"])  # type: ignore[no-any-return]


# ------------------------------------------------------------------------------------ the library ----
@pytest.mark.parametrize("payload_file", PAYLOADS, ids=lambda p: p.stem)
def test_every_injection_payload_is_kept_as_data_and_changes_nothing_else(
    env: Any, tmp_path: Path, payload_file: Path
) -> None:
    injection = " ".join(payload_file.read_text(encoding="utf-8").split())

    def edit(data: dict[str, Any]) -> None:
        data["http"][ROBOTS]["headers"]["x-injected"] = [injection]
        data["http"][ROBOTS]["body"] = f"User-agent: *\n# {injection}\nDisallow: /admin\n"
        data["dns"][HOST]["records"]["TXT"] = [injection[:255]]
        data["tls"][f"{HOST}:443"]["certificate"]["issuer_cn"] = injection[:255]
        data["http"][f"https://{HOST}:443/.well-known/security.txt"]["body"] = (
            f"Contact: {injection}\nExpires: 2027-06-01T00:00:00Z\n"
        )

    loaded = parse_scope(scope_text("healthy"), now=NOW)
    result = run(env, pack_variant(tmp_path, "healthy", edit))
    db, _, data_dir = env
    assert result.planned == 5 and result.coverage.complete and loaded.sha256
    assert result.exit_code is ExitCode.REVIEW  # the variant's robots.txt lists /admin, which a rule drafts about
    with db.begin() as session:
        assert session.execute(text("SELECT host_canonical FROM targets")).scalars().all() == [HOST]
        assert session.execute(text("SELECT count(*) FROM engagements")).scalar() == 1
        assert session.execute(text("SELECT count(*) FROM audit_events WHERE decision = 'denied'")).scalar() == 0
        scope_json = session.execute(text("SELECT scope_json FROM engagements")).scalar()
    assert (
        json.loads(scope_json)["allowed_targets"][0]["host"] == HOST
        and "10.0.0.5" not in scope_json
        and "evil.example.invalid" not in scope_json
    )
    assert injection[:30] in everything_stored(db, data_dir)  # evidence, recorded as it was


def test_the_unicode_tricks_in_header_values_and_parsed_fields_are_neutralised(env: Any, tmp_path: Path) -> None:
    tricks = chr(0x202E) + chr(0x200B) + chr(0x2060) + chr(0xE0041) + chr(0) + chr(0x1B) + chr(0x2028)

    def edit(data: dict[str, Any]) -> None:
        data["http"][ROBOTS]["headers"]["x-note"] = [f"before{tricks}after"]
        data["http"][f"https://{HOST}:443/.well-known/security.txt"]["body"] = (
            f"Contact: mailto:a{tricks}b@{HOST}\nExpires: 2027-06-01T00:00:00Z\n"
        )
        data["dns"][HOST]["records"]["TXT"] = [f"txt{tricks}value"]

    result = run(env, pack_variant(tmp_path, "healthy", edit))
    db, _, _ = env
    stored_json = " ".join(r["normalized_json"] for r in observation_rows(db, result.run_id))
    for char in tricks:
        assert char not in stored_json, hex(ord(char))
    assert "before" in stored_json and "after" in stored_json and result.exit_code is ExitCode.OK


def test_a_crlf_in_a_header_value_cannot_forge_another_header(env: Any, tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["http"][ROBOTS]["headers"]["x-note"] = ["a\r\nSet-Cookie: forged=1\r\nX-Other: y"]

    result = run(env, pack_variant(tmp_path, "healthy", edit))
    headers = payload_of(env, result, 4)["headers"]
    assert set(headers) == {
        "content-type",
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "server",
        "x-note",
    }
    assert "\r" not in headers["x-note"][0] and "\n" not in headers["x-note"][0]


# --------------------------------------------------------------------------------------- limits ----
def test_a_body_over_the_scope_limit_is_truncated_and_recorded_as_a_size_limit(env: Any, tmp_path: Path) -> None:
    data = scope_dict("healthy")
    data["max_response_bytes"] = 2048

    def edit(pack: dict[str, Any]) -> None:
        pack["http"][ROBOTS]["body"] = "User-agent: *\n" + "Disallow: /x\n" * 1000

    result = run(env, pack_variant(tmp_path, "healthy", edit), scope=data)
    body = payload_of(env, result, 4)["body"]
    row = observation_rows(env[0], result.run_id)[4]
    assert row["error_status"] == "size_limit" and body["truncated"] is True and body["size_bytes"] == 2048
    assert len(env[1].read(body["artifact_sha256"])) == 2048 and result.exit_code is ExitCode.INCOMPLETE


def test_a_body_exactly_at_the_limit_is_complete(env: Any, tmp_path: Path) -> None:
    data = scope_dict("healthy")
    data["max_response_bytes"] = 2048

    def edit(pack: dict[str, Any]) -> None:
        pack["http"][ROBOTS]["body"] = "User-agent: *\n" + "a" * (2048 - len("User-agent: *\n"))

    result = run(env, pack_variant(tmp_path, "healthy", edit), scope=data)
    assert (
        observation_rows(env[0], result.run_id)[4]["error_status"] == "ok"
        and payload_of(env, result, 4)["body"]["truncated"] is False
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h: h.update({f"x-h{i}": ["v"] for i in range(70)}),
        lambda h: h.update({"x-big": ["a" * 5000]}),
        lambda h: h.update({"x-many": ["v"] * 70}),
    ],
)
def test_a_response_whose_headers_break_the_caps_is_a_size_limit_not_a_crash(
    env: Any, tmp_path: Path, mutate: Any
) -> None:
    result = run(env, pack_variant(tmp_path, "healthy", lambda d: mutate(d["http"][ROBOTS]["headers"])))
    row = observation_rows(env[0], result.run_id)[4]
    assert (
        row["error_status"] == "size_limit"
        and json.loads(row["normalized_json"])["headers"] == {}
        and result.exit_code is ExitCode.INCOMPLETE
    )


def test_a_compressed_body_is_never_decompressed(env: Any, tmp_path: Path) -> None:
    bomb = gzip.compress(b"\0" * 50_000_000)  # about 50 KB that would expand to 50 MB

    def edit(pack: dict[str, Any]) -> None:
        entry = pack["http"][ROBOTS]
        entry.pop("body")
        entry["body_base64"] = base64.b64encode(bomb).decode()
        entry["headers"]["content-encoding"] = ["gzip"]

    started = time.monotonic()
    result = run(env, pack_variant(tmp_path, "healthy", edit))
    body = payload_of(env, result, 4)["body"]
    assert time.monotonic() - started < 5 and body["size_bytes"] == len(bomb) and result.exit_code is ExitCode.OK
    stored = env[1].read(body["artifact_sha256"])
    assert len(stored) < 200 and b"binary" in stored  # a placeholder, never the expanded bytes


def test_a_binary_body_is_recorded_by_size_and_hash_without_its_content(env: Any, tmp_path: Path) -> None:
    blob = bytes(range(256)) * 4

    def edit(pack: dict[str, Any]) -> None:
        entry = pack["http"][ROBOTS]
        entry.pop("body")
        entry["body_base64"] = base64.b64encode(blob).decode()
        entry["headers"]["content-type"] = ["application/octet-stream"]

    result = run(env, pack_variant(tmp_path, "healthy", edit))
    body = payload_of(env, result, 4)["body"]
    assert body["size_bytes"] == len(blob) and body["parsed"] is None
    with env[0].begin() as session:
        status = session.execute(
            text("SELECT redaction_status FROM artifacts WHERE sha256 = :s"), {"s": body["artifact_sha256"]}
        ).scalar()
    assert status == "metadata_only"


def test_a_deeply_nested_openapi_document_is_a_parse_error_not_a_crash(env: Any, tmp_path: Path) -> None:
    def edit(pack: dict[str, Any]) -> None:
        pack["http"][f"https://{HOST}:443/openapi.json"]["body"] = (
            '{"openapi": "3.0.0", "x": ' + "[" * 20_000 + "]" * 20_000 + "}"
        )

    result = run(env, pack_variant(tmp_path, "healthy", edit))
    assert (
        observation_rows(env[0], result.run_id)[3]["error_status"] == "parse_error"
        and result.exit_code is ExitCode.INCOMPLETE
    )


def test_pathological_text_in_a_body_is_processed_quickly(env: Any, tmp_path: Path) -> None:
    def edit(pack: dict[str, Any]) -> None:
        pack["http"][ROBOTS]["body"] = (
            ("token=" + "a" * 60_000) + ("@" * 5000) + ("eyJ" + "a" * 5000) + "\n"
        )  # under the 100 KB scope limit

    started = time.monotonic()
    result = run(env, pack_variant(tmp_path, "healthy", edit))
    assert time.monotonic() - started < 10 and result.exit_code is ExitCode.OK


def test_an_invalid_status_code_in_the_pack_is_a_parse_error_for_that_operation(env: Any, tmp_path: Path) -> None:
    def edit(pack: dict[str, Any]) -> None:
        pack["http"][ROBOTS]["status"] = 99

    result = run(env, pack_variant(tmp_path, "healthy", edit))
    assert [r["error_status"] for r in observation_rows(env[0], result.run_id)] == [
        "ok",
        "ok",
        "ok",
        "ok",
        "parse_error",
    ]


def test_a_redirect_is_recorded_with_its_target_as_data_and_nothing_is_contacted(env: Any, tmp_path: Path) -> None:
    result = run(env, FIXTURES / "web_responses" / "misconfigured.yaml", "misconfigured")
    payload = payload_of(env, result, 2)
    assert payload["http_status"] == 301 and payload["redirect_location"] == "http://localhost:8080/admin"
    with env[0].begin() as session:
        assert (
            session.execute(text("SELECT count(*) FROM targets")).scalar() == 1
        )  # the redirect target was never added anywhere


def test_a_cname_to_another_domain_is_recorded_and_never_becomes_a_target(env: Any) -> None:
    result = run(env, FIXTURES / "web_responses" / "misconfigured.yaml", "misconfigured")
    assert payload_of(env, result, 0)["records"]["CNAME"] == ["cdn.other.example.invalid"]
    with env[0].begin() as session:
        assert session.execute(text("SELECT host_canonical FROM targets")).scalars().all() == ["bad.example.invalid"]
        assert "cdn.other" not in " ".join(
            str(v) for r in session.execute(text("SELECT * FROM engagements")).all() for v in r
        )


def test_every_hostile_variant_leaves_a_verifiable_audit_chain_and_artifacts_that_match_their_hashes(
    env: Any, tmp_path: Path
) -> None:
    from scopedagent.storage.audit import verify_chain  # noqa: PLC0415

    injection = " ".join(PAYLOADS[0].read_text(encoding="utf-8").split())
    result = run(
        env,
        pack_variant(tmp_path, "healthy", lambda d: d["http"][ROBOTS].update(body=f"User-agent: *\n# {injection}\n")),
    )
    with env[0].begin() as session:
        verify_chain(session, result.run_id)
    for sha in artifact_hashes(env[0], result.run_id):
        env[1].read(sha)
