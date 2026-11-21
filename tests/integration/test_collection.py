"""M2: a scope and a fixture pack become stored observations. The goldens are the oracle; nothing here asks the code what it thinks."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from scopedagent.adapters.pack import load_pack
from scopedagent.pipeline.orchestrator import RunResult, execute_run
from sqlalchemy import select, text

from scopedagent.domain.models import AuditEvent, Run
from scopedagent.domain.outcome import ExitCode
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, PolicyError, ScopeError
from scopedagent.policy.scope import LoadedScope, parse_scope
from scopedagent.storage.audit import verify_chain
from tests.support import (
    AI_PACK,
    FIXTURES,
    NOW,
    PACKS,
    artifact_hashes,
    dump,
    everything_stored,
    golden,
    make_env,
    observation_rows,
    pack,
    pack_variant,
    scope_dict,
    scope_text,
)

pytestmark = pytest.mark.milestone("M2")

HUMAN = Actor(ActorType.HUMAN, "alice")
ALL = [(name, f"{name}") for name in PACKS] + [(AI_PACK, AI_PACK)]


@pytest.fixture
def env(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


def scope_for(name: str) -> LoadedScope:
    return parse_scope(scope_text(name), now=NOW)


def run(
    env: Any, name: str, pack_path: Path | None = None, *, loaded: LoadedScope | None = None, **kw: Any
) -> RunResult:
    db, store, _ = env
    the_pack = load_pack(pack_path or FIXTURES / "web_responses" / f"{name}.yaml")
    return asyncio.run(
        execute_run(db, store, loaded=loaded or scope_for(name), pack=the_pack, human=HUMAN, now=NOW, **kw)
    )


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------------------ the goldens are reproduced ----
@pytest.mark.parametrize(("scope_name", "pack_name"), ALL)
def test_each_pack_reproduces_its_golden_observations_exactly_and_in_plan_order(
    env: Any, scope_name: str, pack_name: str
) -> None:
    result = run(env, scope_name)
    db, _, _ = env
    rows, expected = observation_rows(db, result.run_id), golden(pack_name)
    assert len(rows) == len(expected) == result.planned
    for row, item in zip(rows, expected, strict=True):
        assert (row["adapter"], row["observation_type"], row["error_status"]) == (
            item["adapter"],
            item["observation_type"],
            item["error_status"],
        )
        assert (row["host_canonical"], row["scheme"], row["port"]) == (
            item["target"]["host"],
            item["target"]["scheme"],
            item["target"]["port"],
        )
        assert row["normalized_input_hash"] == hashlib.sha256(item["normalized_input"].encode()).hexdigest()
        assert json.loads(row["normalized_json"]) == item["payload"] and row["normalized_json"] == canonical(
            item["payload"]
        )


@pytest.mark.parametrize(("scope_name", "pack_name"), ALL)
def test_the_stored_artifacts_are_exactly_the_goldens_artifacts(env: Any, scope_name: str, pack_name: str) -> None:
    result = run(env, scope_name)
    db, store, _ = env
    wanted = {i["payload"]["body"]["artifact_sha256"] for i in golden(pack_name) if i["payload"].get("body")}
    wanted |= {i["payload"]["artifact_sha256"] for i in golden(pack_name) if i["observation_type"] == "ai_probe"}
    assert artifact_hashes(db, result.run_id) == wanted
    for sha in wanted:
        assert hashlib.sha256(store.read(sha)).hexdigest() == sha


@pytest.mark.parametrize(
    ("scope_name", "expected"), [("healthy", 0), ("misconfigured", 2), ("poisoned", 1), (AI_PACK, 0)]
)
def test_the_number_of_redactions_is_reported(env: Any, scope_name: str, expected: int) -> None:
    assert run(env, scope_name).redactions == expected


@pytest.mark.parametrize(("scope_name", "pack_name"), ALL)
def test_a_complete_collection_ends_drafted_with_exit_zero_and_a_verified_audit_chain(
    env: Any, scope_name: str, pack_name: str
) -> None:
    result = run(env, scope_name)
    db, _, _ = env
    assert (
        result.state == "DRAFTED" and result.exit_code is ExitCode.OK and result.coverage.complete and not result.failed
    )
    with db.begin() as session:
        run_row = session.get(Run, result.run_id)
        assert (
            run_row is not None
            and run_row.budget_spent == result.planned
            and run_row.started_at == NOW
            and run_row.created_by == "alice"
        )
        assert (
            verify_chain(session, result.run_id) >= 2 * result.planned
        )  # a transition and an event per observation, and more
        actions = [
            e.action
            for e in session.scalars(
                select(AuditEvent).where(AuditEvent.run_id == result.run_id).order_by(AuditEvent.id)
            )
        ]
        assert actions.count("observation.recorded") == len(golden(pack_name))


def test_observations_record_the_collection_time_and_a_source_hash_of_the_redacted_entry(env: Any) -> None:
    result = run(env, "healthy")
    db, _, _ = env
    rows = observation_rows(db, result.run_id)
    entry = pack("healthy")["dns"]["lab.example.invalid"]
    assert (
        rows[0]["source_hash"]
        == hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    assert all(r["collected_at"] == "2026-11-20T12:00:00.000000Z" for r in rows)


def test_the_source_hash_never_depends_on_a_secret_that_was_removed(env: Any, tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["http"]["https://bad.example.invalid:443/"]["headers"]["set-cookie"] = [
            "session=DIFFERENT-COOKIE-VALUE; Path=/"
        ]

    first = run(env, "misconfigured")
    second = run(env, "misconfigured", pack_variant(tmp_path, "misconfigured", edit))
    db, _, _ = env
    a, b = observation_rows(db, first.run_id), observation_rows(db, second.run_id)
    root = next(i for i, r in enumerate(a) if r["normalized_json"].find('"path":"/"') >= 0)
    assert (
        a[root]["source_hash"] == b[root]["source_hash"]
    )  # only the redacted form is hashed, so a changed cookie value is invisible


def test_artifacts_are_stored_redacted_with_the_default_retention(env: Any) -> None:
    result = run(env, "healthy")
    db, _, _ = env
    with db.begin() as session:
        rows = session.execute(
            text("SELECT redaction_status, retention_until, mime FROM artifacts WHERE run_id = :r"),
            {"r": result.run_id},
        ).all()
    assert {r[0] for r in rows} == {"redacted"} and {r[1] for r in rows} == {"2026-12-20T12:00:00.000000Z"}
    assert {r[2] for r in rows} == {"text/plain", "application/json"}


# ------------------------------------------------------------------------------------ determinism ----
@pytest.mark.parametrize(("scope_name", "pack_name"), ALL)
def test_two_runs_of_the_same_scope_and_pack_are_identical_apart_from_their_ids(
    env: Any, scope_name: str, pack_name: str
) -> None:
    first, second = run(env, scope_name), run(env, scope_name)
    db, _, data_dir = env
    assert first.run_id != second.run_id
    assert observation_rows(db, first.run_id) == observation_rows(db, second.run_id)  # every column, including the time
    assert artifact_hashes(db, first.run_id) == artifact_hashes(db, second.run_id)
    files = [p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()]
    assert len(files) == len(artifact_hashes(db, first.run_id))  # one file per content, shared by both runs


# ----------------------------------------------------------------------------------------- budget ----
def test_a_budget_exactly_the_size_of_the_plan_is_complete(env: Any) -> None:
    data = scope_dict("healthy")
    data["max_requests"] = 5
    result = run(env, "healthy", loaded=parse_scope(dump(data), now=NOW))
    assert result.coverage.complete and result.exit_code is ExitCode.OK


def test_a_smaller_budget_records_the_rest_as_budget_exhausted_and_the_run_is_incomplete(env: Any) -> None:
    data = scope_dict("healthy")
    data["max_requests"] = 3
    result = run(env, "healthy", loaded=parse_scope(dump(data), now=NOW))
    db, _, _ = env
    statuses = [r["error_status"] for r in observation_rows(db, result.run_id)]
    assert statuses == ["ok", "ok", "ok", "budget_exhausted", "budget_exhausted"]
    assert result.exit_code is ExitCode.INCOMPLETE and not result.coverage.complete and result.state == "DRAFTED"
    with db.begin() as session:
        run_row = session.get(Run, result.run_id)
        assert run_row is not None and run_row.budget_spent == 3 == run_row.total_budget


def test_an_exhausted_budget_leaves_denials_in_the_audit_trail_and_a_valid_error_payload(env: Any) -> None:
    data = scope_dict("healthy")
    data["max_requests"] = 4
    result = run(env, "healthy", loaded=parse_scope(dump(data), now=NOW))
    db, _, _ = env
    last = observation_rows(db, result.run_id)[-1]
    assert last["error_status"] == "budget_exhausted" and json.loads(last["normalized_json"])["http_status"] is None
    with db.begin() as session:
        assert [e.action for e in session.scalars(select(AuditEvent).where(AuditEvent.decision == "denied"))] == [
            "budget.reserve"
        ]
        verify_chain(session, result.run_id)


# -------------------------------------------------------------------------------------- failures ----
def test_an_operation_the_pack_does_not_answer_is_a_recorded_error_never_an_empty_success(
    env: Any, tmp_path: Path
) -> None:
    def edit(data: dict[str, Any]) -> None:
        del data["http"]["https://lab.example.invalid:443/openapi.json"]

    result = run(env, "healthy", pack_variant(tmp_path, "healthy", edit))
    db, _, _ = env
    rows = observation_rows(db, result.run_id)
    assert [r["error_status"] for r in rows] == ["ok", "ok", "ok", "adapter_error", "ok"]
    payload = json.loads(rows[3]["normalized_json"])
    assert (
        payload["path"] == "/openapi.json"
        and payload["http_status"] is None
        and payload["headers"] == {}
        and payload["body"] is None
    )
    assert result.exit_code is ExitCode.INCOMPLETE and result.coverage.by_status


@pytest.mark.parametrize(
    ("section", "key", "change", "expected"),
    [
        ("dns", "lab.example.invalid", {"status": "timeout", "records": {}}, "timeout"),
        ("dns", "lab.example.invalid", {"status": "error", "records": {}}, "dns_failure"),
        ("dns", "lab.example.invalid", {"status": "nxdomain", "records": {}}, "ok"),
        ("dns", "lab.example.invalid", {"status": "no_data", "records": {}}, "ok"),
        ("tls", "lab.example.invalid:443", {"status": "handshake_failed"}, "tls_failure"),
        ("tls", "lab.example.invalid:443", {"status": "timeout"}, "timeout"),
        ("tls", "lab.example.invalid:443", {"status": "error"}, "adapter_error"),
        ("http", "https://lab.example.invalid:443/robots.txt", {"error": "timeout"}, "timeout"),
        ("http", "https://lab.example.invalid:443/robots.txt", {"error": "http_error"}, "http_error"),
        ("http", "https://lab.example.invalid:443/robots.txt", {"error": "refused_by_policy"}, "refused_by_policy"),
    ],
)
def test_a_failing_answer_in_the_pack_becomes_the_matching_error_status(
    env: Any, tmp_path: Path, section: str, key: str, change: dict[str, Any], expected: str
) -> None:
    def edit(data: dict[str, Any]) -> None:
        data[section][key] = change

    result = run(env, "healthy", pack_variant(tmp_path, "healthy", edit))
    db, _, _ = env
    statuses = [r["error_status"] for r in observation_rows(db, result.run_id)]
    assert expected in statuses
    assert (result.exit_code is ExitCode.OK) == (expected == "ok")


def test_a_malformed_certificate_is_a_parse_error_for_that_operation_only(env: Any, tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["tls"]["lab.example.invalid:443"]["certificate"]["not_after"] = "next tuesday"

    result = run(env, "healthy", pack_variant(tmp_path, "healthy", edit))
    db, _, _ = env
    assert [r["error_status"] for r in observation_rows(db, result.run_id)] == ["ok", "parse_error", "ok", "ok", "ok"]
    assert result.exit_code is ExitCode.INCOMPLETE


def test_a_parse_failure_in_a_known_document_is_recorded_with_its_artifact_kept(env: Any, tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["http"]["https://lab.example.invalid:443/openapi.json"]["body"] = "{ this is not json"

    result = run(env, "healthy", pack_variant(tmp_path, "healthy", edit))
    db, _, _ = env
    row = observation_rows(db, result.run_id)[3]
    payload = json.loads(row["normalized_json"])
    assert row["error_status"] == "parse_error" and payload["http_status"] == 200 and payload["body"]["parsed"] is None
    assert payload["body"]["artifact_sha256"] in artifact_hashes(db, result.run_id)


def test_a_crashing_adapter_fails_the_run_keeps_what_was_collected_and_does_not_echo_the_error(env: Any) -> None:
    class Boom:
        name, operation = "offline_tls", "tls_metadata"

        async def collect(self, operation: Any) -> Any:
            raise RuntimeError("SYNTHETIC-SECRET-IN-AN-EXCEPTION")

    db, store, data_dir = env
    from scopedagent.adapters.offline import build_adapters  # noqa: PLC0415

    loaded = scope_for("healthy")
    adapters = build_adapters(load_pack(FIXTURES / "web_responses" / "healthy.yaml"), loaded.config)
    adapters["tls_metadata"] = Boom()
    result = asyncio.run(
        execute_run(
            db,
            store,
            loaded=loaded,
            pack=load_pack(FIXTURES / "web_responses" / "healthy.yaml"),
            human=HUMAN,
            now=NOW,
            adapters=adapters,
        )
    )
    assert result.failed and result.state == "FAILED" and result.exit_code is ExitCode.INCOMPLETE
    assert len(observation_rows(db, result.run_id)) == 1  # the DNS observation before the crash
    assert "SYNTHETIC-SECRET-IN-AN-EXCEPTION" not in everything_stored(db, data_dir)
    with db.begin() as session:
        run_row = session.get(Run, result.run_id)
        assert run_row is not None and run_row.error_code == "unexpected_error"
        verify_chain(session, result.run_id)


def test_cancelling_mid_run_keeps_the_audit_trail_and_a_fresh_run_completes(env: Any) -> None:
    class Cancel:
        name, operation = "offline_tls", "tls_metadata"

        async def collect(self, operation: Any) -> Any:
            raise asyncio.CancelledError

    db, store, _ = env
    from scopedagent.adapters.offline import build_adapters  # noqa: PLC0415

    loaded, the_pack = scope_for("healthy"), load_pack(FIXTURES / "web_responses" / "healthy.yaml")
    adapters = build_adapters(the_pack, loaded.config)
    adapters["tls_metadata"] = Cancel()
    cancelled = asyncio.run(
        execute_run(db, store, loaded=loaded, pack=the_pack, human=HUMAN, now=NOW, adapters=adapters)
    )
    assert (
        cancelled.state == "CANCELED"
        and cancelled.exit_code is ExitCode.INCOMPLETE
        and len(observation_rows(db, cancelled.run_id)) == 1
    )
    with db.begin() as session:
        verify_chain(session, cancelled.run_id)
        run_row = session.get(Run, cancelled.run_id)
        assert run_row is not None and run_row.ended_at == NOW
    again = run(env, "healthy")
    assert again.state == "DRAFTED" and again.run_id != cancelled.run_id and again.coverage.complete


# --------------------------------------------------------------------------------- refusals first ----
def test_a_live_scope_is_refused_before_anything_is_stored(env: Any) -> None:
    data = scope_dict("healthy")
    data["mode"] = "live"
    db, _, _ = env
    with pytest.raises(PolicyError) as caught:
        run(env, "healthy", loaded=parse_scope(dump(data), now=NOW))
    assert caught.value.code is ErrorCode.POLICY_001
    with db.begin() as session:
        assert [
            session.execute(text(f"SELECT count(*) FROM {t}")).scalar()
            for t in ("engagements", "runs", "observations", "artifacts")
        ] == [0, 0, 0, 0]


def test_a_scope_that_expired_after_it_was_loaded_is_refused_before_anything_is_stored(env: Any) -> None:
    loaded = scope_for("healthy")
    db, store, _ = env
    with pytest.raises(ScopeError) as caught:
        asyncio.run(
            execute_run(
                db,
                store,
                loaded=loaded,
                pack=load_pack(FIXTURES / "web_responses" / "healthy.yaml"),
                human=HUMAN,
                now=loaded.config.expires_at,
            )
        )
    assert caught.value.code is ErrorCode.SCOPE_004
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM runs")).scalar() == 0


def test_only_a_human_may_start_a_collection(env: Any) -> None:
    db, store, _ = env
    from scopedagent.errors import StateError  # noqa: PLC0415

    with pytest.raises(StateError):
        asyncio.run(
            execute_run(
                db,
                store,
                loaded=scope_for("healthy"),
                pack=load_pack(FIXTURES / "web_responses" / "healthy.yaml"),
                human=Actor(ActorType.MODEL, "model-x"),
                now=NOW,
            )
        )


# ----------------------------------------------------------------------------- nothing leaks ----
def test_a_secret_in_a_header_a_body_and_a_reply_is_stored_nowhere(env: Any, tmp_path: Path) -> None:
    jwt = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "dummysig" + "natureXYZ12"])
    token = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"

    def edit(data: dict[str, Any]) -> None:
        data["http"]["https://lab.example.invalid:443/robots.txt"]["body"] = (
            f"User-agent: *\n# debug token={jwt}\nDisallow: /admin\n"
        )
        data["http"]["https://lab.example.invalid:443/robots.txt"]["headers"]["x-trace"] = [f"Bearer {token}"]
        data["http"]["https://lab.example.invalid:443/robots.txt"]["headers"]["authorization"] = [
            "Basic " + "dXNlcjpwYXNzd29yZA=="
        ]

    result = run(env, "healthy", pack_variant(tmp_path, "healthy", edit))
    db, _, data_dir = env
    stored = everything_stored(db, data_dir)
    assert jwt not in stored and token not in stored and "dXNlcjpwYXNzd29yZA==" not in stored
    assert result.redactions >= 3 and "[REDACTED]" in stored


def test_an_ai_reply_with_a_secret_is_stored_redacted_but_its_length_is_the_length_received(
    env: Any, tmp_path: Path
) -> None:
    secret = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    reply = f"Sure. CANARY-5A1E9C02 {secret}"

    def edit(data: dict[str, Any]) -> None:
        body = json.loads(data["ai"]["probe:support-bot:canary-echo-v1:0"]["body"])
        body["choices"][0]["message"]["content"] = reply
        data["ai"]["probe:support-bot:canary-echo-v1:0"]["body"] = json.dumps(body)

    result = run(env, AI_PACK, pack_variant(tmp_path, AI_PACK, edit))
    db, store, data_dir = env
    payload = json.loads(observation_rows(db, result.run_id)[1]["normalized_json"])
    assert secret not in everything_stored(db, data_dir)
    assert payload["output_chars"] == len(reply) and payload["canary_present"] is True
    assert store.read(payload["artifact_sha256"]).decode() == "Sure. CANARY-5A1E9C02 [REDACTED]"


def test_an_email_at_another_domain_is_redacted_but_the_targets_own_contact_is_kept(env: Any, tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["http"]["https://lab.example.invalid:443/.well-known/security.txt"]["body"] = (
            "Contact: mailto:security@lab.example.invalid\nContact: mailto:jane.doe@staff.example.invalid\nExpires: 2027-06-01T00:00:00Z\n"
        )

    result = run(env, "healthy", pack_variant(tmp_path, "healthy", edit))
    db, _, data_dir = env
    stored = everything_stored(db, data_dir)
    assert "security@lab.example.invalid" in stored and "jane.doe@" not in stored
    contact = json.loads(observation_rows(db, result.run_id)[2]["normalized_json"])["body"]["parsed"]["contact"]
    assert contact == ["mailto:security@lab.example.invalid", "mailto:[REDACTED]"]


def test_the_poisoned_pack_changes_nothing_but_its_own_observations(env: Any) -> None:
    loaded = scope_for("poisoned")
    before = loaded.sha256
    result = run(env, "poisoned", loaded=loaded)
    db, _, data_dir = env
    assert (
        loaded.sha256 == before and result.planned == 5 and result.coverage.complete and result.exit_code is ExitCode.OK
    )
    with db.begin() as session:
        targets = session.execute(text("SELECT host_canonical FROM targets")).scalars().all()
        scopes = session.execute(text("SELECT scope_sha256, scope_json FROM engagements")).all()
        assert targets == ["poison.example.invalid"] and [s[0] for s in scopes] == [before]
        assert session.execute(text("SELECT count(*) FROM audit_events WHERE decision = 'denied'")).scalar() == 0
        for table in ("targets", "engagements", "runs"):
            rows = " ".join(str(v) for r in session.execute(text(f"SELECT * FROM {table}")).all() for v in r)
            assert (
                "10.0.0.5" not in rows
                and "evil.example.invalid" not in rows
                and "collector.example.invalid" not in rows
            )
    assert "ignore all previous instructions" in everything_stored(db, data_dir)  # kept as evidence, as data


def test_the_audit_trail_of_a_collection_holds_only_the_expected_kinds_of_event(env: Any) -> None:
    result = run(env, "misconfigured")
    db, _, _ = env
    with db.begin() as session:
        actions = {e.action for e in session.scalars(select(AuditEvent).where(AuditEvent.run_id == result.run_id))}
    assert actions == {"run.created", "run.transition", "observation.recorded", "artifact.stored"}


def test_the_ai_scope_run_uses_only_ai_targets(env: Any) -> None:
    result = run(env, AI_PACK)
    db, _, _ = env
    assert {r["kind"] for r in observation_rows(db, result.run_id)} == {"ai"}
    assert result.planned == 5
