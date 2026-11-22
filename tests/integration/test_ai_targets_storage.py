"""D-E34: AI targets are stored as their own kind of target, and an observation may only be filed under the right kind."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from scopedagent.domain.models import Run, Target
from scopedagent.domain.schemas import ObservationEnvelope
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, PolicyError
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.repositories import record_observation, register_engagement
from tests.support import (
    AI_PACK,
    NOW,
    dump,
    golden,
    make_database,
    run_in_state,
    scope_dict,
    scope_text,
    seed,
    sql_insert,
    stamp,
)

pytestmark = pytest.mark.milestone("M1")

WORKER = Actor(ActorType.WORKER, "worker-1")
SOURCE = "b" * 64


@pytest.fixture
def db(tmp_path: Any) -> Any:
    database = make_database(tmp_path)
    yield database
    database.close()


def ai_loaded() -> Any:
    return parse_scope(scope_text(AI_PACK), now=NOW)


def rows(db: Any, run_id: str) -> list[Target]:
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None
        return list(
            session.scalars(
                select(Target)
                .where(Target.engagement_id == run.engagement_id)
                .order_by(Target.kind, Target.host_canonical)
            )
        )


def row_of(db: Any, run_id: str, kind: str) -> str:
    return next(t.id for t in rows(db, run_id) if t.kind == kind)


def envelope(pack: str, index: int) -> ObservationEnvelope:
    return ObservationEnvelope.model_validate(golden(pack)[index])


# -------------------------------------------------------------------------------------- the rows ----
def test_an_ai_scope_registers_one_ai_target_row_with_its_exact_paths(db: Any) -> None:
    with db.begin() as session:
        engagement = register_engagement(session, ai_loaded(), now=NOW)
        (row,) = session.scalars(select(Target).where(Target.engagement_id == engagement.id)).all()
        assert (row.kind, row.ai_target_id, row.host_canonical, row.scheme, row.port) == (
            "ai",
            "support-bot",
            "assistant.example.invalid",
            "https",
            443,
        )
        assert row.allowed_path_prefixes == ["/v1/models", "/v1/chat/completions"] and row.verified_scope is True


def test_web_target_rows_have_kind_web_and_no_ai_target_id(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    assert [(t.kind, t.ai_target_id) for t in rows(db, run_id)] == [("web", None)]


def test_a_host_listed_as_web_and_as_ai_gets_two_rows(db: Any) -> None:
    data = scope_dict(AI_PACK)
    data["allowed_targets"] = [
        {"host": "assistant.example.invalid", "schemes": ["https"], "ports": [443], "allowed_paths": ["/robots.txt"]}
    ]
    data["allowed_operations"] = ["dns_metadata", "tls_metadata", "http_metadata", "ai_metadata", "ai_probe"]
    with db.begin() as session:
        engagement = register_engagement(session, parse_scope(dump(data), now=NOW), now=NOW)
        kinds = sorted(t.kind for t in session.scalars(select(Target).where(Target.engagement_id == engagement.id)))
    assert kinds == ["ai", "web"]


def test_each_ai_target_of_a_scope_gets_its_own_row(db: Any) -> None:
    data = scope_dict(AI_PACK)
    second = copy.deepcopy(data["ai_targets"][0])
    second.update(id="second-bot", host="second.example.invalid")
    data["ai_targets"].append(second)
    with db.begin() as session:
        engagement = register_engagement(session, parse_scope(dump(data), now=NOW), now=NOW)
        ids = sorted(
            t.ai_target_id for t in session.scalars(select(Target).where(Target.engagement_id == engagement.id))
        )
    assert ids == ["second-bot", "support-bot"]


def test_registering_the_same_ai_scope_twice_is_idempotent(db: Any) -> None:
    with db.begin() as session:
        first = register_engagement(session, ai_loaded(), now=NOW).id
    with db.begin() as session:
        assert register_engagement(session, ai_loaded(), now=NOW).id == first
        assert session.execute(text("SELECT count(*) FROM targets")).scalar() == 1


def test_a_run_from_an_ai_scope_takes_its_budget_from_the_scope(db: Any) -> None:
    run_id = run_in_state(db, "CREATED", scope=AI_PACK)
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and (run.total_budget, run.state) == (12, "CREATED")


# ------------------------------------------------------------------------------- recording AI data ----
def test_every_ai_golden_can_be_stored_on_the_ai_target(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING", scope=AI_PACK)
    target_id = row_of(db, run_id, "ai")
    for index in range(len(golden(AI_PACK))):
        with db.begin() as session:
            _, created = record_observation(
                session,
                run_id=run_id,
                target_id=target_id,
                envelope=envelope(AI_PACK, index),
                source_hash=SOURCE,
                collected_at=NOW,
                actor=WORKER,
            )
        assert created
    with db.begin() as session:
        types = sorted(session.execute(text("SELECT observation_type FROM observations")).scalars())
    assert types == ["ai_metadata"] + ["ai_probe"] * 4


def test_an_ai_observation_cannot_be_filed_under_a_web_target(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    healthy_target = row_of(db, run_id, "web")
    ai = copy.deepcopy(golden(AI_PACK)[0])
    ai["target"] = {
        "host": "lab.example.invalid",
        "scheme": "https",
        "port": 443,
    }  # even naming the web row's own endpoint
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        record_observation(
            session,
            run_id=run_id,
            target_id=healthy_target,
            envelope=ObservationEnvelope.model_validate(ai),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
    assert caught.value.code is ErrorCode.POLICY_002


def test_a_web_observation_cannot_be_filed_under_an_ai_target(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING", scope=AI_PACK)
    web = copy.deepcopy(golden("healthy")[0])
    web["target"] = {"host": "assistant.example.invalid", "scheme": "https", "port": 443}
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        record_observation(
            session,
            run_id=run_id,
            target_id=row_of(db, run_id, "ai"),
            envelope=ObservationEnvelope.model_validate(web),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
    assert caught.value.code is ErrorCode.POLICY_002
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM observations")).scalar() == 0


def test_a_refused_kind_mismatch_is_audited_as_denied(db: Any) -> None:
    from scopedagent.domain.models import AuditEvent  # noqa: PLC0415

    run_id = run_in_state(db, "COLLECTING", scope=AI_PACK)
    web = copy.deepcopy(golden("healthy")[0])
    web["target"] = {"host": "assistant.example.invalid", "scheme": "https", "port": 443}
    with pytest.raises(PolicyError), db.begin() as session:
        record_observation(
            session,
            run_id=run_id,
            target_id=row_of(db, run_id, "ai"),
            envelope=ObservationEnvelope.model_validate(web),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
    with db.begin() as session:
        denied = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "observation.record", AuditEvent.decision == "denied")
        ).all()
        assert len(denied) == 1


# ------------------------------------------------------------------------------ the database itself ----
def target_row(**over: Any) -> dict[str, Any]:
    row = {
        "id": "t9",
        "engagement_id": "e1",
        "host_canonical": "x.example.invalid",
        "scheme": "https",
        "port": 8443,
        "allowed_path_prefixes": "[]",
        "verified_scope": 1,
        "kind": "web",
        "ai_target_id": None,
    }
    row.update(over)
    return row


def test_the_kind_must_be_web_ai_or_api(db: Any) -> None:
    for bad in ("rest", "WEB", "", "ai ", "API"):
        with pytest.raises(DatabaseError), db.begin() as session:
            seed(session)
            sql_insert(session, "targets", **target_row(kind=bad))
    with db.begin() as session:
        seed(session)
        sql_insert(session, "targets", **target_row(kind="api"))  # an API target has no AI target id


def test_an_api_row_must_not_carry_an_ai_target_id(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "targets", **target_row(kind="api", ai_target_id="support-bot"))


def test_an_ai_row_needs_an_ai_target_id_and_a_web_row_must_not_have_one(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "targets", **target_row(kind="ai", ai_target_id=None))
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "targets", **target_row(kind="web", ai_target_id="support-bot"))
    with db.begin() as session:
        seed(session)
        sql_insert(session, "targets", **target_row(kind="ai", ai_target_id="support-bot"))


def test_the_same_endpoint_may_exist_once_per_kind_but_not_twice_in_one_kind(db: Any) -> None:
    with db.begin() as session:
        seed(session)
        same = {"host_canonical": "lab.example.invalid", "scheme": "https", "port": 443}
        sql_insert(session, "targets", **target_row(id="t-ai", kind="ai", ai_target_id="bot", **same))
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "targets", **target_row(id="t-ai", kind="ai", ai_target_id="bot", **same))
        sql_insert(session, "targets", **target_row(id="t-ai2", kind="ai", ai_target_id="bot2", **same))


def test_the_database_accepts_the_known_adapters_and_types_but_nothing_else(db: Any) -> None:
    def observation(**over: Any) -> dict[str, Any]:
        row = {
            "id": "o1",
            "run_id": "r1",
            "target_id": "t1",
            "adapter": "offline_ai",
            "observation_type": "ai_probe",
            "normalized_json": "{}",
            "collected_at": stamp(),
            "source_hash": "b" * 64,
            "normalized_input_hash": "c" * 64,
            "error_status": "ok",
        }
        row.update(over)
        return row

    with db.begin() as session:
        seed(session)
    for ok in (
        {"observation_type": "ai_probe"},
        {"observation_type": "ai_metadata", "id": "o2", "normalized_input_hash": "d" * 64},
    ):
        with db.begin() as session:
            sql_insert(session, "observations", **observation(**ok))
    for ok in (
        {"adapter": "offline_api", "observation_type": "api_spec", "id": "o3", "normalized_input_hash": "e" * 64},
        {"adapter": "offline_api", "observation_type": "api_read", "id": "o4", "normalized_input_hash": "f" * 64},
        {"adapter": "offline_api", "observation_type": "api_options", "id": "o5", "normalized_input_hash": "9" * 64},
    ):
        with db.begin() as session:
            sql_insert(session, "observations", **observation(**ok))
    for bad in (
        {"adapter": "offline_apis", "id": "o6"},
        {"observation_type": "api_write", "id": "o7"},
        {"observation_type": "API_READ", "id": "o8"},
        {"adapter": "live_ai", "id": "o9"},
    ):
        with pytest.raises(DatabaseError), db.begin() as session:
            sql_insert(session, "observations", **observation(**bad))
