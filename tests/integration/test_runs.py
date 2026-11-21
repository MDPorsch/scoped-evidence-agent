"""D-E15, AE-15, X-05: engagements, runs, audited transitions, retries. Every change is logged in its own transaction."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select, text

from scopedagent.domain.models import AuditEvent, Engagement, Run, Target
from scopedagent.domain.state_machine import Actor, ActorType, RunState
from scopedagent.errors import ErrorCode, PolicyError, StateError
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.repositories import create_run, list_runs, register_engagement, retry_run, transition_run
from tests.support import NOW, dump, healthy_loaded, make_database, run_in_state, scope_dict, scope_text

pytestmark = pytest.mark.milestone("M1")

HUMAN = Actor(ActorType.HUMAN, "alice")
WORKER = Actor(ActorType.WORKER, "worker-1")
MODEL = Actor(ActorType.MODEL, "model-x")


@pytest.fixture
def db(tmp_path: Any) -> Any:
    database = make_database(tmp_path)
    yield database
    database.close()


def events(db: Any, run_id: str) -> list[AuditEvent]:
    with db.begin() as session:
        return list(session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id)))


# ------------------------------------------------------------------------------- engagements ----
def test_registering_a_scope_stores_the_normalised_scope_its_hash_and_one_row_per_target(db: Any) -> None:
    loaded = healthy_loaded()
    with db.begin() as session:
        engagement = register_engagement(session, loaded, now=NOW)
        stored = session.get(Engagement, engagement.id)
        assert stored is not None
        assert stored.scope_sha256 == loaded.sha256 and stored.scope_json == loaded.canonical_json
        assert stored.label == "lab-healthy-001" and stored.owner_approval_ref == "local-lab-consent"
        assert stored.status == "active" and stored.expires_at == loaded.config.expires_at and stored.created_at == NOW
        (target,) = session.scalars(select(Target).where(Target.engagement_id == engagement.id)).all()
        assert (target.host_canonical, target.scheme, target.port, target.verified_scope) == (
            "lab.example.invalid",
            "https",
            443,
            True,
        )
        assert target.allowed_path_prefixes == ["/.well-known/security.txt", "/openapi.json", "/robots.txt"]


def test_the_same_scope_registers_the_same_engagement_and_a_changed_one_a_new_engagement(db: Any) -> None:
    with db.begin() as session:
        first = register_engagement(session, healthy_loaded(), now=NOW).id
    with db.begin() as session:
        again = register_engagement(session, healthy_loaded(), now=NOW + timedelta(hours=1)).id
        data = scope_dict()
        data["allowed_targets"][0]["allowed_paths"].append("/extra")
        other = register_engagement(session, parse_scope(dump(data), now=NOW), now=NOW).id
    assert first == again and other != first


def test_a_target_row_exists_for_every_scheme_and_port_of_an_entry(db: Any) -> None:
    data = scope_dict()
    data["allowed_targets"][0]["ports"] = [443, 8443]
    data["allowed_targets"].append(
        {"host": "b.example.invalid", "schemes": ["http", "https"], "ports": [8080], "allowed_paths": ["/h"]}
    )
    with db.begin() as session:
        engagement = register_engagement(session, parse_scope(dump(data), now=NOW), now=NOW)
        rows = session.scalars(select(Target).where(Target.engagement_id == engagement.id)).all()
    assert sorted((t.host_canonical, t.scheme, t.port) for t in rows) == [
        ("b.example.invalid", "http", 8080),
        ("b.example.invalid", "https", 8080),
        ("lab.example.invalid", "https", 443),
        ("lab.example.invalid", "https", 8443),
    ]


def test_an_expired_scope_cannot_be_registered(db: Any) -> None:
    loaded = healthy_loaded()
    with pytest.raises(Exception, match="SCOPE-004"), db.begin() as session:
        register_engagement(session, loaded, now=loaded.config.expires_at)


# ------------------------------------------------------------------------------------- runs ----
def test_a_new_run_starts_created_with_the_scopes_request_budget_and_an_audit_event(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None
        assert (run.state, run.mode, run.total_budget, run.budget_spent, run.attempt, run.created_by) == (
            "CREATED",
            "offline",
            12,
            0,
            1,
            "alice",
        )
        assert (
            run.started_at is None and run.ended_at is None and run.error_code is None and run.retry_of_run_id is None
        )
    (created,) = events(db, run_id)
    assert (created.action, created.decision, created.actor_type, created.actor_id) == (
        "run.created",
        "allowed",
        "human",
        "alice",
    )


def test_a_model_cannot_create_a_run(db: Any) -> None:
    with db.begin() as session:
        engagement = register_engagement(session, healthy_loaded(), now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        create_run(session, engagement, actor=MODEL, now=NOW)
    assert caught.value.code is ErrorCode.STATE_003


def test_a_live_scope_cannot_create_a_run_in_this_version(db: Any) -> None:
    data = scope_dict()
    data["mode"] = "live"
    with db.begin() as session:
        engagement = register_engagement(session, parse_scope(dump(data), now=NOW), now=NOW)
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        create_run(session, engagement, actor=HUMAN, now=NOW)
    assert caught.value.code is ErrorCode.POLICY_001


def test_the_whole_happy_path_is_recorded_step_by_step_and_the_chain_verifies(db: Any) -> None:
    run_id = run_in_state(db, "EXPORTED")
    log = events(db, run_id)
    assert [e.action for e in log] == ["run.created"] + ["run.transition"] * 7
    assert [e.reason for e in log[1:]] == [
        "CREATED -> SCOPE_VALIDATED",
        "SCOPE_VALIDATED -> QUEUED",
        "QUEUED -> COLLECTING",
        "COLLECTING -> CORRELATING",
        "CORRELATING -> DRAFTED",
        "DRAFTED -> HUMAN_REVIEW",
        "HUMAN_REVIEW -> EXPORTED",
    ]
    assert all(e.decision == "allowed" for e in log)
    with db.begin() as session:
        verify_chain(session, run_id)
        run = session.get(Run, run_id)
        assert run is not None and run.state == "EXPORTED"
        assert run.started_at is not None and run.ended_at is not None  # COLLECTING starts it, EXPORTED ends it


def test_started_at_is_set_on_entering_collecting_and_ended_at_on_a_terminal_state(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.started_at == NOW and run.ended_at is None
        transition_run(
            session,
            run_id,
            RunState.FAILED,
            actor=WORKER,
            now=NOW + timedelta(minutes=5),
            error_code="adapter_error",
            reason="the adapter crashed",
        )
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.state == "FAILED" and run.error_code == "adapter_error"
        assert run.ended_at == NOW + timedelta(minutes=5)


def test_an_invalid_transition_is_refused_logged_as_denied_and_changes_nothing(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_run(session, run_id, RunState.COLLECTING, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_001
    last = events(db, run_id)[-1]
    assert (last.decision, last.action, last.actor_type) == ("denied", "run.transition", "worker")
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.state == "CREATED"
        verify_chain(session, run_id)


def test_a_model_attempt_is_refused_and_leaves_a_denial_in_the_audit_trail(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_run(session, run_id, RunState.SCOPE_VALIDATED, actor=MODEL, now=NOW, reason="I decided")
    assert caught.value.code is ErrorCode.STATE_003
    last = events(db, run_id)[-1]
    assert (last.decision, last.actor_type, last.actor_id) == ("denied", "model", "model-x")
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.state == "CREATED"


def test_a_worker_cannot_export_and_a_human_can(db: Any) -> None:
    run_id = run_in_state(db, "HUMAN_REVIEW")
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_run(session, run_id, RunState.EXPORTED, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_003
    with db.begin() as session:
        transition_run(session, run_id, RunState.EXPORTED, actor=HUMAN, now=NOW)


def test_a_stale_expected_state_loses_the_race(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    with db.begin() as session:
        transition_run(session, run_id, RunState.SCOPE_VALIDATED, actor=WORKER, now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_run(session, run_id, RunState.SCOPE_VALIDATED, actor=WORKER, now=NOW, expected=RunState.CREATED)
    assert caught.value.code is ErrorCode.STATE_002
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.state == "SCOPE_VALIDATED"


def test_an_unknown_run_is_an_error_not_a_crash(db: Any) -> None:
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_run(session, "no-such-run", RunState.QUEUED, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_001


@pytest.mark.parametrize(
    "state", ["CREATED", "SCOPE_VALIDATED", "QUEUED", "COLLECTING", "CORRELATING", "DRAFTED", "HUMAN_REVIEW"]
)
def test_a_run_can_be_cancelled_from_every_active_state_and_nothing_follows(db: Any, state: str) -> None:
    run_id = run_in_state(db, state)
    with db.begin() as session:
        transition_run(session, run_id, RunState.CANCELED, actor=HUMAN, now=NOW, reason="operator stopped it")
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.state == "CANCELED" and run.ended_at == NOW
    for dst in (RunState.COLLECTING, RunState.FAILED, RunState.RETRIED, RunState.CREATED):
        with pytest.raises(StateError), db.begin() as session:
            transition_run(session, run_id, dst, actor=HUMAN, now=NOW)


# --------------------------------------------------------------------------------- AE-15: retry ----
def test_a_failed_run_is_retried_as_a_new_attempt_and_the_old_history_is_kept(db: Any) -> None:
    old_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        transition_run(session, old_id, RunState.FAILED, actor=WORKER, now=NOW, error_code="adapter_error")
    with db.begin() as session:
        new = retry_run(session, old_id, actor=HUMAN, now=NOW + timedelta(minutes=1))
        new_id = new.id
    assert new_id != old_id
    with db.begin() as session:
        old, fresh = session.get(Run, old_id), session.get(Run, new_id)
        assert old is not None and fresh is not None
        assert old.state == "RETRIED" and old.error_code == "adapter_error"
        assert (fresh.state, fresh.attempt, fresh.retry_of_run_id, fresh.budget_spent) == ("CREATED", 2, old_id, 0)
        assert fresh.total_budget == old.total_budget and fresh.engagement_id == old.engagement_id
        verify_chain(session, old_id)
        verify_chain(session, new_id)
    assert events(db, old_id)[-1].reason.startswith("FAILED -> RETRIED")
    assert events(db, new_id)[0].action == "run.created" and old_id in events(db, new_id)[0].reason


def test_attempts_chain_up(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    for expected_attempt in (2, 3, 4):
        with db.begin() as session:
            transition_run(session, run_id, RunState.FAILED, actor=WORKER, now=NOW, error_code="infra")
        with db.begin() as session:
            run_id = retry_run(session, run_id, actor=HUMAN, now=NOW).id
        with db.begin() as session:
            run = session.get(Run, run_id)
            assert run is not None and run.attempt == expected_attempt


@pytest.mark.parametrize("state", ["CREATED", "COLLECTING", "DRAFTED", "CANCELED"])
def test_only_a_failed_run_can_be_retried(db: Any, state: str) -> None:
    run_id = run_in_state(db, state) if state != "CANCELED" else run_in_state(db, "CREATED")
    if state == "CANCELED":
        with db.begin() as session:
            transition_run(session, run_id, RunState.CANCELED, actor=HUMAN, now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        retry_run(session, run_id, actor=HUMAN, now=NOW)
    assert caught.value.code is ErrorCode.STATE_001


def test_a_worker_cannot_retry_and_a_failed_run_stays_failed(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    with db.begin() as session:
        transition_run(session, run_id, RunState.FAILED, actor=WORKER, now=NOW, error_code="infra")
    with pytest.raises(StateError) as caught, db.begin() as session:
        retry_run(session, run_id, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_003
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None and run.state == "FAILED"
        assert session.execute(text("SELECT count(*) FROM runs")).scalar() == 1


def test_a_run_cannot_be_retried_twice(db: Any) -> None:
    run_id = run_in_state(db, "CREATED")
    with db.begin() as session:
        transition_run(session, run_id, RunState.FAILED, actor=WORKER, now=NOW, error_code="infra")
    with db.begin() as session:
        retry_run(session, run_id, actor=HUMAN, now=NOW)
    with pytest.raises(StateError), db.begin() as session:
        retry_run(session, run_id, actor=HUMAN, now=NOW)


# ------------------------------------------------------------------------------------- listing ----
def test_runs_are_listed_newest_first_with_bounded_pages(db: Any) -> None:
    ids = []
    for minute in range(5):
        with db.begin() as session:
            engagement = register_engagement(session, healthy_loaded(), now=NOW)
            ids.append(create_run(session, engagement, actor=HUMAN, now=NOW + timedelta(minutes=minute)).id)
    with db.begin() as session:
        assert [r.id for r in list_runs(session, limit=100, offset=0)] == list(reversed(ids))
        assert [r.id for r in list_runs(session, limit=2, offset=1)] == list(reversed(ids))[1:3]
        assert list_runs(session, limit=2, offset=10) == []


@pytest.mark.parametrize(("limit", "offset"), [(0, 0), (101, 0), (-1, 0), (10, -1)])
def test_list_bounds_are_enforced(db: Any, limit: int, offset: int) -> None:
    with pytest.raises(ValueError, match="limit|offset"), db.begin() as session:
        list_runs(session, limit=limit, offset=offset)


def test_the_expiry_is_rechecked_when_a_run_is_created(db: Any) -> None:
    loaded = parse_scope(scope_text(), now=NOW)
    with db.begin() as session:
        engagement = register_engagement(session, loaded, now=NOW)
    with pytest.raises(Exception, match="SCOPE-004"), db.begin() as session:
        create_run(session, engagement, actor=HUMAN, now=loaded.config.expires_at)


def test_a_worker_cannot_start_a_run_and_the_attempt_is_audited(db: Any) -> None:
    with db.begin() as session:
        engagement = register_engagement(session, healthy_loaded(), now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        create_run(session, engagement, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_003
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM runs")).scalar() == 0
        denied = session.scalars(select(AuditEvent).where(AuditEvent.action == "run.create")).all()
        assert [(e.decision, e.run_id, e.actor_type) for e in denied] == [("denied", None, "worker")]
        verify_chain(session, None)


def test_retrying_an_unknown_run_is_an_error(db: Any) -> None:
    with pytest.raises(StateError) as caught, db.begin() as session:
        retry_run(session, "no-such-run", actor=HUMAN, now=NOW)
    assert caught.value.code is ErrorCode.STATE_001


def test_a_concurrent_change_between_the_check_and_the_update_is_caught(
    db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scopedagent.storage.repositories as module  # noqa: PLC0415

    run_id = run_in_state(db, "CREATED")
    real_check = module.check_run_transition

    def check_then_race(src: Any, dst: Any, actor: Any) -> None:
        real_check(src, dst, actor)
        # another writer sneaks in between the check and the conditional update
        module_session.execute(text("UPDATE runs SET state = 'QUEUED' WHERE id = :id"), {"id": run_id})

    monkeypatch.setattr(module, "check_run_transition", check_then_race)
    with pytest.raises(StateError) as caught, db.begin() as session:
        module_session = session
        transition_run(session, run_id, RunState.SCOPE_VALIDATED, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_002


def test_a_retried_run_keeps_the_time_it_failed_not_the_time_it_was_retried(db: Any) -> None:
    old_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        transition_run(session, old_id, RunState.FAILED, actor=WORKER, now=NOW, error_code="infra")
    with db.begin() as session:
        retry_run(session, old_id, actor=HUMAN, now=NOW + timedelta(hours=2))
    with db.begin() as session:
        run = session.get(Run, old_id)
        assert run is not None and run.state == "RETRIED" and run.ended_at == NOW


def test_a_retry_starts_with_nothing_spent_even_if_the_failed_run_spent_some(db: Any) -> None:
    from scopedagent.policy.budget import reserve  # noqa: PLC0415

    old_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        reserve(session, old_id, units=7)
    with db.begin() as session:
        transition_run(session, old_id, RunState.FAILED, actor=WORKER, now=NOW, error_code="infra")
    with db.begin() as session:
        fresh_id = retry_run(session, old_id, actor=HUMAN, now=NOW).id
    with db.begin() as session:
        old, fresh = session.get(Run, old_id), session.get(Run, fresh_id)
        assert old is not None and fresh is not None
        assert (old.budget_spent, fresh.budget_spent, fresh.total_budget) == (7, 0, old.total_budget)
