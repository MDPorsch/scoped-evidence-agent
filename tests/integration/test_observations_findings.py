"""D-E16, D-E17, AE-16, X-05: observations are idempotent and run-scoped; findings need evidence and a human."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from scopedagent.domain.models import AuditEvent, FindingDraft, FindingEvidence, Observation, Target
from scopedagent.domain.schemas import FindingDraftCreate, ObservationEnvelope
from scopedagent.domain.state_machine import Actor, ActorType, FindingStatus, RunState
from scopedagent.errors import ErrorCode, PolicyError, StateError
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.repositories import (
    create_finding_draft,
    record_observation,
    register_engagement,
    transition_finding,
    transition_run,
)
from tests.support import NOW, dump, golden, make_database, run_in_state, scope_dict

pytestmark = pytest.mark.milestone("M1")

HUMAN = Actor(ActorType.HUMAN, "alice")
WORKER = Actor(ActorType.WORKER, "worker-1")
MODEL = Actor(ActorType.MODEL, "model-x")
SOURCE = "b" * 64


@pytest.fixture
def db(tmp_path: Any) -> Any:
    database = make_database(tmp_path)
    yield database
    database.close()


def target_id(db: Any, run_id: str) -> str:
    with db.begin() as session:
        from scopedagent.domain.models import Run  # noqa: PLC0415

        run = session.get(Run, run_id)
        assert run is not None
        return session.scalars(select(Target).where(Target.engagement_id == run.engagement_id)).first().id  # type: ignore[union-attr]


def envelope(index: int = 0, pack: str = "healthy") -> ObservationEnvelope:
    return ObservationEnvelope.model_validate(golden(pack)[index])


def record(
    db: Any, run_id: str, index: int = 0, *, actor: Actor = WORKER, source: str = SOURCE
) -> tuple[Observation, bool]:
    with db.begin() as session:
        return record_observation(
            session,
            run_id=run_id,
            target_id=target_id(db, run_id),
            envelope=envelope(index),
            source_hash=source,
            collected_at=NOW,
            actor=actor,
        )


# -------------------------------------------------------------------------------- observations ----
def test_an_observation_is_stored_with_canonical_json_and_both_hashes(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    observation, created = record(db, run_id, 2)
    assert created is True
    item = golden("healthy")[2]
    with db.begin() as session:
        row = session.get(Observation, observation.id)
        assert row is not None
        assert (row.adapter, row.observation_type, row.error_status, row.source_hash) == (
            "offline_http",
            "http_metadata",
            "ok",
            SOURCE,
        )
        assert row.run_id == run_id and row.collected_at == NOW
        assert json.loads(row.normalized_json) == item["payload"]
        import hashlib  # noqa: PLC0415

        assert row.normalized_input_hash == hashlib.sha256(item["normalized_input"].encode()).hexdigest()


def test_recording_the_same_input_again_is_an_idempotent_replay(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    first, created = record(db, run_id, 0)
    again, created_again = record(db, run_id, 0)
    assert created and not created_again and first.id == again.id
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM observations")).scalar() == 1
        # the replay is logged, so a retry is visible rather than silent
        actions = [
            e.action
            for e in session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id))
        ]
        assert actions.count("observation.recorded") == 1 and actions.count("observation.replayed") == 1


def test_a_replay_never_overwrites_the_first_result(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    first, _ = record(db, run_id, 0, source=SOURCE)
    changed = copy.deepcopy(golden("healthy")[0])
    changed["payload"]["records"]["A"] = ["192.0.2.99"]
    with db.begin() as session:
        again, created = record_observation(
            session,
            run_id=run_id,
            target_id=target_id(db, run_id),
            envelope=ObservationEnvelope.model_validate(changed),
            source_hash="c" * 64,
            collected_at=NOW,
            actor=WORKER,
        )
    assert not created and again.id == first.id
    with db.begin() as session:
        row = session.get(Observation, first.id)
        assert (
            row is not None
            and json.loads(row.normalized_json)["records"]["A"] == ["192.0.2.10"]
            and row.source_hash == SOURCE
        )


def test_every_golden_observation_can_be_stored(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING", scope="misconfigured")
    for index in range(len(golden("misconfigured"))):
        with db.begin() as session:
            _, created = record_observation(
                session,
                run_id=run_id,
                target_id=target_id(db, run_id),
                envelope=envelope(index, "misconfigured"),
                source_hash=SOURCE,
                collected_at=NOW,
                actor=WORKER,
            )
        assert created
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM observations")).scalar() == 6
        verify_chain(session, run_id)


@pytest.mark.parametrize(
    "state", ["CREATED", "SCOPE_VALIDATED", "QUEUED", "CORRELATING", "DRAFTED", "HUMAN_REVIEW", "EXPORTED"]
)
def test_observations_are_accepted_only_while_collecting(db: Any, state: str) -> None:
    run_id = run_in_state(db, state)
    with pytest.raises(StateError) as caught:
        record(db, run_id, 0)
    assert caught.value.code is ErrorCode.STATE_001


@pytest.mark.parametrize("actor", [HUMAN, MODEL])
def test_only_the_adapter_process_writes_observations(db: Any, actor: Actor) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with pytest.raises(StateError) as caught:
        record(db, run_id, 0, actor=actor)
    assert caught.value.code is ErrorCode.STATE_003
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM observations")).scalar() == 0
        denied = session.scalars(select(AuditEvent).where(AuditEvent.decision == "denied")).all()
        assert len(denied) == 1 and denied[0].actor_type == actor.type.value


def test_a_target_of_another_engagement_is_refused_by_the_application_before_the_database(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    other = scope_dict("misconfigured")
    with db.begin() as session:
        engagement = register_engagement(session, parse_scope(dump(other), now=NOW), now=NOW)
        foreign = session.scalars(select(Target).where(Target.engagement_id == engagement.id)).first()
        assert foreign is not None
        foreign_id = foreign.id
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        record_observation(
            session,
            run_id=run_id,
            target_id=foreign_id,
            envelope=envelope(0),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
    assert caught.value.code is ErrorCode.POLICY_002


def test_an_unknown_run_or_target_is_refused(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with pytest.raises(StateError):
        with db.begin() as session:
            record_observation(
                session,
                run_id="nope",
                target_id="t",
                envelope=envelope(0),
                source_hash=SOURCE,
                collected_at=NOW,
                actor=WORKER,
            )
    with pytest.raises(PolicyError):
        with db.begin() as session:
            record_observation(
                session,
                run_id=run_id,
                target_id="nope",
                envelope=envelope(0),
                source_hash=SOURCE,
                collected_at=NOW,
                actor=WORKER,
            )


@pytest.mark.parametrize("bad", ["", "short", "G" * 64, "a" * 63, "a" * 65])
def test_the_source_hash_must_be_a_sha256(db: Any, bad: str) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with pytest.raises(ValueError, match="source_hash"):
        record(db, run_id, 0, source=bad)


def test_collected_at_must_be_timezone_aware(db: Any) -> None:
    from datetime import datetime  # noqa: PLC0415

    run_id = run_in_state(db, "COLLECTING")
    with pytest.raises(ValueError, match="(?i)aware|timezone"), db.begin() as session:
        record_observation(
            session,
            run_id=run_id,
            target_id=target_id(db, run_id),
            envelope=envelope(0),
            source_hash=SOURCE,
            collected_at=datetime(2026, 11, 20),
            actor=WORKER,
        )


# ------------------------------------------------------------------------------------ findings ----
def draft_input(**over: Any) -> FindingDraftCreate:
    base = {"title": "Missing security headers", "category": "http-headers", "confidence": 0.6}
    return FindingDraftCreate.model_validate(base | over)


def correlating_run_with_observations(db: Any, count: int = 2) -> tuple[str, list[str]]:
    run_id = run_in_state(db, "COLLECTING", scope="misconfigured")
    ids = []
    for index in range(count):
        with db.begin() as session:
            obs, _ = record_observation(
                session,
                run_id=run_id,
                target_id=target_id(db, run_id),
                envelope=envelope(index, "misconfigured"),
                source_hash=SOURCE,
                collected_at=NOW,
                actor=WORKER,
            )
            ids.append(obs.id)
    with db.begin() as session:
        transition_run(session, run_id, RunState.CORRELATING, actor=WORKER, now=NOW)
    return run_id, ids


def test_a_draft_starts_as_a_draft_with_its_evidence_linked(db: Any) -> None:
    run_id, ids = correlating_run_with_observations(db)
    with db.begin() as session:
        draft = create_finding_draft(
            session, run_id=run_id, draft=draft_input(), observation_ids=ids, actor=WORKER, now=NOW
        )
        draft_id = draft.id
    with db.begin() as session:
        row = session.get(FindingDraft, draft_id)
        assert row is not None
        assert (row.status, row.revision, row.reviewer_id, row.run_id) == ("DRAFT", 1, None, run_id)
        assert (row.title, row.category, row.confidence) == ("Missing security headers", "http-headers", 0.6)
        assert sorted(
            session.scalars(select(FindingEvidence.observation_id).where(FindingEvidence.finding_id == draft_id))
        ) == sorted(ids)
        assert row.evidence_ids == sorted(ids)  # the spec's evidence_ids, exposed as a property
        verify_chain(session, run_id)


def test_a_draft_must_cite_at_least_one_observation_and_only_existing_ones(db: Any) -> None:
    run_id, ids = correlating_run_with_observations(db)
    for bad in ([], ["no-such-observation"], [ids[0], "no-such-observation"]):
        with pytest.raises(PolicyError) as caught, db.begin() as session:
            create_finding_draft(
                session, run_id=run_id, draft=draft_input(), observation_ids=bad, actor=WORKER, now=NOW
            )
        assert caught.value.code is ErrorCode.POLICY_002
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM finding_drafts")).scalar() == 0


def test_a_draft_cannot_cite_an_observation_of_another_run(db: Any) -> None:
    run_a, ids_a = correlating_run_with_observations(db)
    run_b = run_in_state(db, "CORRELATING", scope="healthy")
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        create_finding_draft(session, run_id=run_b, draft=draft_input(), observation_ids=ids_a, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.POLICY_002
    assert run_a != run_b


def test_a_duplicate_observation_id_in_the_evidence_list_is_refused(db: Any) -> None:
    run_id, ids = correlating_run_with_observations(db)
    with pytest.raises(PolicyError), db.begin() as session:
        create_finding_draft(
            session, run_id=run_id, draft=draft_input(), observation_ids=[ids[0], ids[0]], actor=WORKER, now=NOW
        )


def test_the_model_cannot_create_a_draft_but_a_worker_and_a_human_can(db: Any) -> None:
    run_id, ids = correlating_run_with_observations(db)
    with pytest.raises(StateError) as caught, db.begin() as session:
        create_finding_draft(session, run_id=run_id, draft=draft_input(), observation_ids=ids, actor=MODEL, now=NOW)
    assert caught.value.code is ErrorCode.STATE_003
    for actor in (WORKER, HUMAN):
        with db.begin() as session:
            create_finding_draft(
                session,
                run_id=run_id,
                draft=draft_input(title=f"Draft by {actor.id}"),
                observation_ids=ids,
                actor=actor,
                now=NOW,
            )


@pytest.mark.parametrize("state", ["COLLECTING", "DRAFTED", "HUMAN_REVIEW"])
def test_drafts_are_created_only_while_correlating(db: Any, state: str) -> None:
    run_id = run_in_state(db, "COLLECTING", scope="misconfigured")
    with db.begin() as session:
        obs, _ = record_observation(
            session,
            run_id=run_id,
            target_id=target_id(db, run_id),
            envelope=envelope(0, "misconfigured"),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
        obs_id = obs.id
    if state != "COLLECTING":
        for step in (RunState.CORRELATING, RunState.DRAFTED, RunState.HUMAN_REVIEW):
            with db.begin() as session:
                transition_run(session, run_id, step, actor=WORKER, now=NOW)
            if step.value == state:
                break
    with pytest.raises(StateError) as caught, db.begin() as session:
        create_finding_draft(
            session, run_id=run_id, draft=draft_input(), observation_ids=[obs_id], actor=WORKER, now=NOW
        )
    assert caught.value.code is ErrorCode.STATE_001


@pytest.mark.parametrize(
    "bad",
    [
        {"title": "abc"},
        {"title": "x" * 161},
        {"confidence": 1.01},
        {"confidence": -0.01},
        {"category": "Bad Category"},
        {"category": ""},
        {"unknown": 1},
        {"title": 5},
    ],
)
def test_the_draft_input_is_validated(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="(?i)validation|string|pattern|less|greater|extra|input|at least|at most"):
        draft_input(**bad)


def test_the_draft_input_accepts_its_boundaries() -> None:
    draft_input(title="abcde", confidence=0.0)
    draft_input(title="x" * 160, confidence=1.0)


def make_draft(db: Any) -> tuple[str, str]:
    run_id, ids = correlating_run_with_observations(db)
    with db.begin() as session:
        return run_id, create_finding_draft(
            session, run_id=run_id, draft=draft_input(), observation_ids=ids, actor=WORKER, now=NOW
        ).id


def to_validated(db: Any, finding_id: str) -> None:
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    with db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.VALIDATED, actor=HUMAN, now=NOW, reason="reproduced from the headers"
        )


def test_the_full_finding_lifecycle_needs_a_human_from_validation_on(db: Any) -> None:
    run_id, finding_id = make_draft(db)
    to_validated(db, finding_id)
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.REMEDIATED, actor=HUMAN, now=NOW, reason="header added")
    with db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.VERIFIED, actor=HUMAN, now=NOW, reason="re-collected, header present"
        )
    with db.begin() as session:
        row = session.get(FindingDraft, finding_id)
        assert row is not None and (row.status, row.reviewer_id, row.revision) == ("VERIFIED", "alice", 5)
        log = [
            e
            for e in session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id))
            if e.action.startswith("finding.")
        ]
        assert [e.action for e in log] == ["finding.created"] + ["finding.transition"] * 4
        assert [e.decision for e in log] == ["allowed"] * 5 and log[-1].reason.endswith("re-collected, header present")
        verify_chain(session, run_id)


def test_a_worker_cannot_validate_and_the_attempt_is_audited(db: Any) -> None:
    run_id, finding_id = make_draft(db)
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.VALIDATED, actor=WORKER, now=NOW, reason="the rule fired")
    assert caught.value.code is ErrorCode.STATE_003
    with db.begin() as session:
        row = session.get(FindingDraft, finding_id)
        assert row is not None and row.status == "NEEDS_VALIDATION" and row.reviewer_id is None
        last = session.scalars(
            select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id.desc())
        ).first()
        assert last is not None and (last.decision, last.actor_type, last.action) == (
            "denied",
            "worker",
            "finding.transition",
        )


@pytest.mark.parametrize("dst", [FindingStatus.VALIDATED, FindingStatus.FALSE_POSITIVE])
def test_the_model_can_never_validate_or_dismiss_a_finding(db: Any, dst: FindingStatus) -> None:
    run_id, finding_id = make_draft(db)
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_finding(session, finding_id, dst, actor=MODEL, now=NOW, reason="certainly a vulnerability")
    assert caught.value.code is ErrorCode.STATE_003
    with db.begin() as session:
        row = session.get(FindingDraft, finding_id)
        assert row is not None and row.status == "NEEDS_VALIDATION"
    assert run_id


def test_a_human_review_without_a_reason_is_refused_and_audited(db: Any) -> None:
    run_id, finding_id = make_draft(db)
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.VALIDATED, actor=HUMAN, now=NOW, reason="  ")
    assert caught.value.code is ErrorCode.STATE_004
    with db.begin() as session:
        last = session.scalars(
            select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id.desc())
        ).first()
        assert last is not None and last.decision == "denied"


def test_a_false_positive_is_final(db: Any) -> None:
    _, finding_id = make_draft(db)
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    with db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.FALSE_POSITIVE, actor=HUMAN, now=NOW, reason="expected behaviour"
        )
    for dst in FindingStatus:
        with pytest.raises(StateError), db.begin() as session:
            transition_finding(session, finding_id, dst, actor=HUMAN, now=NOW, reason="changed my mind")


def test_a_stale_revision_loses_the_race(db: Any) -> None:
    _, finding_id = make_draft(db)
    with db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW, expected_revision=1
        )
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.VALIDATED, actor=HUMAN, now=NOW, reason="ok enough", expected_revision=1
        )
    assert caught.value.code is ErrorCode.STATE_002
    with db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.VALIDATED, actor=HUMAN, now=NOW, reason="ok enough", expected_revision=2
        )


def test_an_unknown_finding_is_an_error(db: Any) -> None:
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_finding(session, "nope", FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_001


def test_a_finding_with_no_evidence_link_cannot_be_validated_even_by_a_human(db: Any) -> None:
    run_id, ids = correlating_run_with_observations(db)
    with db.begin() as session:
        finding = create_finding_draft(
            session, run_id=run_id, draft=draft_input(), observation_ids=ids[:1], actor=WORKER, now=NOW
        )
        finding_id = finding.id
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
        # remove the only link behind the application's back (the table allows deletes; the transition must still notice)
        session.execute(text("DELETE FROM finding_evidence"))
    with pytest.raises(StateError) as caught, db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.VALIDATED, actor=HUMAN, now=NOW, reason="looks right")
    assert caught.value.code is ErrorCode.STATE_004


def test_raw_sql_cannot_link_a_finding_to_a_foreign_run_observation(db: Any) -> None:
    run_a, ids_a = correlating_run_with_observations(db)
    run_b = run_in_state(db, "CORRELATING", scope="healthy")
    with db.begin() as session:
        session.execute(
            text(
                "INSERT INTO finding_drafts (id, run_id, title, category, confidence, status, revision, created_at) "
                "VALUES ('f-b', :r, 'A finding', 'x', 0.5, 'DRAFT', 1, '2026-11-20T12:00:00.000000Z')"
            ),
            {"r": run_b},
        )
    with pytest.raises(DatabaseError), db.begin() as session:
        session.execute(
            text("INSERT INTO finding_evidence (finding_id, observation_id, run_id) VALUES ('f-b', :o, :r)"),
            {"o": ids_a[0], "r": run_b},
        )
    assert run_a


def test_actors_are_attributed_in_the_finding_row(db: Any) -> None:
    run_id, finding_id = make_draft(db)
    with db.begin() as session:
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    with db.begin() as session:
        row = session.get(FindingDraft, finding_id)
        assert row is not None and row.reviewer_id is None  # a worker's step is not a review
    with db.begin() as session:
        transition_finding(
            session, finding_id, FindingStatus.VALIDATED, actor=HUMAN, now=NOW, reason="reproduced from the headers"
        )
    with db.begin() as session:
        row = session.get(FindingDraft, finding_id)
        assert row is not None and row.reviewer_id == "alice"
    assert run_id


def test_an_observation_that_names_a_different_target_than_its_row_is_refused(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    other = copy.deepcopy(golden("healthy")[0])
    other["target"]["port"] = 8443  # the row says 443
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        record_observation(
            session,
            run_id=run_id,
            target_id=target_id(db, run_id),
            envelope=ObservationEnvelope.model_validate(other),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
    assert caught.value.code is ErrorCode.POLICY_002
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM observations")).scalar() == 0
        assert [
            e.decision for e in session.scalars(select(AuditEvent).where(AuditEvent.action == "observation.record"))
        ] == ["denied"]


def test_a_draft_for_an_unknown_run_is_an_error(db: Any) -> None:
    with pytest.raises(StateError) as caught, db.begin() as session:
        create_finding_draft(session, run_id="nope", draft=draft_input(), observation_ids=["x"], actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_001


def test_a_concurrent_change_to_a_finding_between_the_check_and_the_update_is_caught(
    db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scopedagent.storage.repositories as module  # noqa: PLC0415

    _, finding_id = make_draft(db)
    real_check = module.check_finding_transition

    def check_then_race(*args: Any, **kwargs: Any) -> None:
        real_check(*args, **kwargs)
        holder["session"].execute(text("UPDATE finding_drafts SET revision = revision + 1"))

    holder: dict[str, Any] = {}
    monkeypatch.setattr(module, "check_finding_transition", check_then_race)
    with pytest.raises(StateError) as caught, db.begin() as session:
        holder["session"] = session
        transition_finding(session, finding_id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=NOW)
    assert caught.value.code is ErrorCode.STATE_002


def test_the_error_status_of_an_observation_is_stored_as_given(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    failed = copy.deepcopy(golden("healthy")[2])
    failed["error_status"] = "timeout"
    failed["payload"].update(http_status=None, headers={}, redirect_location=None, body=None)
    with db.begin() as session:
        observation, _ = record_observation(
            session,
            run_id=run_id,
            target_id=target_id(db, run_id),
            envelope=ObservationEnvelope.model_validate(failed),
            source_hash=SOURCE,
            collected_at=NOW,
            actor=WORKER,
        )
        assert observation.error_status == "timeout"
    with db.begin() as session:
        assert session.execute(text("SELECT error_status FROM observations")).scalar() == "timeout"


def test_the_stored_payload_is_canonical_json(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    observation, _ = record(db, run_id, 2)
    expected = json.dumps(golden("healthy")[2]["payload"], sort_keys=True, separators=(",", ":"))
    with db.begin() as session:
        assert session.get(Observation, observation.id).normalized_json == expected  # type: ignore[union-attr]


def test_a_recorded_observation_is_an_allowed_audit_event_and_a_replay_is_a_recorded_one(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    record(db, run_id, 0)
    record(db, run_id, 0)
    with db.begin() as session:
        events = {e.action: e.decision for e in session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id))}
    assert events["observation.recorded"] == "allowed" and events["observation.replayed"] == "recorded"
