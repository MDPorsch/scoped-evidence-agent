"""D-E11, X-02: the audit trail is append-only and hash-chained; an edit or a gap is detected."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

import pytest
from scopedagent.domain.models import AuditEvent
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import AuditError, ErrorCode
from scopedagent.storage.audit import GENESIS_HASH, append_event, verify_chain
from scopedagent.storage.database import DataDir, open_database, upgrade_database
from sqlalchemy import text

from tests.support import NOW, seed

pytestmark = pytest.mark.milestone("M1")

WORKER = Actor(ActorType.WORKER, "worker-1")
HUMAN = Actor(ActorType.HUMAN, "alice")


@pytest.fixture
def db(tmp_path: Any) -> Any:
    data_dir = DataDir(tmp_path / "data")
    upgrade_database(data_dir)
    database = open_database(data_dir)
    with database.begin() as session:
        seed(session)
        session.execute(
            text(
                "INSERT INTO runs (id, engagement_id, created_by, mode, state, total_budget, budget_spent, attempt, created_at) "
                "VALUES ('r2', 'e1', 'alice', 'offline', 'CREATED', 1, 0, 1, '2026-11-20T12:00:00.000000Z')"
            )
        )
    yield database
    database.close()


def expected_hash(event: AuditEvent) -> str:
    payload = {
        "id": event.id,
        "run_id": event.run_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "action": event.action,
        "decision": event.decision,
        "reason": event.reason,
        "ts": event.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "prev_hash": event.prev_hash,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def add(session: Any, n: int, run_id: str | None = "r1", offset: int = 0) -> list[AuditEvent]:
    return [
        append_event(
            session,
            run_id=run_id,
            actor=WORKER,
            action=f"step.{i}",
            decision="allowed",
            reason=f"why {i}",
            now=NOW + timedelta(seconds=offset + i),
        )
        for i in range(n)
    ]


def drop_triggers(session: Any) -> None:
    session.execute(text("DROP TRIGGER audit_events_no_update"))
    session.execute(text("DROP TRIGGER audit_events_no_delete"))


def test_the_first_event_of_a_run_links_to_the_genesis_hash(db: Any) -> None:
    with db.begin() as session:
        (first,) = add(session, 1)
    assert first.prev_hash == GENESIS_HASH == "0" * 64 and first.id == 1


def test_each_event_links_to_the_previous_one_and_hashes_its_own_fields(db: Any) -> None:
    with db.begin() as session:
        events = add(session, 4)
    assert [e.id for e in events] == [1, 2, 3, 4]
    for previous, current in zip(events, events[1:], strict=False):
        assert current.prev_hash == previous.entry_hash
    for event in events:
        assert event.entry_hash == expected_hash(event)


def test_every_field_of_an_event_is_recorded(db: Any) -> None:
    with db.begin() as session:
        event = append_event(
            session, run_id="r1", actor=HUMAN, action="run.cancel", decision="denied", reason="nope", now=NOW
        )
    assert (event.run_id, event.actor_type, event.actor_id, event.action, event.decision, event.reason) == (
        "r1",
        "human",
        "alice",
        "run.cancel",
        "denied",
        "nope",
    )
    assert event.ts == NOW


def test_chains_are_per_run_and_a_run_less_chain_is_separate(db: Any) -> None:
    with db.begin() as session:
        a = add(session, 2, "r1")
        b = add(session, 2, "r2", offset=10)
        c = add(session, 2, None, offset=20)
    assert a[0].prev_hash == b[0].prev_hash == c[0].prev_hash == GENESIS_HASH
    assert a[1].prev_hash == a[0].entry_hash and b[1].prev_hash == b[0].entry_hash and c[1].prev_hash == c[0].entry_hash
    with db.begin() as session:
        for run in ("r1", "r2", None):
            verify_chain(session, run)


def test_a_chain_of_many_events_verifies(db: Any) -> None:
    with db.begin() as session:
        add(session, 60)
    with db.begin() as session:
        verify_chain(session, "r1")


def test_an_empty_chain_verifies(db: Any) -> None:
    with db.begin() as session:
        verify_chain(session, "r1")


def test_an_unknown_decision_or_a_blank_action_is_refused_before_it_is_written(db: Any) -> None:
    with pytest.raises(ValueError, match="decision"), db.begin() as session:
        append_event(session, run_id="r1", actor=WORKER, action="x", decision="maybe", reason="", now=NOW)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="action"), db.begin() as session:
        append_event(session, run_id="r1", actor=WORKER, action="  ", decision="allowed", reason="", now=NOW)


def test_a_naive_timestamp_is_refused(db: Any) -> None:
    from datetime import datetime  # noqa: PLC0415

    with pytest.raises(ValueError, match="(?i)aware|timezone"), db.begin() as session:
        append_event(
            session, run_id="r1", actor=WORKER, action="x", decision="allowed", reason="", now=datetime(2026, 1, 1)
        )


def test_the_reason_is_bounded_and_stripped_of_control_characters(db: Any) -> None:
    with db.begin() as session:
        event = append_event(
            session,
            run_id="r1",
            actor=WORKER,
            action="x",
            decision="allowed",
            reason="line one\nline two" + chr(0) + chr(0x202E) + "z" * 5000,
            now=NOW,
        )
    assert (
        len(event.reason) <= 500
        and "\n" not in event.reason
        and chr(0) not in event.reason
        and chr(0x202E) not in event.reason
    )
    with db.begin() as session:
        verify_chain(session, "r1")


# ------------------------------------------------------------------------------- tamper evidence ----
def test_an_edited_event_is_detected_and_named(db: Any) -> None:
    with db.begin() as session:
        add(session, 5)
        drop_triggers(session)
    with db.begin() as session:
        session.execute(text("UPDATE audit_events SET reason = 'rewritten' WHERE id = 3"))
    with pytest.raises(AuditError) as caught, db.begin() as session:
        verify_chain(session, "r1")
    assert caught.value.code is ErrorCode.AUDIT_001 and "3" in str(caught.value)


def test_a_deleted_middle_event_is_detected(db: Any) -> None:
    with db.begin() as session:
        add(session, 5)
        drop_triggers(session)
    with db.begin() as session:
        session.execute(text("DELETE FROM audit_events WHERE id = 3"))
    with pytest.raises(AuditError) as caught, db.begin() as session:
        verify_chain(session, "r1")
    assert caught.value.code is ErrorCode.AUDIT_001


def test_a_deleted_first_event_is_detected(db: Any) -> None:
    with db.begin() as session:
        add(session, 3)
        drop_triggers(session)
    with db.begin() as session:
        session.execute(text("DELETE FROM audit_events WHERE id = 1"))
    with pytest.raises(AuditError), db.begin() as session:
        verify_chain(session, "r1")


def test_a_rewritten_event_with_a_recomputed_hash_still_breaks_the_next_link(db: Any) -> None:
    with db.begin() as session:
        events = add(session, 4)
        drop_triggers(session)
        target = events[1]
    with db.begin() as session:
        forged = dict(
            id=target.id,
            run_id=target.run_id,
            actor_type=target.actor_type,
            actor_id=target.actor_id,
            action=target.action,
            decision="allowed",
            reason="forged",
            ts=target.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            prev_hash=target.prev_hash,
        )
        digest = hashlib.sha256(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        session.execute(text("UPDATE audit_events SET reason = 'forged', entry_hash = :h WHERE id = 2"), {"h": digest})
    with pytest.raises(AuditError) as caught, db.begin() as session:
        verify_chain(session, "r1")
    assert "3" in str(caught.value)  # event 2 looks self-consistent; event 3 no longer links to it


def test_reordered_events_are_detected(db: Any) -> None:
    with db.begin() as session:
        add(session, 3)
        drop_triggers(session)
    with db.begin() as session:
        session.execute(text("UPDATE audit_events SET id = 99 WHERE id = 1"))
        session.execute(text("UPDATE audit_events SET id = 1 WHERE id = 3"))
        session.execute(text("UPDATE audit_events SET id = 3 WHERE id = 99"))
    with pytest.raises(AuditError), db.begin() as session:
        verify_chain(session, "r1")


def test_tampering_with_one_run_does_not_break_another(db: Any) -> None:
    with db.begin() as session:
        add(session, 3, "r1")
        add(session, 3, "r2", offset=10)
        drop_triggers(session)
    with db.begin() as session:
        session.execute(text("UPDATE audit_events SET reason = 'x' WHERE run_id = 'r1' AND id = 2"))
    with db.begin() as session:
        verify_chain(session, "r2")
    with pytest.raises(AuditError), db.begin() as session:
        verify_chain(session, "r1")
