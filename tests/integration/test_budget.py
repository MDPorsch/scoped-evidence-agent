"""AE-12, D-E18: a request budget is reserved atomically; racing workers can never overshoot it."""

from __future__ import annotations

import threading
from typing import Any

import pytest
from sqlalchemy import select, text

from scopedagent.domain.models import AuditEvent, Run
from scopedagent.errors import BudgetError, ErrorCode, StateError
from scopedagent.policy.budget import Permit, release, reserve
from scopedagent.storage.database import DataDir, open_database, upgrade_database
from tests.support import make_database, run_in_state, seed, sql_insert, stamp

pytestmark = pytest.mark.milestone("M1")


@pytest.fixture
def db(tmp_path: Any) -> Any:
    database = make_database(tmp_path)
    yield database
    database.close()


def spent(db: Any, run_id: str) -> int:
    with db.begin() as session:
        run = session.get(Run, run_id)
        assert run is not None
        return run.budget_spent


def test_a_reservation_spends_the_budget_and_returns_a_permit(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        permit = reserve(session, run_id)
    assert permit == Permit(run_id=run_id, units=1) and spent(db, run_id) == 1
    with db.begin() as session:
        assert reserve(session, run_id, units=3).units == 3
    assert spent(db, run_id) == 4


def test_the_budget_can_be_spent_exactly_and_not_one_unit_more(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")  # total_budget is 12
    for _ in range(12):
        with db.begin() as session:
            reserve(session, run_id)
    assert spent(db, run_id) == 12
    with pytest.raises(BudgetError) as caught, db.begin() as session:
        reserve(session, run_id)
    assert caught.value.code is ErrorCode.BUDGET_001 and caught.value.exit_code == 2
    assert spent(db, run_id) == 12


def test_a_reservation_larger_than_what_is_left_changes_nothing(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        reserve(session, run_id, units=10)
    with pytest.raises(BudgetError), db.begin() as session:
        reserve(session, run_id, units=3)
    assert spent(db, run_id) == 10
    with db.begin() as session:
        reserve(session, run_id, units=2)
    assert spent(db, run_id) == 12


def test_an_exhausted_budget_leaves_a_denial_in_the_audit_trail(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        reserve(session, run_id, units=12)
    with pytest.raises(BudgetError), db.begin() as session:
        reserve(session, run_id)
    with db.begin() as session:
        denied = [
            e for e in session.scalars(select(AuditEvent).where(AuditEvent.run_id == run_id)) if e.decision == "denied"
        ]
        assert [e.action for e in denied] == ["budget.reserve"]


@pytest.mark.parametrize(
    "state", ["CREATED", "SCOPE_VALIDATED", "QUEUED", "CORRELATING", "DRAFTED", "HUMAN_REVIEW", "EXPORTED"]
)
def test_budget_is_reserved_only_while_collecting(db: Any, state: str) -> None:
    run_id = run_in_state(db, state)
    with pytest.raises(StateError) as caught, db.begin() as session:
        reserve(session, run_id)
    assert caught.value.code is ErrorCode.STATE_001
    assert spent(db, run_id) == 0


def test_a_cancelled_run_cannot_reserve_either(db: Any) -> None:
    from scopedagent.domain.state_machine import Actor, ActorType, RunState  # noqa: PLC0415
    from scopedagent.storage.repositories import transition_run  # noqa: PLC0415
    from tests.support import NOW  # noqa: PLC0415

    run_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        transition_run(session, run_id, RunState.CANCELED, actor=Actor(ActorType.HUMAN, "alice"), now=NOW)
    with pytest.raises(StateError), db.begin() as session:
        reserve(session, run_id)


def test_an_unknown_run_is_refused(db: Any) -> None:
    with pytest.raises(StateError), db.begin() as session:
        reserve(session, "nope")


@pytest.mark.parametrize("units", [0, -1, 501, 1.5, True])
def test_units_must_be_a_small_positive_integer(db: Any, units: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with pytest.raises(ValueError, match="units"), db.begin() as session:
        reserve(session, run_id, units=units)


def test_a_permit_can_be_returned_once(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with db.begin() as session:
        permit = reserve(session, run_id, units=5)
    with db.begin() as session:
        release(session, permit)
    assert spent(db, run_id) == 0
    with pytest.raises(ValueError, match="already"), db.begin() as session:
        release(session, permit)
    assert spent(db, run_id) == 0


def test_a_forged_permit_cannot_push_the_spend_below_zero(db: Any) -> None:
    run_id = run_in_state(db, "COLLECTING")
    with pytest.raises(ValueError, match="(?i)permit|spent"), db.begin() as session:
        release(session, Permit(run_id=run_id, units=3))
    assert spent(db, run_id) == 0


def test_the_database_itself_refuses_to_overspend(db: Any) -> None:
    from sqlalchemy.exc import DatabaseError  # noqa: PLC0415

    with db.begin() as session:
        seed(session, total_budget=3)
    with pytest.raises(DatabaseError), db.begin() as session:
        session.execute(text("UPDATE runs SET budget_spent = 4 WHERE id = 'r1'"))
    with db.begin() as session:
        sql_insert(
            session,
            "audit_events",
            run_id="r1",
            actor_type="worker",
            actor_id="w",
            action="x",
            decision="allowed",
            reason="",
            ts=stamp(),
            prev_hash="0" * 64,
            entry_hash="1" * 64,
        )


def test_racing_workers_never_overshoot_the_budget(tmp_path: Any) -> None:
    data_dir = DataDir(tmp_path / "data")
    upgrade_database(data_dir)
    seeder = open_database(data_dir)
    with seeder.begin() as session:
        seed(session, state="COLLECTING", total_budget=40)
    seeder.close()

    granted: list[int] = []
    refused: list[int] = []
    lock = threading.Lock()
    errors: list[BaseException] = []

    def worker() -> None:
        own = open_database(data_dir)  # one connection per worker, as separate processes would have
        try:
            for _ in range(30):
                try:
                    with own.begin() as session:
                        reserve(session, "r1")
                    with lock:
                        granted.append(1)
                except BudgetError:
                    with lock:
                        refused.append(1)
        except BaseException as exc:
            errors.append(exc)
        finally:
            own.close()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors, errors
    assert len(granted) == 40 and len(refused) == 4 * 30 - 40
    check = open_database(data_dir)
    with check.begin() as session:
        run = session.get(Run, "r1")
        assert run is not None and run.budget_spent == 40 and run.total_budget == 40
    check.close()
