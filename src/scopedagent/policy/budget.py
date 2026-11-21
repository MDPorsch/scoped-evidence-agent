"""The request budget (D-E18, AE-12): reserved by one conditional UPDATE, so racing workers can never overshoot it.

A reservation is granted only while the run is COLLECTING and `budget_spent + units <= total_budget`. The database also
carries a CHECK that backstops this. Tokens join the budget with the AI adapter (M4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from scopedagent.domain.models import Run
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import BudgetError, ErrorCode, StateError
from scopedagent.storage.audit import append_event

MAX_UNITS = 500
_ACTOR = Actor(ActorType.WORKER, "budget")


@dataclass
class Permit:
    """One reservation. Returning it twice is refused, and one that was never granted cannot be returned."""

    run_id: str
    units: int
    _returned: bool = field(default=False, compare=False, repr=False)


def _check_units(units: object) -> int:
    if isinstance(units, bool) or not isinstance(units, int) or not 1 <= units <= MAX_UNITS:
        raise ValueError(f"units must be an integer from 1 to {MAX_UNITS}")
    return units


def reserve(session: Session, run_id: str, units: int = 1, *, now: datetime | None = None) -> Permit:
    """`now` stamps the audit event of a refusal; it defaults to the system clock."""
    _check_units(units)
    result = session.execute(
        text(
            "UPDATE runs SET budget_spent = budget_spent + :units "
            "WHERE id = :run AND state = 'COLLECTING' AND budget_spent + :units <= total_budget"
        ),
        {"units": units, "run": run_id},
    )
    if result.rowcount == 1:  # type: ignore[attr-defined]
        return Permit(run_id=run_id, units=units)
    run = session.get(Run, run_id)
    if run is None:
        raise StateError(ErrorCode.STATE_001, "the run does not exist")
    if run.state != "COLLECTING":
        raise StateError(ErrorCode.STATE_001, f"budget is reserved only while a run is COLLECTING (it is {run.state})")
    append_event(
        session,
        run_id=run_id,
        actor=_ACTOR,
        action="budget.reserve",
        decision="denied",
        reason=f"requested {units}, spent {run.budget_spent} of {run.total_budget}",
        now=now or datetime.now(UTC),
    )
    session.commit()  # keep the denial even though the caller's block is about to fail
    raise BudgetError(ErrorCode.BUDGET_001, "the request budget is spent")


def release(session: Session, permit: Permit) -> None:
    """Give back a permit whose operation never ran (for example, on cancellation)."""
    if permit._returned:
        raise ValueError("this permit was already returned")
    result = session.execute(
        text("UPDATE runs SET budget_spent = budget_spent - :units WHERE id = :run AND budget_spent >= :units"),
        {"units": permit.units, "run": permit.run_id},
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise ValueError("this permit exceeds what the run has spent")
    permit._returned = True
