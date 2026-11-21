"""M3: a person reviews a draft (D-E57, D-E63). Only a human, with a name and a reason, and the exact decision is kept."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from scopedagent.domain.findings import ReviewDecision
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, StateError
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.repositories import list_reviews, review_finding
from tests.support import NOW, assemble, everything_stored, findings_of, make_env, run_pack

pytestmark = pytest.mark.milestone("M3")

ALICE = Actor(ActorType.HUMAN, "alice")
WORKER = Actor(ActorType.WORKER, "collector")
MODEL = Actor(ActorType.MODEL, "assistant")


@pytest.fixture
def env(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


@pytest.fixture
def drafted(env: Any) -> Any:
    result = run_pack(env, "misconfigured")
    db, _, _ = env
    return db, result.run_id, [f.id for f, _ in findings_of(db, result.run_id)]


def review(
    db: Any,
    finding_id: str,
    decision: ReviewDecision = ReviewDecision.CONFIRMED,
    *,
    actor: Actor = ALICE,
    reason: str = "ran the steps; it holds",
) -> Any:
    with db.begin() as session:
        finding = review_finding(session, finding_id, decision, reviewer=actor, reason=reason, now=NOW)
        return finding.status, finding.reviewer_id, finding.revision


def state(db: Any, finding_id: str) -> tuple[str, str | None, int]:
    with db.begin() as session:
        row = session.execute(
            text("SELECT status, reviewer_id, revision FROM finding_drafts WHERE id = :f"), {"f": finding_id}
        ).one()
        return row[0], row[1], row[2]


def reviews(db: Any, finding_id: str) -> list[tuple[str, str, str, str]]:
    with db.begin() as session:
        return [(r.decision, r.reviewer_id, r.reason, r.status_after) for r in list_reviews(session, finding_id)]


def refused(db: Any, finding_id: str, code: ErrorCode, **kw: Any) -> None:
    with pytest.raises(StateError) as caught:
        review(db, finding_id, **kw)
    assert caught.value.code is code, str(caught.value)


# ------------------------------------------------------------------------------------------- the three decisions ----
def test_confirmed_validates_and_names_the_reviewer(drafted: Any) -> None:
    db, _, ids = drafted
    assert review(db, ids[0], ReviewDecision.CONFIRMED) == ("VALIDATED", "alice", 3)
    assert reviews(db, ids[0]) == [("confirmed", "alice", "ran the steps; it holds", "VALIDATED")]


def test_not_exploitable_closes_the_finding_as_a_false_positive_and_keeps_the_exact_decision(drafted: Any) -> None:
    db, _, ids = drafted
    assert review(db, ids[0], ReviewDecision.NOT_EXPLOITABLE, reason="the host is decommissioned") == (
        "FALSE_POSITIVE",
        "alice",
        3,
    )
    assert reviews(db, ids[0]) == [("not_exploitable", "alice", "the host is decommissioned", "FALSE_POSITIVE")]


def test_inconclusive_records_the_review_and_leaves_the_finding_open(drafted: Any) -> None:
    db, _, ids = drafted
    assert review(db, ids[0], ReviewDecision.INCONCLUSIVE, reason="the owner did not answer") == (
        "NEEDS_VALIDATION",
        None,
        2,
    )
    assert reviews(db, ids[0]) == [("inconclusive", "alice", "the owner did not answer", "NEEDS_VALIDATION")]
    assert state(db, ids[0]) == ("NEEDS_VALIDATION", None, 2)  # revision 1 was the DRAFT, 2 the move to review


def test_an_open_finding_can_be_reviewed_again_and_every_review_is_kept_in_order(drafted: Any) -> None:
    db, _, ids = drafted
    review(db, ids[0], ReviewDecision.INCONCLUSIVE, reason="first look")
    review(db, ids[0], ReviewDecision.INCONCLUSIVE, reason="second look")
    review(db, ids[0], ReviewDecision.CONFIRMED, reason="owner answered")
    assert [r[0] for r in reviews(db, ids[0])] == ["inconclusive", "inconclusive", "confirmed"]
    assert [r[2] for r in reviews(db, ids[0])] == ["first look", "second look", "owner answered"]
    assert state(db, ids[0])[0] == "VALIDATED"


@pytest.mark.parametrize("decision", list(ReviewDecision))
def test_a_closed_finding_cannot_be_reviewed_again(drafted: Any, decision: ReviewDecision) -> None:
    db, _, ids = drafted
    review(db, ids[0], ReviewDecision.CONFIRMED)
    refused(db, ids[0], ErrorCode.STATE_001, decision=decision)
    assert len(reviews(db, ids[0])) == 1 and state(db, ids[0])[0] == "VALIDATED"


def test_reviewing_one_finding_touches_no_other(drafted: Any) -> None:
    db, _, ids = drafted
    review(db, ids[2], ReviewDecision.CONFIRMED)
    assert [state(db, i)[0] for i in ids].count("VALIDATED") == 1
    assert all(state(db, i)[0] == "NEEDS_VALIDATION" for i in ids if i != ids[2])


# --------------------------------------------------------------------------------------------------- who and why ----
@pytest.mark.parametrize("actor", [WORKER, MODEL])
@pytest.mark.parametrize("decision", list(ReviewDecision))
def test_only_a_human_may_review(drafted: Any, actor: Actor, decision: ReviewDecision) -> None:
    db, _, ids = drafted
    refused(db, ids[0], ErrorCode.STATE_003, actor=actor, decision=decision)
    assert reviews(db, ids[0]) == [] and state(db, ids[0]) == ("NEEDS_VALIDATION", None, 2)
    with db.begin() as session:
        denied = session.execute(
            text(
                "SELECT actor_type, decision FROM audit_events WHERE action = 'finding.review' AND decision = 'denied'"
            )
        ).all()
    assert (actor.type.value, "denied") in [tuple(r) for r in denied]


@pytest.mark.parametrize("reason", ["", "   ", "\n\t"])
@pytest.mark.parametrize("decision", list(ReviewDecision))
def test_a_reason_is_required_for_every_decision(drafted: Any, reason: str, decision: ReviewDecision) -> None:
    db, _, ids = drafted
    refused(db, ids[0], ErrorCode.STATE_004, reason=reason, decision=decision)
    assert reviews(db, ids[0]) == []


@pytest.mark.parametrize("name", ["", "  ", "a" * 65, "bad;name", "x\ny", "<b>"])
def test_the_reviewer_must_be_named_with_a_plain_name(drafted: Any, name: str) -> None:
    db, _, ids = drafted
    refused(db, ids[0], ErrorCode.STATE_004, actor=Actor(ActorType.HUMAN, name))
    assert reviews(db, ids[0]) == []


def test_a_reason_over_a_thousand_characters_is_refused(drafted: Any) -> None:
    db, _, ids = drafted
    refused(db, ids[0], ErrorCode.STATE_004, reason="x" * 1001)
    review(db, ids[0], reason="x" * 1000)


def test_an_unknown_finding_is_refused(env: Any) -> None:
    db, _, _ = env
    refused(db, "no-such-finding", ErrorCode.STATE_001)


# ------------------------------------------------------------------------------------------------------ the run ----
def test_the_first_review_moves_the_run_to_human_review_and_later_ones_leave_it(drafted: Any) -> None:
    db, run_id, ids = drafted

    def run_state() -> str:
        with db.begin() as session:
            return str(session.execute(text("SELECT state FROM runs WHERE id = :r"), {"r": run_id}).scalar())

    assert run_state() == "DRAFTED"
    review(db, ids[0], ReviewDecision.INCONCLUSIVE, reason="looked")
    assert run_state() == "HUMAN_REVIEW"
    review(db, ids[1], ReviewDecision.CONFIRMED)
    assert run_state() == "HUMAN_REVIEW"


def test_a_refused_review_does_not_move_the_run(drafted: Any) -> None:
    db, run_id, ids = drafted
    refused(db, ids[0], ErrorCode.STATE_004, reason="")
    refused(db, ids[0], ErrorCode.STATE_003, actor=MODEL)
    with db.begin() as session:
        assert session.execute(text("SELECT state FROM runs WHERE id = :r"), {"r": run_id}).scalar() == "DRAFTED"


def test_the_run_is_never_exported_by_a_review(drafted: Any) -> None:
    db, run_id, ids = drafted
    for finding_id in ids:
        review(db, finding_id, ReviewDecision.CONFIRMED)
    with db.begin() as session:
        assert session.execute(text("SELECT state FROM runs WHERE id = :r"), {"r": run_id}).scalar() == "HUMAN_REVIEW"


# ------------------------------------------------------------------------------------------------------ audit ----
def test_a_review_is_audited_with_who_what_and_why_and_the_chain_verifies(drafted: Any) -> None:
    db, run_id, ids = drafted
    review(db, ids[0], ReviewDecision.CONFIRMED, reason="reproduced with the steps")
    with db.begin() as session:
        rows = session.execute(
            text(
                "SELECT action, actor_type, actor_id, decision, reason FROM audit_events WHERE run_id = :r AND action IN ('finding.review', 'finding.transition', 'run.transition') ORDER BY id"
            ),
            {"r": run_id},
        ).all()
        human = [r for r in rows if r[1] == "human"]
        assert verify_chain(session, run_id) > 0
    assert ("finding.review", "human", "alice", "allowed") in [tuple(r[:4]) for r in human]
    assert any("confirmed" in r[4] and "reproduced with the steps" in r[4] for r in human if r[0] == "finding.review")
    assert any(r[0] == "finding.transition" and "VALIDATED" in r[4] for r in human)
    assert any(r[0] == "run.transition" and "HUMAN_REVIEW" in r[4] for r in human)


def test_a_secret_pasted_into_a_reason_is_redacted_everywhere_it_could_be_stored(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, data_dir = env
    finding_id = findings_of(db, result.run_id)[0][0].id
    token = assemble("gh", "p_", "R" * 36)
    review(db, finding_id, ReviewDecision.CONFIRMED, reason=f"worked with token={token}")
    assert token not in everything_stored(db, data_dir)
    assert "[REDACTED]" in reviews(db, finding_id)[0][2]


def test_a_reason_is_stored_as_one_plain_line(drafted: Any) -> None:
    db, _, ids = drafted
    review(db, ids[0], ReviewDecision.CONFIRMED, reason="line one\nline two\ttabbed" + chr(0x202E) + "end")
    stored = reviews(db, ids[0])[0][2]
    assert "\n" not in stored and "\t" not in stored and chr(0x202E) not in stored
    assert stored.startswith("line one line two tabbed")
