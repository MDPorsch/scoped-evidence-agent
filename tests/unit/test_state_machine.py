"""D-E08, D-E15, X-05: the run and finding state machines, checked over every possible pair."""

from __future__ import annotations

from itertools import product

import pytest

from scopedagent.domain.state_machine import (
    Actor,
    ActorType,
    FindingStatus,
    RunState,
    check_finding_transition,
    check_run_transition,
)
from scopedagent.errors import ErrorCode, StateError

pytestmark = pytest.mark.milestone("M1")

R = RunState
F = FindingStatus
ACTIVE = [R.CREATED, R.SCOPE_VALIDATED, R.QUEUED, R.COLLECTING, R.CORRELATING, R.DRAFTED, R.HUMAN_REVIEW]

# Written from the spec (section 7), independently of the implementation.
RUN_ALLOWED: dict[RunState, set[RunState]] = {
    R.CREATED: {R.SCOPE_VALIDATED, R.FAILED, R.CANCELED},
    R.SCOPE_VALIDATED: {R.QUEUED, R.FAILED, R.CANCELED},
    R.QUEUED: {R.COLLECTING, R.FAILED, R.CANCELED},
    R.COLLECTING: {R.CORRELATING, R.FAILED, R.CANCELED},
    R.CORRELATING: {R.DRAFTED, R.FAILED, R.CANCELED},
    R.DRAFTED: {R.HUMAN_REVIEW, R.FAILED, R.CANCELED},
    R.HUMAN_REVIEW: {R.EXPORTED, R.FAILED, R.CANCELED},
    R.EXPORTED: set(),
    R.CANCELED: set(),
    R.RETRIED: set(),
    R.FAILED: {R.RETRIED},
}
HUMAN_ONLY_RUN = {R.EXPORTED, R.RETRIED}

FINDING_ALLOWED: dict[FindingStatus, set[FindingStatus]] = {
    F.DRAFT: {F.NEEDS_VALIDATION},
    F.NEEDS_VALIDATION: {F.VALIDATED, F.FALSE_POSITIVE},
    F.VALIDATED: {F.REMEDIATED},
    F.REMEDIATED: {F.VERIFIED},
    F.FALSE_POSITIVE: set(),
    F.VERIFIED: set(),
}

HUMAN = Actor(ActorType.HUMAN, "alice")
WORKER = Actor(ActorType.WORKER, "worker-1")
MODEL = Actor(ActorType.MODEL, "model-x")


def test_the_spec_lists_every_state() -> None:
    assert {s.value for s in RunState} == {s.name for s in RUN_ALLOWED}
    assert {s.value for s in FindingStatus} == {s.name for s in FINDING_ALLOWED}


@pytest.mark.parametrize(("src", "dst"), list(product(RunState, RunState)))
def test_a_human_may_make_exactly_the_documented_run_transitions(src: RunState, dst: RunState) -> None:
    if dst in RUN_ALLOWED[src]:
        check_run_transition(src, dst, HUMAN)
    else:
        with pytest.raises(StateError) as caught:
            check_run_transition(src, dst, HUMAN)
        assert caught.value.code is ErrorCode.STATE_001


@pytest.mark.parametrize(("src", "dst"), [(s, d) for s in RunState for d in RUN_ALLOWED[s]])
def test_a_worker_may_make_every_documented_run_transition_except_export_and_retry(
    src: RunState, dst: RunState
) -> None:
    if dst in HUMAN_ONLY_RUN:
        with pytest.raises(StateError) as caught:
            check_run_transition(src, dst, WORKER)
        assert caught.value.code is ErrorCode.STATE_003
    else:
        check_run_transition(src, dst, WORKER)


@pytest.mark.parametrize(("src", "dst"), list(product(RunState, RunState)))
def test_the_model_may_make_no_run_transition_at_all(src: RunState, dst: RunState) -> None:
    with pytest.raises(StateError) as caught:
        check_run_transition(src, dst, MODEL)
    assert caught.value.code in {ErrorCode.STATE_003, ErrorCode.STATE_001}
    if dst in RUN_ALLOWED[src]:
        assert caught.value.code is ErrorCode.STATE_003


def test_every_active_state_can_fail_or_be_cancelled_and_terminal_states_are_final() -> None:
    for state in ACTIVE:
        assert {R.FAILED, R.CANCELED} <= RUN_ALLOWED[state]
    for terminal in (R.EXPORTED, R.CANCELED, R.RETRIED):
        for dst in RunState:
            with pytest.raises(StateError):
                check_run_transition(terminal, dst, HUMAN)
    assert RUN_ALLOWED[R.FAILED] == {R.RETRIED}


# ---------------------------------------------------------------------------------- findings ----
@pytest.mark.parametrize(("src", "dst"), list(product(FindingStatus, FindingStatus)))
def test_a_human_with_a_reviewer_reason_and_evidence_makes_exactly_the_documented_finding_transitions(
    src: FindingStatus, dst: FindingStatus
) -> None:
    if dst in FINDING_ALLOWED[src]:
        check_finding_transition(src, dst, actor=HUMAN, reason="checked the headers", evidence_count=1)
    else:
        with pytest.raises(StateError) as caught:
            check_finding_transition(src, dst, actor=HUMAN, reason="checked the headers", evidence_count=1)
        assert caught.value.code is ErrorCode.STATE_001


def test_a_worker_may_only_move_a_draft_to_needs_validation() -> None:
    check_finding_transition(F.DRAFT, F.NEEDS_VALIDATION, actor=WORKER, reason="", evidence_count=1)
    for src, dst in [
        (F.NEEDS_VALIDATION, F.VALIDATED),
        (F.NEEDS_VALIDATION, F.FALSE_POSITIVE),
        (F.VALIDATED, F.REMEDIATED),
        (F.REMEDIATED, F.VERIFIED),
    ]:
        with pytest.raises(StateError) as caught:
            check_finding_transition(src, dst, actor=WORKER, reason="because", evidence_count=3)
        assert caught.value.code is ErrorCode.STATE_003


@pytest.mark.parametrize(("src", "dst"), list(product(FindingStatus, FindingStatus)))
def test_the_model_can_never_move_a_finding(src: FindingStatus, dst: FindingStatus) -> None:
    with pytest.raises(StateError) as caught:
        check_finding_transition(src, dst, actor=MODEL, reason="I am sure", evidence_count=5)
    assert caught.value.code in {ErrorCode.STATE_003, ErrorCode.STATE_001}
    if dst in FINDING_ALLOWED[src]:
        assert caught.value.code is ErrorCode.STATE_003


@pytest.mark.parametrize("dst", [F.VALIDATED, F.FALSE_POSITIVE])
def test_a_review_decision_needs_a_reason_an_evidence_link_and_a_named_reviewer(dst: FindingStatus) -> None:
    for reason, count, actor in [
        ("", 1, HUMAN),
        ("   ", 1, HUMAN),
        ("ok", 0, HUMAN),
        ("ok", -1, HUMAN),
        ("ok", 1, Actor(ActorType.HUMAN, "")),
        ("ok", 1, Actor(ActorType.HUMAN, "  ")),
    ]:
        with pytest.raises(StateError) as caught:
            check_finding_transition(F.NEEDS_VALIDATION, dst, actor=actor, reason=reason, evidence_count=count)
        assert caught.value.code is ErrorCode.STATE_004


def test_remediation_and_verification_need_the_same_review_data() -> None:
    for src, dst in [(F.VALIDATED, F.REMEDIATED), (F.REMEDIATED, F.VERIFIED)]:
        with pytest.raises(StateError) as caught:
            check_finding_transition(src, dst, actor=HUMAN, reason="", evidence_count=1)
        assert caught.value.code is ErrorCode.STATE_004
        check_finding_transition(src, dst, actor=HUMAN, reason="done", evidence_count=1)


def test_an_actor_cannot_be_built_from_an_unknown_type() -> None:
    with pytest.raises(ValueError, match="actor"):
        Actor("robot", "x")  # type: ignore[arg-type]
