"""The run and finding state machines, and who may move them (D-E08, D-E15).

The model is never an actor that can change anything. A worker may move a run along and may mark a draft as needing
validation, but only a human validates, dismisses, remediates or verifies a finding, and only a human exports or
retries.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from scopedagent.errors import ErrorCode, StateError


class ActorType(StrEnum):
    HUMAN = "human"
    WORKER = "worker"
    MODEL = "model"


@dataclass(frozen=True)
class Actor:
    type: ActorType
    id: str

    def __post_init__(self) -> None:
        if not isinstance(self.type, ActorType):
            raise ValueError("unknown actor type")


class RunState(StrEnum):
    CREATED = "CREATED"
    SCOPE_VALIDATED = "SCOPE_VALIDATED"
    QUEUED = "QUEUED"
    COLLECTING = "COLLECTING"
    CORRELATING = "CORRELATING"
    DRAFTED = "DRAFTED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    EXPORTED = "EXPORTED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    RETRIED = "RETRIED"


class FindingStatus(StrEnum):
    DRAFT = "DRAFT"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    VALIDATED = "VALIDATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATED = "REMEDIATED"
    VERIFIED = "VERIFIED"


_R = RunState
_OFF_RAMP = {_R.FAILED, _R.CANCELED}
RUN_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    _R.CREATED: frozenset({_R.SCOPE_VALIDATED} | _OFF_RAMP),
    _R.SCOPE_VALIDATED: frozenset({_R.QUEUED} | _OFF_RAMP),
    _R.QUEUED: frozenset({_R.COLLECTING} | _OFF_RAMP),
    _R.COLLECTING: frozenset({_R.CORRELATING} | _OFF_RAMP),
    _R.CORRELATING: frozenset({_R.DRAFTED} | _OFF_RAMP),
    _R.DRAFTED: frozenset({_R.HUMAN_REVIEW} | _OFF_RAMP),
    _R.HUMAN_REVIEW: frozenset({_R.EXPORTED} | _OFF_RAMP),
    _R.FAILED: frozenset({_R.RETRIED}),
    _R.EXPORTED: frozenset(),
    _R.CANCELED: frozenset(),
    _R.RETRIED: frozenset(),
}
HUMAN_ONLY_RUN_TARGETS = frozenset({_R.EXPORTED, _R.RETRIED})
TERMINAL_RUN_STATES = frozenset({_R.EXPORTED, _R.FAILED, _R.CANCELED, _R.RETRIED})

_F = FindingStatus
FINDING_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    _F.DRAFT: frozenset({_F.NEEDS_VALIDATION}),
    _F.NEEDS_VALIDATION: frozenset({_F.VALIDATED, _F.FALSE_POSITIVE}),
    _F.VALIDATED: frozenset({_F.REMEDIATED}),
    _F.REMEDIATED: frozenset({_F.VERIFIED}),
    _F.FALSE_POSITIVE: frozenset(),
    _F.VERIFIED: frozenset(),
}


def check_run_transition(src: RunState, dst: RunState, actor: Actor) -> None:
    if dst not in RUN_TRANSITIONS[src]:
        raise StateError(ErrorCode.STATE_001, f"a run cannot go from {src.value} to {dst.value}")
    if actor.type is ActorType.MODEL:
        raise StateError(ErrorCode.STATE_003, "the model may not change the state of a run")
    if dst in HUMAN_ONLY_RUN_TARGETS and actor.type is not ActorType.HUMAN:
        raise StateError(ErrorCode.STATE_003, f"only a human may move a run to {dst.value}")


def check_finding_transition(
    src: FindingStatus, dst: FindingStatus, *, actor: Actor, reason: str, evidence_count: int
) -> None:
    if dst not in FINDING_TRANSITIONS[src]:
        raise StateError(ErrorCode.STATE_001, f"a finding cannot go from {src.value} to {dst.value}")
    if actor.type is ActorType.MODEL:
        raise StateError(ErrorCode.STATE_003, "the model may not change the state of a finding")
    if dst is FindingStatus.NEEDS_VALIDATION:
        return  # a worker's deterministic step; the draft already has evidence
    if actor.type is not ActorType.HUMAN:
        raise StateError(ErrorCode.STATE_003, f"only a human reviewer may move a finding to {dst.value}")
    if not actor.id.strip():
        raise StateError(ErrorCode.STATE_004, "a review needs a named reviewer")
    if not reason.strip():
        raise StateError(ErrorCode.STATE_004, "a review needs a reason")
    if evidence_count < 1:
        raise StateError(ErrorCode.STATE_004, "a review needs at least one linked observation")
