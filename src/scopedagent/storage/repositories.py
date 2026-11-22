"""Engagements, runs, observations and findings: every change is checked, audited, and made in one transaction.

Callers pass `now` explicitly; nothing here reads a clock. A refused action is recorded as a `denied` audit event and
committed before the error is raised, so a rejected attempt leaves a trace instead of rolling away with its transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime
from itertools import product

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from scopedagent.domain.findings import FindingDetails, ReviewDecision
from scopedagent.domain.models import (
    Engagement,
    FindingDetail,
    FindingDraft,
    FindingEvidence,
    FindingReview,
    Observation,
    Run,
    Target,
)
from scopedagent.domain.schemas import FindingDraftCreate, ObservationEnvelope
from scopedagent.domain.state_machine import (
    TERMINAL_RUN_STATES,
    Actor,
    ActorType,
    FindingStatus,
    RunState,
    check_finding_transition,
    check_run_transition,
)
from scopedagent.errors import ErrorCode, PolicyError, StateError
from scopedagent.ids import new_id
from scopedagent.logs import safe_text
from scopedagent.pipeline.redact import redact_text
from scopedagent.policy.scope import LoadedScope, check_not_expired, plan_api_target
from scopedagent.storage.audit import append_event

_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_PAGE = 100
_REVIEWER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@ -]{0,63}")
MAX_REASON = 1000
MIN_REF = 8  # a finding reference is a full id or a unique prefix of at least this many characters


def _deny(
    session: Session, *, run_id: str | None, actor: Actor, action: str, reason: str, now: datetime, error: Exception
) -> None:
    """Record a refusal, keep it, and re-raise the error that caused it."""
    append_event(session, run_id=run_id, actor=actor, action=action, decision="denied", reason=reason, now=now)
    session.commit()
    raise error


# ------------------------------------------------------------------------------------ engagements ----
def register_engagement(session: Session, loaded: LoadedScope, *, now: datetime) -> Engagement:
    """Store the normalised scope and its targets. The same scope registers the same engagement."""
    check_not_expired(loaded.config.expires_at, now)
    existing = session.scalars(
        select(Engagement).where(
            Engagement.label == loaded.config.engagement_id, Engagement.scope_sha256 == loaded.sha256
        )
    ).first()
    if existing is not None:
        return existing
    engagement = Engagement(
        id=new_id(),
        label=loaded.config.engagement_id,
        owner_approval_ref=loaded.config.owner_approval_ref,
        scope_sha256=loaded.sha256,
        scope_json=loaded.canonical_json,
        expires_at=loaded.config.expires_at,
        created_at=now,
        status="active",
    )
    session.add(engagement)
    for entry in loaded.config.allowed_targets:
        for scheme, port in product(entry.schemes, entry.ports):
            session.add(
                Target(
                    id=new_id(),
                    engagement_id=engagement.id,
                    host_canonical=entry.host,
                    scheme=scheme,
                    port=port,
                    allowed_path_prefixes=list(entry.allowed_paths),
                    verified_scope=True,
                    kind="web",
                )
            )
    for ai in loaded.config.ai_targets:
        paths = [
            *ai.metadata_paths,
            *([ai.probe_path] if ai.probe_path else []),
        ]  # the only paths an AI target may be contacted at
        session.add(
            Target(
                id=new_id(),
                engagement_id=engagement.id,
                host_canonical=ai.host,
                scheme=ai.scheme,
                port=ai.port,
                allowed_path_prefixes=paths,
                verified_scope=True,
                kind="ai",
                ai_target_id=ai.id,
            )
        )
    for api in loaded.config.api_targets:
        paths = list(dict.fromkeys(op.path for op in plan_api_target(api) if op.path))  # the only paths it may be sent
        session.add(
            Target(
                id=new_id(),
                engagement_id=engagement.id,
                host_canonical=api.host,
                scheme=api.scheme,
                port=api.port,
                allowed_path_prefixes=paths,
                verified_scope=True,
                kind="api",
            )
        )
    session.flush()
    return engagement


# ------------------------------------------------------------------------------------------ runs ----
def create_run(
    session: Session, engagement: Engagement, *, actor: Actor, now: datetime, planned_operations: int | None = None
) -> Run:
    if actor.type is not ActorType.HUMAN:
        _deny(
            session,
            run_id=None,
            actor=actor,
            action="run.create",
            now=now,
            reason="only a human starts a run",
            error=StateError(ErrorCode.STATE_003, "only a human may start a run"),
        )
    check_not_expired(engagement.expires_at, now)
    scope = json.loads(engagement.scope_json)
    if scope["mode"] != "offline":
        raise PolicyError(ErrorCode.POLICY_001, "live mode is not available in this version (D-E01)")
    run = Run(
        id=new_id(),
        engagement_id=engagement.id,
        created_by=actor.id,
        mode=scope["mode"],
        state=RunState.CREATED.value,
        total_budget=scope["max_requests"],
        budget_spent=0,
        attempt=1,
        created_at=now,
        planned_operations=planned_operations,
    )
    session.add(run)
    session.flush()
    append_event(
        session,
        run_id=run.id,
        actor=actor,
        action="run.created",
        decision="allowed",
        reason=f"engagement {engagement.label}",
        now=now,
    )
    return run


def transition_run(
    session: Session,
    run_id: str,
    dst: RunState,
    *,
    actor: Actor,
    now: datetime,
    reason: str = "",
    error_code: str | None = None,
    expected: RunState | None = None,
) -> Run:
    run = session.get(Run, run_id)
    if run is None:
        raise StateError(ErrorCode.STATE_001, "the run does not exist")
    src = RunState(run.state)
    summary = f"{src.value} -> {dst.value}" + (f": {reason.strip()}" if reason.strip() else "")
    if expected is not None and expected is not src:
        _deny(
            session,
            run_id=run_id,
            actor=actor,
            action="run.transition",
            now=now,
            reason=f"{summary} (expected {expected.value})",
            error=StateError(
                ErrorCode.STATE_002, f"the run is {src.value}, not {expected.value}: it changed since it was read"
            ),
        )
    try:
        check_run_transition(src, dst, actor)
    except StateError as exc:
        _deny(session, run_id=run_id, actor=actor, action="run.transition", now=now, reason=summary, error=exc)
    values: dict[str, object] = {"state": dst.value}
    if dst is RunState.COLLECTING:
        values["started_at"] = now
    if dst in TERMINAL_RUN_STATES and run.ended_at is None:
        values["ended_at"] = now
    if error_code is not None:
        values["error_code"] = error_code
    changed = session.execute(update(Run).where(Run.id == run_id, Run.state == src.value).values(**values))
    if changed.rowcount != 1:  # type: ignore[attr-defined]
        raise StateError(ErrorCode.STATE_002, "the run changed while it was being updated")
    session.expire(run)
    append_event(
        session, run_id=run_id, actor=actor, action="run.transition", decision="allowed", reason=summary, now=now
    )
    return run


def retry_run(session: Session, run_id: str, *, actor: Actor, now: datetime) -> Run:
    """A failed run is retried as a NEW run (attempt + 1); the failed one is kept and marked RETRIED (AE-15)."""
    old = session.get(Run, run_id)
    if old is None:
        raise StateError(ErrorCode.STATE_001, "the run does not exist")
    attempt = old.attempt + 1
    transition_run(session, run_id, RunState.RETRIED, actor=actor, now=now, reason=f"retry creates attempt {attempt}")
    fresh = Run(
        id=new_id(),
        engagement_id=old.engagement_id,
        created_by=actor.id,
        mode=old.mode,
        state=RunState.CREATED.value,
        total_budget=old.total_budget,
        budget_spent=0,
        attempt=attempt,
        retry_of_run_id=old.id,
        created_at=now,
        planned_operations=old.planned_operations,
    )
    session.add(fresh)
    session.flush()
    append_event(
        session,
        run_id=fresh.id,
        actor=actor,
        action="run.created",
        decision="allowed",
        reason=f"retry of {old.id} (attempt {attempt})",
        now=now,
    )
    return fresh


def list_observations(session: Session, run_id: str, *, limit: int, offset: int) -> list[Observation]:
    """The observations of one run in the order they were stored (`rowid` is the insertion order)."""
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError(f"limit must be from 1 to {MAX_PAGE}")
    if offset < 0:
        raise ValueError("offset must not be negative")
    query = (
        select(Observation)
        .where(Observation.run_id == run_id)
        .order_by(text("observations.rowid"))
        .limit(limit)
        .offset(offset)
    )
    return list(session.scalars(query))


def list_runs(session: Session, *, limit: int, offset: int) -> list[Run]:
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError(f"limit must be from 1 to {MAX_PAGE}")
    if offset < 0:
        raise ValueError("offset must not be negative")
    return list(session.scalars(select(Run).order_by(Run.created_at.desc(), Run.id.desc()).limit(limit).offset(offset)))


# --------------------------------------------------------------------------------- observations ----
def _target_kind(observation_type: str) -> str:
    """The kind of target an observation of this type may be recorded against."""
    return "ai" if observation_type.startswith("ai_") else "api" if observation_type.startswith("api_") else "web"


def record_observation(
    session: Session,
    *,
    run_id: str,
    target_id: str,
    envelope: ObservationEnvelope,
    source_hash: str,
    collected_at: datetime,
    actor: Actor,
) -> tuple[Observation, bool]:
    """Store one normalised observation. Returns (row, created); a replay of the same input returns the first row
    unchanged."""
    if not _SHA256.fullmatch(source_hash):
        raise ValueError("source_hash must be a lower-case SHA-256 hex digest")
    if collected_at.tzinfo is None:
        raise ValueError("collected_at must be timezone-aware")
    run = session.get(Run, run_id)
    if run is None:
        raise StateError(ErrorCode.STATE_001, "the run does not exist")
    if actor.type is not ActorType.WORKER:
        _deny(
            session,
            run_id=run_id,
            actor=actor,
            action="observation.record",
            now=collected_at,
            reason="only the adapter process writes observations",
            error=StateError(ErrorCode.STATE_003, "only the adapter process may write observations"),
        )
    if run.state != RunState.COLLECTING.value:
        _deny(
            session,
            run_id=run_id,
            actor=actor,
            action="observation.record",
            now=collected_at,
            reason=f"run is {run.state}",
            error=StateError(
                ErrorCode.STATE_001, f"observations are accepted only while a run is COLLECTING (it is {run.state})"
            ),
        )
    target = session.get(Target, target_id)
    wanted = (envelope.target.host, envelope.target.scheme, envelope.target.port)
    if (
        target is None
        or target.engagement_id != run.engagement_id
        or (target.host_canonical, target.scheme, target.port) != wanted
        or target.kind != _target_kind(envelope.observation_type)
    ):
        _deny(
            session,
            run_id=run_id,
            actor=actor,
            action="observation.record",
            now=collected_at,
            reason="the target is not one of this run's targets, or the observation names a different one",
            error=PolicyError(ErrorCode.POLICY_002, "the target does not belong to this run's engagement"),
        )
    input_hash = hashlib.sha256(envelope.normalized_input.encode()).hexdigest()
    existing = session.scalars(
        select(Observation).where(
            Observation.run_id == run_id,
            Observation.adapter == envelope.adapter,
            Observation.target_id == target_id,
            Observation.normalized_input_hash == input_hash,
        )
    ).first()
    if existing is not None:
        append_event(
            session,
            run_id=run_id,
            actor=actor,
            action="observation.replayed",
            decision="recorded",
            reason=f"{existing.id} {input_hash[:12]}",
            now=collected_at,
        )
        return existing, False
    payload = json.dumps(envelope.payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    observation = Observation(
        id=new_id(),
        run_id=run_id,
        target_id=target_id,
        adapter=envelope.adapter,
        observation_type=envelope.observation_type,
        normalized_json=payload,
        collected_at=collected_at,
        source_hash=source_hash,
        normalized_input_hash=input_hash,
        error_status=envelope.error_status.value,
    )
    session.add(observation)
    session.flush()
    append_event(
        session,
        run_id=run_id,
        actor=actor,
        action="observation.recorded",
        decision="allowed",
        reason=f"{envelope.observation_type} {envelope.error_status.value} {input_hash[:12]}",
        now=collected_at,
    )
    return observation, True


# -------------------------------------------------------------------------------------- findings ----
def create_finding_draft(
    session: Session,
    *,
    run_id: str,
    draft: FindingDraftCreate,
    observation_ids: Sequence[str],
    actor: Actor,
    now: datetime,
    details: FindingDetails | None = None,
) -> FindingDraft:
    run = session.get(Run, run_id)
    if run is None:
        raise StateError(ErrorCode.STATE_001, "the run does not exist")
    if actor.type is ActorType.MODEL:
        _deny(
            session,
            run_id=run_id,
            actor=actor,
            action="finding.create",
            now=now,
            reason="the model may not create a finding",
            error=StateError(ErrorCode.STATE_003, "the model may not create a finding"),
        )
    if run.state != RunState.CORRELATING.value:
        raise StateError(ErrorCode.STATE_001, f"drafts are created only while a run is CORRELATING (it is {run.state})")
    ids = list(observation_ids)
    found = session.scalar(
        select(func.count()).select_from(Observation).where(Observation.run_id == run_id, Observation.id.in_(ids))
    )
    if not ids or len(set(ids)) != len(ids) or found != len(ids):
        raise PolicyError(
            ErrorCode.POLICY_002, "a draft must cite at least one observation, each once, each from this run"
        )
    if details is not None:
        if draft.category != details.vulnerability_class.value:
            raise PolicyError(ErrorCode.POLICY_003, "the draft's category must be its vulnerability class")
        cited = {cite for step in details.validation_steps for cite in step.cites}
        if not cited <= set(ids):
            raise PolicyError(ErrorCode.POLICY_002, "a validation step may cite only the observations the draft cites")
    finding = FindingDraft(
        id=new_id(),
        run_id=run_id,
        title=draft.title,
        category=draft.category,
        confidence=draft.confidence,
        status=FindingStatus.DRAFT.value,
        reviewer_id=None,
        revision=1,
        created_at=now,
    )
    session.add(finding)
    session.flush()
    for observation_id in ids:
        session.add(FindingEvidence(finding_id=finding.id, observation_id=observation_id, run_id=run_id))
    session.flush()
    if details is not None:
        session.add(
            FindingDetail(
                finding_id=finding.id,
                run_id=run_id,
                rule_id=details.rule_id,
                rule_version=details.rule_version,
                details_json=details.model_dump_json(),
            )
        )
        session.flush()
    append_event(
        session,
        run_id=run_id,
        actor=actor,
        action="finding.created",
        decision="allowed",
        reason=f"{finding.id} cites {len(ids)} observation(s)",
        now=now,
    )
    return finding


def transition_finding(
    session: Session,
    finding_id: str,
    dst: FindingStatus,
    *,
    actor: Actor,
    now: datetime,
    reason: str = "",
    expected_revision: int | None = None,
) -> FindingDraft:
    finding = session.get(FindingDraft, finding_id)
    if finding is None:
        raise StateError(ErrorCode.STATE_001, "the finding does not exist")
    src = FindingStatus(finding.status)
    summary = f"{src.value} -> {dst.value}" + (f": {reason.strip()}" if reason.strip() else "")
    if expected_revision is not None and expected_revision != finding.revision:
        _deny(
            session,
            run_id=finding.run_id,
            actor=actor,
            action="finding.transition",
            now=now,
            reason=f"{summary} (revision {expected_revision})",
            error=StateError(ErrorCode.STATE_002, "the finding changed since it was read"),
        )
    evidence = (
        session.scalar(
            select(func.count()).select_from(FindingEvidence).where(FindingEvidence.finding_id == finding_id)
        )
        or 0
    )
    try:
        check_finding_transition(src, dst, actor=actor, reason=reason, evidence_count=evidence)
    except StateError as exc:
        _deny(
            session, run_id=finding.run_id, actor=actor, action="finding.transition", now=now, reason=summary, error=exc
        )
    values: dict[str, object] = {"status": dst.value, "revision": finding.revision + 1}
    if dst is not FindingStatus.NEEDS_VALIDATION:
        values["reviewer_id"] = actor.id
    changed = session.execute(
        update(FindingDraft)
        .where(FindingDraft.id == finding_id, FindingDraft.revision == finding.revision)
        .values(**values)
    )
    if changed.rowcount != 1:  # type: ignore[attr-defined]
        raise StateError(ErrorCode.STATE_002, "the finding changed while it was being updated")
    session.expire(finding)
    append_event(
        session,
        run_id=finding.run_id,
        actor=actor,
        action="finding.transition",
        decision="allowed",
        reason=summary,
        now=now,
    )
    return finding


# --------------------------------------------------------------------------------------- reading and review ----
def list_findings(session: Session, run_id: str) -> list[FindingDraft]:
    """The findings of a run in the order they were drafted (`rowid` is the insertion order)."""
    return list(
        session.scalars(
            select(FindingDraft).where(FindingDraft.run_id == run_id).order_by(text("finding_drafts.rowid"))
        )
    )


def get_finding_details(session: Session, finding_id: str) -> FindingDetails:
    row = session.get(FindingDetail, finding_id)
    if row is None:
        raise StateError(ErrorCode.STATE_001, "the finding has no stored details")
    return FindingDetails.model_validate_json(row.details_json)  # the database is a trust boundary: validated on read


def list_reviews(session: Session, finding_id: str) -> list[FindingReview]:
    return list(
        session.scalars(select(FindingReview).where(FindingReview.finding_id == finding_id).order_by(FindingReview.id))
    )


def resolve_finding(session: Session, ref: str) -> FindingDraft:
    """A finding by its full id or by a unique prefix of at least eight characters."""
    if len(ref) < MIN_REF:
        raise PolicyError(ErrorCode.POLICY_003, f"a finding reference is at least {MIN_REF} characters")
    escaped = ref.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    matches = list(
        session.scalars(select(FindingDraft).where(FindingDraft.id.like(f"{escaped}%", escape="\\")).limit(2))
    )
    if not matches:
        raise PolicyError(ErrorCode.POLICY_002, "no such finding")
    if len(matches) > 1:
        raise PolicyError(ErrorCode.POLICY_003, "that reference matches more than one finding: type more of it")
    return matches[0]


_DECIDES = {
    ReviewDecision.CONFIRMED: FindingStatus.VALIDATED,
    ReviewDecision.NOT_EXPLOITABLE: FindingStatus.FALSE_POSITIVE,
}


def review_finding(
    session: Session,
    finding_id: str,
    decision: ReviewDecision,
    *,
    reviewer: Actor,
    reason: str,
    now: datetime,
) -> FindingDraft:
    """Record a person's decision on a finding that waits for review (D-E57, D-E63).

    `confirmed` validates it, `not_exploitable` closes it as a false positive, `inconclusive` records the review and
    leaves it open. The reason is redacted before it is stored anywhere. Refusals are audited and kept.
    """
    finding = session.get(FindingDraft, finding_id)
    if finding is None:
        raise StateError(ErrorCode.STATE_001, "the finding does not exist")
    run_id = finding.run_id

    def deny(error: StateError, why: str) -> None:
        _deny(session, run_id=run_id, actor=reviewer, action="finding.review", now=now, reason=why, error=error)

    if reviewer.type is not ActorType.HUMAN:
        deny(StateError(ErrorCode.STATE_003, "only a human may review a finding"), "only a human may review")
    if _REVIEWER.fullmatch(reviewer.id) is None:
        deny(StateError(ErrorCode.STATE_004, "a review needs a named reviewer"), "the reviewer is not named")
    cleaned = redact_text(safe_text(reason, 2 * MAX_REASON).strip()).text
    if not cleaned or len(cleaned) > MAX_REASON:
        deny(
            StateError(ErrorCode.STATE_004, f"a review needs a reason of 1 to {MAX_REASON} characters"),
            "the reason is missing or too long",
        )
    if finding.status != FindingStatus.NEEDS_VALIDATION.value:
        deny(
            StateError(ErrorCode.STATE_001, f"a finding that is {finding.status} cannot be reviewed"),
            f"the finding is {finding.status}, not waiting for review",
        )
    destination = _DECIDES.get(decision)
    if destination is not None:
        transition_finding(session, finding_id, destination, actor=reviewer, now=now, reason=cleaned)
    run = session.get(Run, run_id)
    if run is not None and run.state == RunState.DRAFTED.value:
        transition_run(session, run_id, RunState.HUMAN_REVIEW, actor=reviewer, now=now, reason="first review")
    session.refresh(finding)
    session.add(
        FindingReview(
            finding_id=finding_id,
            run_id=run_id,
            decision=decision.value,
            reviewer_id=reviewer.id,
            reason=cleaned,
            status_after=finding.status,
            created_at=now,
        )
    )
    session.flush()
    append_event(
        session,
        run_id=run_id,
        actor=reviewer,
        action="finding.review",
        decision="allowed",
        reason=f"{finding_id[:8]} {decision.value}: {cleaned}",
        now=now,
    )
    return finding
