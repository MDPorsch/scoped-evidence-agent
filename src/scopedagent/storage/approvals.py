"""Approvals for live runs (D-E41): the deliberate pause before anything leaves the machine.

An approval is created by a human command, is bound to one scope hash (editing the scope invalidates it), has an expiry no later than
the scope's and the declared authorization's, and ends only by an explicit revocation. In a single-user tool the approver and the
operator are the same account: this is a pause and a record, not a second person (LIMITATIONS SE-03).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopedagent.domain.models import Approval, ApprovalRevocation
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, LiveRefused, StateError
from scopedagent.ids import new_id
from scopedagent.logs import safe_text
from scopedagent.policy.scope import LoadedScope
from scopedagent.storage.audit import append_event

MAX_APPROVAL_DAYS = 366


def _deny(session: Session, *, actor: Actor, action: str, now: datetime, reason: str, error: Exception) -> None:
    append_event(session, run_id=None, actor=actor, action=action, decision="denied", reason=reason, now=now)
    session.commit()  # the refusal is kept even though the caller's transaction ends with the error
    raise error


def grant_approval(session: Session, loaded: LoadedScope, *, until: datetime, actor: Actor, now: datetime) -> Approval:
    """Record that a human allows live runs of exactly this scope until `until`."""
    if actor.type is not ActorType.HUMAN:
        _deny(
            session,
            actor=actor,
            action="approval.grant",
            now=now,
            reason="only a human grants an approval",
            error=StateError(ErrorCode.STATE_003, "only a human may grant an approval"),
        )
    config = loaded.config
    authorization = config.authorization
    if config.mode != "live" or authorization is None:
        raise LiveRefused(ErrorCode.LIVE_002, "an approval is for a scope with mode live and an authorization block")
    limit = min(config.expires_at, authorization.not_after, now + timedelta(days=MAX_APPROVAL_DAYS))
    if not now < until <= limit:
        raise LiveRefused(
            ErrorCode.LIVE_002,
            "an approval must end in the future and no later than the scope's expiry and the authorization's not_after",
        )
    approval = Approval(
        id=new_id(),
        scope_sha256=loaded.sha256,
        engagement=authorization.engagement,
        granted_by=actor.id,
        granted_at=now,
        expires_at=until,
    )
    session.add(approval)
    session.flush()
    append_event(
        session,
        run_id=None,
        actor=actor,
        action="approval.grant",
        decision="allowed",
        reason=f"{approval.id} scope {loaded.sha256[:12]} until {until.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        now=now,
    )
    return approval


def revoke_approval(session: Session, approval_id: str, *, actor: Actor, reason: str, now: datetime) -> None:
    if actor.type is not ActorType.HUMAN:
        _deny(
            session,
            actor=actor,
            action="approval.revoke",
            now=now,
            reason="only a human revokes an approval",
            error=StateError(ErrorCode.STATE_003, "only a human may revoke an approval"),
        )
    cleaned = safe_text(reason, 500).strip()
    if not cleaned:
        raise LiveRefused(ErrorCode.LIVE_002, "a revocation needs a reason")
    if session.get(Approval, approval_id) is None:
        raise LiveRefused(ErrorCode.LIVE_002, "no such approval")
    if session.get(ApprovalRevocation, approval_id) is not None:
        raise LiveRefused(ErrorCode.LIVE_002, "that approval is already revoked")
    session.add(ApprovalRevocation(approval_id=approval_id, revoked_by=actor.id, revoked_at=now, reason=cleaned))
    session.flush()
    append_event(
        session,
        run_id=None,
        actor=actor,
        action="approval.revoke",
        decision="allowed",
        reason=f"{approval_id} {cleaned}",
        now=now,
    )


def status_of(session: Session, approval: Approval, *, now: datetime) -> str:
    if session.get(ApprovalRevocation, approval.id) is not None:
        return "revoked"
    return "expired" if now >= approval.expires_at else "valid"


def list_approvals(session: Session, *, now: datetime) -> list[tuple[Approval, str]]:
    rows = session.scalars(select(Approval).order_by(Approval.granted_at, Approval.id)).all()
    return [(approval, status_of(session, approval, now=now)) for approval in rows]


def require_approval(session: Session, approval_id: str, loaded: LoadedScope, *, now: datetime) -> Approval:
    """The approval, or `LiveRefused` saying which condition failed. Checked before anything is resolved or started."""
    approval = session.get(Approval, approval_id)
    if approval is None:
        raise LiveRefused(ErrorCode.LIVE_002, "no such approval: create one with `scoped-agent approvals grant`")
    if approval.scope_sha256 != loaded.sha256:
        raise LiveRefused(ErrorCode.LIVE_002, "the scope changed since this approval was granted: grant a new one")
    state = status_of(session, approval, now=now)
    if state != "valid":
        raise LiveRefused(ErrorCode.LIVE_002, f"this approval is {state}")
    return approval
