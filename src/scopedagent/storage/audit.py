"""The audit trail: append-only (triggers) and hash-chained, so an edited or removed event is detectable (D-E11).

Tamper-evident, not tamper-proof: someone who can replace the whole database can rewrite a consistent chain, and
removing the
*last* events of a chain leaves no later event to notice (LIMITATIONS SE-04).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scopedagent.domain.models import STAMP, AuditEvent
from scopedagent.domain.state_machine import Actor
from scopedagent.errors import AuditError, ErrorCode
from scopedagent.logs import safe_text

GENESIS_HASH = "0" * 64
Decision = Literal["allowed", "denied", "recorded"]
_DECISIONS = ("allowed", "denied", "recorded")


def compute_entry_hash(
    *,
    id: int,
    run_id: str | None,
    actor_type: str,
    actor_id: str,
    action: str,
    decision: str,
    reason: str,
    ts: datetime,
    prev_hash: str,
) -> str:
    payload = {
        "id": id,
        "run_id": run_id,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "decision": decision,
        "reason": reason,
        "ts": ts.astimezone(UTC).strftime(STAMP),
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def append_event(
    session: Session, *, run_id: str | None, actor: Actor, action: str, decision: Decision, reason: str, now: datetime
) -> AuditEvent:
    """Add one event to the chain of `run_id` (or the run-less chain when it is None). Call inside a write
    transaction."""
    if decision not in _DECISIONS:
        raise ValueError("decision must be allowed, denied or recorded")
    if not action.strip():
        raise ValueError("action must not be blank")
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    cleaned_reason = safe_text(reason, 500)
    cleaned_action = safe_text(action, 64)
    cleaned_actor = safe_text(actor.id, 128)
    previous = session.scalars(
        select(AuditEvent.entry_hash).where(AuditEvent.run_id.is_(run_id)).order_by(AuditEvent.id.desc()).limit(1)
    ).first()
    next_id = (session.scalar(select(func.coalesce(func.max(AuditEvent.id), 0))) or 0) + 1
    moment = now.astimezone(UTC)
    prev_hash = previous or GENESIS_HASH
    entry = compute_entry_hash(
        id=next_id,
        run_id=run_id,
        actor_type=actor.type.value,
        actor_id=cleaned_actor,
        action=cleaned_action,
        decision=decision,
        reason=cleaned_reason,
        ts=moment,
        prev_hash=prev_hash,
    )
    event = AuditEvent(
        id=next_id,
        run_id=run_id,
        actor_type=actor.type.value,
        actor_id=cleaned_actor,
        action=cleaned_action,
        decision=decision,
        reason=cleaned_reason,
        ts=moment,
        prev_hash=prev_hash,
        entry_hash=entry,
    )
    session.add(event)
    session.flush()
    return event


def verify_chain(session: Session, run_id: str | None) -> int:
    """Recompute every link of one chain. Returns the event count, or raises AuditError naming the first bad one."""
    expected_prev = GENESIS_HASH
    count = 0
    for event in session.scalars(select(AuditEvent).where(AuditEvent.run_id.is_(run_id)).order_by(AuditEvent.id)):
        if event.prev_hash != expected_prev:
            raise AuditError(
                ErrorCode.AUDIT_001, f"event {event.id} does not follow the previous event: the chain is broken"
            )
        recomputed = compute_entry_hash(
            id=event.id,
            run_id=event.run_id,
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            action=event.action,
            decision=event.decision,
            reason=event.reason,
            ts=event.ts,
            prev_hash=event.prev_hash,
        )
        if recomputed != event.entry_hash:
            raise AuditError(ErrorCode.AUDIT_001, f"event {event.id} does not match its own hash: it was edited")
        expected_prev = event.entry_hash
        count += 1
    return count
