"""The model's rows: wordings and calls (M4). Both are append-only. The model itself can write nothing (D-E08)."""

from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scopedagent.ai.fields import FIELDS
from scopedagent.domain.models import FindingWording, ModelCall
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, StateError
from scopedagent.storage.audit import append_event


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def list_wordings(session: Session, finding_id: str) -> list[FindingWording]:
    return list(
        session.scalars(
            select(FindingWording).where(FindingWording.finding_id == finding_id).order_by(FindingWording.id)
        )
    )


def model_usage(session: Session, run_id: str) -> tuple[int, int]:
    """(calls made, tokens spent) by one run. A refused call spends nothing and is not a call."""
    calls = session.scalar(
        select(func.count())
        .select_from(ModelCall)
        .where(ModelCall.run_id == run_id, ModelCall.status != "budget_exhausted")
    )
    tokens = session.scalar(
        select(func.coalesce(func.sum(ModelCall.input_tokens + ModelCall.output_tokens), 0)).where(
            ModelCall.run_id == run_id
        )
    )
    return int(calls or 0), int(tokens or 0)


def store_wording(
    session: Session,
    *,
    finding_id: str,
    run_id: str,
    field: str,
    index: int,
    original: str,
    wording: str,
    model: str,
    prompt_version: str,
    actor: Actor,
    now: datetime,
) -> FindingWording:
    """Keep a model's wording beside the rule's sentence. A model cannot do this itself; the refusal is audited."""
    if actor.type is ActorType.MODEL:
        append_event(
            session,
            run_id=run_id,
            actor=actor,
            action="wording.store",
            decision="denied",
            reason="the model may not store anything",
            now=now,
        )
        session.commit()
        raise StateError(ErrorCode.STATE_003, "the model may not store a wording")
    if field not in FIELDS or index < 0:
        raise ValueError("a wording is for a known field and a non-negative index")
    row = FindingWording(
        finding_id=finding_id,
        run_id=run_id,
        field=field,
        item_index=index,
        original_sha256=sha256_text(original),
        text=wording,
        model=model,
        prompt_version=prompt_version,
        created_at=now,
    )
    session.add(row)
    session.flush()
    return row
