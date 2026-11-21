"""Reword a run's drafts with a model, within a budget, checking every answer (docs/ai-adapter.md).

For each draft: take the rule's sentences that have no wording yet, hide the hosts, ask the adapter once, accept each
returned sentence only if it passes the checks, and store what passed beside the rule's text. Every failure leaves the
rule's text and is recorded. The model never sees a target's words, and nothing here can change a draft, its status or
its evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal

from sqlalchemy.orm import Session

from scopedagent.ai.config import AiConfig
from scopedagent.ai.fields import FIELDS
from scopedagent.ai.prompt import PROMPT_VERSION
from scopedagent.ai.protocol import ModelAdapter, ModelUnavailable, RewordItem, RewordReply, RewordRequest
from scopedagent.ai.validation import mask_hosts, unmask, validate_item
from scopedagent.domain.findings import FindingDetails
from scopedagent.domain.models import ModelCall
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import StateError
from scopedagent.logs import safe_text
from scopedagent.storage.audit import append_event
from scopedagent.storage.database import Database
from scopedagent.storage.repositories import get_finding_details, list_findings
from scopedagent.storage.wordings import list_wordings, model_usage, store_wording

__all__ = ["FIELDS", "Piece", "RewordSummary", "estimate_tokens", "pieces_of", "reword_run"]
WORKER = Actor(ActorType.WORKER, "reworder")


@dataclass(frozen=True)
class Piece:
    field: str
    index: int
    text: str
    limit: int

    @property
    def id(self) -> str:
        return f"{self.field}-{self.index}"


@dataclass(frozen=True)
class RewordSummary:
    findings: int = 0
    calls: int = 0
    reworded: int = 0
    kept: int = 0
    tokens: int = 0
    statuses: dict[str, int] = field(default_factory=dict)


def pieces_of(details: FindingDetails) -> list[Piece]:
    """The sentences of a draft a model may reword, in a fixed order. Facts, steps and the guide are never in it."""
    exploit = details.exploitability
    groups: list[tuple[str, list[str]]] = [
        ("condition", list(details.conditions)),
        ("precondition", list(exploit.preconditions)),
        ("unknown", list(exploit.unknowns)),
        ("attacker_position", [exploit.attacker_position]),
        ("basis", [exploit.basis]),
        ("remediation", [details.remediation]),
        ("severity_basis", [details.suggested_severity.basis]),
    ]
    return [Piece(name, i, text, FIELDS[name]) for name, texts in groups for i, text in enumerate(texts)]


def estimate_tokens(request: RewordRequest, max_output_tokens: int) -> int:
    """A cautious count before a call: the reply cap plus the prompt at three characters a token."""
    return max_output_tokens + -(-sum(len(i.text) for i in request.items) // 3)


def _input_hash(request: RewordRequest) -> str:
    body = json.dumps(
        {"v": request.prompt_version, "items": [[i.id, i.text, i.limit] for i in request.items]}, sort_keys=True
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Outcome:
    """What one call came to, after every check."""

    status: str
    detail: str
    accepted: dict[str, str]
    rejected: int
    tokens_in: int
    tokens_out: int


@dataclass(frozen=True)
class _Call:
    """What the `model_calls` row and its audit event record."""

    run_id: str
    finding_id: str
    provider: str
    model: str
    digest: str
    sent: int
    accepted: int
    rejected: int
    tokens_in: int
    tokens_out: int
    status: str
    detail: str

    @property
    def decision(self) -> Literal["allowed", "denied", "recorded"]:
        if self.status == "budget_exhausted":
            return "denied"
        return "allowed" if self.status == "ok" else "recorded"


def _pending(db: Database, run_id: str, finding_id: str | None) -> list[tuple[str, list[Piece]]]:
    """The drafts of a run that still have sentences without a wording."""
    todo: list[tuple[str, list[Piece]]] = []
    with db.begin() as session:
        for finding in list_findings(session, run_id):
            if finding_id is not None and finding.id != finding_id:
                continue
            try:
                details = get_finding_details(session, finding.id)
            except StateError:
                continue  # a finding made before M3 has no sentences to reword
            done = {(w.field, w.item_index) for w in list_wordings(session, finding.id)}
            missing = [p for p in pieces_of(details) if (p.field, p.index) not in done]
            if missing:
                todo.append((finding.id, missing))
    return todo


def _ask(adapter: ModelAdapter, request: RewordRequest) -> tuple[str, str, RewordReply]:
    """The adapter's answer, or why there is none. Only an error's class name is kept."""
    try:
        return "ok", "", adapter.reword(request)
    except ModelUnavailable as exc:
        return exc.status, exc.detail, RewordReply({}, 0, 0)
    except Exception as exc:
        return "unavailable", type(exc).__name__, RewordReply({}, 0, 0)


def _check(
    pieces: list[Piece], masked: list[str], mapping: dict[str, str], reply: RewordReply, secrets: Sequence[str]
) -> _Outcome:
    """Accept each returned sentence that passes every check, with its hosts put back; count the rest by reason."""
    if set(reply.texts) != {p.id for p in pieces}:
        return _Outcome("invalid", "the ids were not the ids sent", {}, 0, 0, 0)
    accepted: dict[str, str] = {}
    rejected: Counter[str] = Counter()
    for piece, sent in zip(pieces, masked, strict=True):
        reason = validate_item(sent, reply.texts[piece.id], limit=piece.limit, secrets=secrets)
        restored = unmask(reply.texts[piece.id], mapping)
        if reason is None and len(restored) > piece.limit:
            reason = "length"
        if reason is None:
            accepted[piece.id] = restored
        else:
            rejected[reason] += 1
    detail = ", ".join(f"{name} {count}" for name, count in sorted(rejected.items()))
    return _Outcome(
        "ok", detail, accepted, sum(rejected.values()), max(0, reply.input_tokens), max(0, reply.output_tokens)
    )


def _budget_refusal(session: Session, run_id: str, config: AiConfig, request: RewordRequest) -> str | None:
    """Why the next call may not be made, or None. The estimate counts the prompt and the reply cap (D-E69)."""
    limits = config.limits
    used_calls, used_tokens = model_usage(session, run_id)
    over = used_tokens + estimate_tokens(request, limits.max_output_tokens) > limits.max_total_tokens
    if used_calls >= limits.max_calls_per_run or over:
        return f"calls {used_calls}, tokens {used_tokens}"
    return None


def reword_run(
    db: Database,
    run_id: str,
    *,
    adapter: ModelAdapter,
    config: AiConfig,
    hosts: Sequence[str],
    now: datetime,
    finding_id: str | None = None,
    secrets: Sequence[str] = (),
) -> RewordSummary:
    """Reword what is not yet worded, finding by finding. Returns what happened; every failure keeps the rule's text."""
    todo = _pending(db, run_id, finding_id)
    statuses: Counter[str] = Counter()
    calls = reworded = kept = tokens = 0
    for fid, pieces in todo:
        masked, mapping = mask_hosts([p.text for p in pieces], hosts if config.mask_hosts else [])
        items = tuple(RewordItem(p.id, m, p.limit) for p, m in zip(pieces, masked, strict=True))
        request = RewordRequest(items, PROMPT_VERSION)
        digest = _input_hash(request)
        base = _Call(run_id, fid, adapter.provider, adapter.model, digest, 0, 0, 0, 0, 0, "", "")
        with db.begin() as session:
            refusal = _budget_refusal(session, run_id, config, request)
            if refusal is not None:
                _record(session, replace(base, status="budget_exhausted", detail=refusal), now)
        if refusal is not None:
            statuses["budget_exhausted"] += 1
            kept += len(pieces)
            continue
        status, detail, reply = _ask(adapter, request)
        outcome = (
            _check(pieces, masked, mapping, reply, secrets) if status == "ok" else _Outcome(status, detail, {}, 0, 0, 0)
        )
        with db.begin() as session:
            for piece in pieces:
                if piece.id in outcome.accepted:
                    store_wording(
                        session,
                        finding_id=fid,
                        run_id=run_id,
                        field=piece.field,
                        index=piece.index,
                        original=piece.text,
                        wording=outcome.accepted[piece.id],
                        model=adapter.model,
                        prompt_version=PROMPT_VERSION,
                        actor=WORKER,
                        now=now,
                    )
            logged = replace(
                base,
                sent=len(pieces),
                accepted=len(outcome.accepted),
                rejected=outcome.rejected,
                tokens_in=outcome.tokens_in,
                tokens_out=outcome.tokens_out,
                status=outcome.status,
                detail=outcome.detail,
            )
            _record(session, logged, now)
        calls += 1
        statuses[outcome.status] += 1
        reworded += len(outcome.accepted)
        kept += len(pieces) - len(outcome.accepted)
        tokens += outcome.tokens_in + outcome.tokens_out
    return RewordSummary(len(todo), calls, reworded, kept, tokens, dict(statuses))


def _record(session: Session, call: _Call, now: datetime) -> None:
    session.add(
        ModelCall(
            run_id=call.run_id,
            finding_id=call.finding_id,
            provider=call.provider,
            model=call.model,
            prompt_version=PROMPT_VERSION,
            input_sha256=call.digest,
            items_sent=call.sent,
            items_accepted=call.accepted,
            items_rejected=call.rejected,
            input_tokens=call.tokens_in,
            output_tokens=call.tokens_out,
            status=call.status,
            detail=safe_text(call.detail, 200).strip(),
            created_at=now,
        )
    )
    session.flush()
    reason = (
        f"{call.finding_id[:8]} model {call.model} prompt {PROMPT_VERSION} input {call.digest[:12]} "
        f"sent {call.sent} accepted {call.accepted} tokens {call.tokens_in}+{call.tokens_out}"
    )
    append_event(
        session,
        run_id=call.run_id,
        actor=WORKER,
        action="model.reword",
        decision=call.decision,
        reason=reason + ("" if call.status == "ok" else f" {call.status}"),
        now=now,
    )
