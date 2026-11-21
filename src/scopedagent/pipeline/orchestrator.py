"""Run a scope against a fixture pack: plan, reserve budget, collect, store, and close the run honestly (M2).

Order is deterministic (the plan's order), one operation at a time. Each operation reserves one unit of budget
first; when the budget is spent the rest are recorded as `budget_exhausted`, never skipped silently. An
observation and its artifact are stored in one transaction. When collection ends, the rules draft findings from what
was stored, all in one transaction (M3). A crash or a cancellation ends the run as FAILED or CANCELED with what was
collected kept and the audit trail intact. Parallelism (`max_parallelism`) arrives with live mode: offline collection
is sequential so it is reproducible.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select

from scopedagent.adapters.base import Adapter, AdapterResult
from scopedagent.adapters.offline import build_adapters, error_result
from scopedagent.adapters.pack import Pack
from scopedagent.domain.models import Artifact, Target
from scopedagent.domain.outcome import Coverage, ErrorStatus, ExitCode, coverage_from, exit_code_for
from scopedagent.domain.state_machine import Actor, ActorType, RunState
from scopedagent.errors import BudgetError
from scopedagent.pipeline.correlate import correlate_run
from scopedagent.policy.authorization import check_run_allowed
from scopedagent.policy.budget import reserve
from scopedagent.policy.scope import LoadedScope, PlannedOperation
from scopedagent.storage.artifacts import ArtifactStore
from scopedagent.storage.database import Database
from scopedagent.storage.repositories import create_run, record_observation, register_engagement, transition_run

WORKER = Actor(ActorType.WORKER, "collector")


@dataclass(frozen=True)
class RunResult:
    run_id: str
    state: str
    planned: int
    coverage: Coverage
    exit_code: ExitCode
    redactions: int
    observations: int
    artifacts: int
    findings: int
    failed: bool
    scope_sha256: str


def _kind(op: PlannedOperation) -> str:
    return "ai" if op.kind.startswith("ai_") else "web"


async def _collect_one(
    db: Database,
    store: ArtifactStore,
    run_id: str,
    op: PlannedOperation,
    adapter: Adapter,
    targets: Mapping[tuple[str, str, str, int], str],
    now: datetime,
) -> AdapterResult:
    try:
        with db.begin() as session:
            reserve(session, run_id, 1, now=now)
    except BudgetError:
        result = error_result(op, ErrorStatus.BUDGET_EXHAUSTED)
    else:
        result = await adapter.collect(op)
    with db.begin() as session:  # the artifact and the observation that cites it are stored, or neither is
        if result.body is not None:
            store.put(
                session,
                run_id=run_id,
                content=result.body,
                mime=result.body_mime or "application/octet-stream",
                now=now,
                actor=WORKER,
                redaction_status=result.body_status,
            )
        record_observation(
            session,
            run_id=run_id,
            target_id=targets[(_kind(op), op.host, op.scheme, op.port)],
            envelope=result.envelope,
            source_hash=hashlib.sha256(result.source_bytes).hexdigest(),
            collected_at=now,
            actor=WORKER,
        )
    return result


async def execute_run(
    db: Database,
    store: ArtifactStore,
    *,
    loaded: LoadedScope,
    pack: Pack,
    human: Actor,
    now: datetime,
    adapters: Mapping[str, Adapter] | None = None,
) -> RunResult:
    check_run_allowed(
        loaded, now=now, expected_sha256=loaded.sha256
    )  # live mode, a changed scope and an expiry are refused first
    with db.begin() as session:
        engagement = register_engagement(session, loaded, now=now)
        run = create_run(session, engagement, actor=human, now=now, planned_operations=len(loaded.planned))
        run_id = run.id
        targets = {
            (t.kind, t.host_canonical, t.scheme, t.port): t.id
            for t in session.scalars(select(Target).where(Target.engagement_id == engagement.id))
        }
    for step in (RunState.SCOPE_VALIDATED, RunState.QUEUED, RunState.COLLECTING):
        with db.begin() as session:
            transition_run(session, run_id, step, actor=WORKER, now=now)
    use = dict(adapters) if adapters is not None else dict(build_adapters(pack, loaded.config))
    statuses: list[ErrorStatus] = []
    redactions, failed, end_state, drafted, phase = 0, False, RunState.DRAFTED, 0, "collecting"
    try:
        for op in loaded.planned:
            result = await _collect_one(db, store, run_id, op, use[op.kind], targets, now)
            statuses.append(result.envelope.error_status)
            redactions += result.redactions
        phase = "correlating"
        with db.begin() as session:
            transition_run(session, run_id, RunState.CORRELATING, actor=WORKER, now=now)
        with db.begin() as session:  # every draft is stored, or none is
            drafted = correlate_run(session, run_id, loaded.config, now=now)
        with db.begin() as session:
            transition_run(session, run_id, RunState.DRAFTED, actor=WORKER, now=now)
    except asyncio.CancelledError:
        end_state = RunState.CANCELED
        with db.begin() as session:
            transition_run(
                session, run_id, end_state, actor=WORKER, now=now, reason=f"the run was cancelled while {phase}"
            )
    except Exception as exc:
        failed, end_state, drafted = True, RunState.FAILED, 0
        with db.begin() as session:
            transition_run(
                session,
                run_id,
                end_state,
                actor=WORKER,
                now=now,
                error_code="unexpected_error",
                reason=f"{type(exc).__name__} while {phase}",
            )
    coverage = coverage_from(len(loaded.planned), statuses)
    with db.begin() as session:
        artifacts = session.scalar(select(func.count()).select_from(Artifact).where(Artifact.run_id == run_id)) or 0
    return RunResult(
        run_id,
        end_state.value,
        len(loaded.planned),
        coverage,
        exit_code_for(coverage, drafts_needing_review=drafted, infrastructure_failure=failed),
        redactions,
        len(statuses),
        artifacts,
        drafted,
        failed,
        loaded.sha256,
    )
