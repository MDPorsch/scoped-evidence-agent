"""Correlation: read a run's stored observations, apply the rule catalogue, check the steps, store drafts (M3).

Everything happens in ONE transaction: either every draft of the run is stored, each waiting for a person, or none
is. Nothing here contacts anything. The model has no part in it: a draft is made only by a rule (D-E60).
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from scopedagent.domain.findings import FindingDetails
from scopedagent.domain.models import Observation, Target
from scopedagent.domain.schemas import FindingDraftCreate
from scopedagent.domain.state_machine import Actor, ActorType, FindingStatus
from scopedagent.pipeline.rules import ObservationView, RuleContext, RuleDraft, run_rules
from scopedagent.pipeline.steps import render_steps
from scopedagent.policy.scope import ScopeConfig
from scopedagent.storage.repositories import create_finding_draft, transition_finding

WORKER = Actor(ActorType.WORKER, "correlator")


def load_views(session: Session, run_id: str) -> tuple[ObservationView, ...]:
    """The run's observations in collection order, each with its target and its validated payload."""
    rows = session.execute(
        select(Observation, Target)
        .join(Target, Target.id == Observation.target_id)
        .where(Observation.run_id == run_id)
        .order_by(text("observations.rowid"))
    ).all()
    return tuple(
        ObservationView.build(
            observation.id,
            observation.observation_type,
            json.loads(observation.normalized_json),
            target=(target.host_canonical, target.scheme, target.port),
            error_status=observation.error_status,
            collected_at=observation.collected_at,
        )
        for observation, target in rows
    )


def details_for(draft: RuleDraft, scope: ScopeConfig) -> FindingDetails:
    """A rule's draft with its steps rendered and checked against the scope. Dropped steps are reported inside."""
    steps, dropped = render_steps(draft.specs, scope, set(draft.evidence))
    return FindingDetails.model_validate(
        {
            "rule_id": draft.rule_id,
            "rule_version": draft.rule_version,
            "vulnerability_class": draft.vulnerability_class,
            "cwe_candidates": list(draft.cwe_candidates),
            "conditions": list(draft.conditions),
            "exploitability": {
                "assessment": draft.assessment,
                "preconditions": list(draft.preconditions),
                "attacker_position": draft.attacker_position,
                "unknowns": list(draft.unknowns),
                "basis": draft.basis,
            },
            "validation_steps": steps,
            "validation_steps_dropped": dropped,
            "decision_guide": [{"outcome": o, "suggests": s} for o, s in draft.decision_guide],
            "remediation": draft.remediation,
            "suggested_severity": {"value": draft.severity, "basis": draft.severity_basis},
            "severity": "unknown",
            "facts": list(draft.facts),
            "assumptions": list(draft.assumptions),
        }
    )


def correlate_run(session: Session, run_id: str, scope: ScopeConfig, *, now: datetime) -> int:
    """Draft findings for a run that is CORRELATING. Returns how many were stored (each awaiting review)."""
    context = RuleContext(load_views(session, run_id), scope)
    stored = 0
    for draft in run_rules(context):
        create = FindingDraftCreate(
            title=draft.title, category=draft.vulnerability_class.value, confidence=draft.confidence
        )
        finding = create_finding_draft(
            session,
            run_id=run_id,
            draft=create,
            observation_ids=draft.evidence,
            actor=WORKER,
            now=now,
            details=details_for(draft, scope),
        )
        transition_finding(
            session, finding.id, FindingStatus.NEEDS_VALIDATION, actor=WORKER, now=now, reason="awaiting review"
        )
        stored += 1
    return stored
