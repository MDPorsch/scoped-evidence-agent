"""Reports (M3, D-E64): one local file, built only from the database, that a reader can check.

What goes in: the run, the scope's hash, coverage, every observation (by id, type, status, subject and hashes), every artifact (by
hash, never by content), every finding with its details and its reviews, and the audit chain's state. What stays out: artifact
content, raw headers and bodies, the name of whoever started the run, the time of the export, and any path or host name. So the
same run exports byte-identical files. Text a person typed (a reviewer's name and reason) passes through the redactor.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from scopedagent.domain.models import Artifact, AuditEvent, Engagement, Observation, Run, Target
from scopedagent.errors import AuditError, ErrorCode, PolicyError, ReportError, StateError
from scopedagent.pipeline.redact import redact_text
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.repositories import get_finding_details, list_findings, list_reviews

SCHEMA_VERSION = 1
NOTES = (
    "A draft is not a finding: every draft is unvalidated until a person reviews it, and an assessment is not a confirmation.",
    "The scope file is a restriction, not proof of authorization. This report does not show that anyone authorized the test: confirm that outside this tool.",
    "Only what the scope lists was examined, with the rules in the catalogue. No draft is not proof that nothing is wrong, and anything that was not collected was not examined.",
    "Evidence is stored redacted, and redaction is best effort: read this report before sharing it.",
    "Artifact contents are not part of this report: each artifact is identified by its sha256.",
)
_LABELS = {
    "DRAFT": "DRAFT: not validated",
    "NEEDS_VALIDATION": "DRAFT: not validated",
    "VALIDATED": "VALIDATED by a reviewer",
    "FALSE_POSITIVE": "FALSE_POSITIVE: closed by a reviewer",
    "REMEDIATED": "REMEDIATED: reported fixed, not yet verified",
    "VERIFIED": "VERIFIED: the fix was checked by a reviewer",
}


def _when(moment: datetime | None) -> str | None:
    return None if moment is None else moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def subject_of(kind: str, payload: dict[str, Any]) -> str:
    """What an observation is about, in one short line."""
    if kind == "dns_metadata":
        return str(payload["host"])
    if kind == "tls_metadata":
        return f"{payload['host']}:{payload['port']}"
    if kind == "ai_probe":
        return f"probe {payload['probe_set']}[{payload['probe_index']}]"
    return f"{payload['scheme']}://{payload['host']}:{payload['port']}{payload['path']}"


def _clean(value: str) -> str:
    return redact_text(value).text


def _coverage(run: Run, observations: list[dict[str, Any]]) -> dict[str, Any]:
    ok = sum(1 for o in observations if o["status"] == "ok")
    other: dict[str, int] = {}
    for observation in observations:
        if observation["status"] != "ok":
            other[observation["status"]] = other.get(observation["status"], 0) + 1
    planned = run.planned_operations
    return {
        "planned": planned,
        "recorded": len(observations),
        "ok": ok,
        "other": dict(sorted(other.items())),
        "complete": planned is not None and planned > 0 and ok == planned,
    }


def _finding_entry(session: Session, finding: Any, order: dict[str, int]) -> dict[str, Any]:
    try:
        details: dict[str, Any] | None = json.loads(get_finding_details(session, finding.id).model_dump_json())
    except StateError:
        details = None  # a finding stored without an assessment (made before M3)
    evidence = sorted(finding.evidence_ids, key=lambda i: order.get(i, len(order)))
    reviews = [
        {
            "decision": review.decision,
            "reviewer": _clean(review.reviewer_id),
            "reason": _clean(review.reason),
            "status_after": review.status_after,
            "reviewed_at": _when(review.created_at),
        }
        for review in list_reviews(session, finding.id)
    ]
    return {
        "id": finding.id,
        "status": finding.status,
        "label": _LABELS[finding.status],
        "title": finding.title,
        "class": finding.category,
        "confidence": finding.confidence,
        "evidence": evidence,
        "details": details,
        "reviews": reviews,
    }


def build_report(session: Session, run_id: str, *, tool_version: str) -> dict[str, Any]:
    """Everything the report says, as plain data. Reads the database and changes nothing."""
    run = session.get(Run, run_id)
    if run is None:
        raise PolicyError(ErrorCode.POLICY_002, "no such run")
    engagement = session.get(Engagement, run.engagement_id)
    if engagement is None:  # pragma: no cover - a foreign key makes this impossible
        raise PolicyError(ErrorCode.POLICY_002, "the run's engagement is missing")
    rows = session.execute(
        select(Observation, Target)
        .join(Target, Target.id == Observation.target_id)
        .where(Observation.run_id == run_id)
        .order_by(text("observations.rowid"))
    ).all()
    observations = [
        {
            "id": o.id,
            "type": o.observation_type,
            "status": o.error_status,
            "subject": subject_of(o.observation_type, json.loads(o.normalized_json)),
            "source_hash": o.source_hash,
            "normalized_input_hash": o.normalized_input_hash,
            "collected_at": _when(o.collected_at),
        }
        for o, _target in rows
    ]
    order: dict[str, int] = {str(o["id"]): index for index, o in enumerate(observations)}
    artifacts = [
        {"sha256": a.sha256, "mime": a.mime, "size": a.size, "redaction_status": a.redaction_status}
        for a in session.scalars(select(Artifact).where(Artifact.run_id == run_id).order_by(text("artifacts.rowid")))
    ]
    try:
        verified, events = True, verify_chain(session, run_id)
    except AuditError:
        verified = False
        events = session.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.run_id == run_id)) or 0
    head = session.scalar(
        select(AuditEvent.entry_hash).where(AuditEvent.run_id == run_id).order_by(AuditEvent.id.desc()).limit(1)
    )
    scope = json.loads(engagement.scope_json)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "scoped-agent", "version": tool_version},
        "run": {
            "id": run.id,
            "state": run.state,
            "attempt": run.attempt,
            "mode": run.mode,
            "created_at": _when(run.created_at),
            "started_at": _when(run.started_at),
            "ended_at": _when(run.ended_at),
            "error_code": run.error_code,
        },
        "engagement": {
            "label": engagement.label,
            "owner_approval_ref": engagement.owner_approval_ref,
            "scope_sha256": engagement.scope_sha256,
            "expires_at": _when(engagement.expires_at),
            "mode": scope.get("mode", run.mode),
        },
        "coverage": _coverage(run, observations),
        "observations": observations,
        "artifacts": artifacts,
        "findings": [_finding_entry(session, f, order) for f in list_findings(session, run_id)],
        "audit": {"events": events, "chain_verified": verified, "head_hash": head},
        "notes": list(NOTES),
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


# ----------------------------------------------------------------------------------------------- markdown ----
_MD_SPECIAL = "\\`*_[]()<>&|#"
_MD_HTML = {"<": "&lt;", ">": "&gt;", "&": "&amp;"}


def md_escape(value: object) -> str:
    """Text that a reader sees as typed: no markup, no link, no HTML, on one line."""
    flat = " ".join(str(value).split())
    return "".join(_MD_HTML.get(ch) or (f"\\{ch}" if ch in _MD_SPECIAL else ch) for ch in flat)


def _code(value: object) -> str:
    return "`" + " ".join(str(value).split()).replace("`", "'") + "`"


def _finding_markdown(finding: dict[str, Any]) -> list[str]:
    lines = [f"### {md_escape(finding['title'])}", "", f"**{md_escape(finding['label'])}**", ""]
    lines += [
        f"- id: {_code(finding['id'])}",
        f"- status: {_code(finding['status'])}",
        f"- class: {_code(finding['class'])}",
        f"- confidence: {finding['confidence']:.2f}",
        "- evidence: " + (", ".join(_code(i) for i in finding["evidence"]) or "none"),
    ]
    details = finding["details"]
    if details is not None:
        lines += [
            f"- rule: {_code(details['rule_id'])} (version {details['rule_version']})",
            "- CWE suggestions (to verify): " + (", ".join(details["cwe_candidates"]) or "none"),
            f"- severity: unknown (suggested: {details['suggested_severity']['value']}, {md_escape(details['suggested_severity']['basis'])})",
            f"- exploitability: {details['exploitability']['assessment']} (an assessment, not a confirmation)",
            "",
            "Conditions",
            "",
            *[f"- {md_escape(c)}" for c in details["conditions"]],
        ]
        if details["facts"]:
            lines += ["", "Quoted from the target, as data", "", *[f"- {_code(f)}" for f in details["facts"]]]
        ex = details["exploitability"]
        lines += [
            "",
            "Exploitability",
            "",
            f"- attacker position: {md_escape(ex['attacker_position'])}",
            *[f"- precondition: {md_escape(p)}" for p in ex["preconditions"]],
            *[f"- unknown: {md_escape(u)}" for u in ex["unknowns"]],
            f"- basis: {md_escape(ex['basis'])}",
            "",
            "Validation steps (read-only, run by a person)",
            "",
        ]
        for step in details["validation_steps"]:
            lines += [f"{step['order']}. {_code(step['kind'])}: {md_escape(step['action'])}"]
            if step["example_invocation"]:
                lines += [f"   - command: {_code(step['example_invocation'])}"]
            lines += [
                f"   - if the condition holds: {md_escape(step['if_condition_holds'])}",
                f"   - if it does not: {md_escape(step['if_it_does_not'])}",
                f"   - record: {md_escape(step['record'])}",
                f"   - must not: {md_escape(', '.join(step['must_not']))}",
                f"   - stop if: {md_escape(step['stop_if'])}",
            ]
        if details["validation_steps_dropped"]:
            lines += [
                "",
                "Steps dropped by the checker: "
                + ", ".join(f"{_code(d['kind'])} ({d['rule']})" for d in details["validation_steps_dropped"]),
            ]
        lines += ["", "Decision guide (advice, a person decides)", ""]
        lines += [f"- {md_escape(g['outcome'])} suggests {_code(g['suggests'])}" for g in details["decision_guide"]]
        lines += ["", f"Remediation: {md_escape(details['remediation'])}"]
    lines += ["", "Reviews", ""]
    if finding["reviews"]:
        lines += [
            f"- {_code(r['decision'])} by {md_escape(r['reviewer'])} at {r['reviewed_at']}, status {_code(r['status_after'])}: {md_escape(r['reason'])}"
            for r in finding["reviews"]
        ]
    else:
        lines += ["- none"]
    return [*lines, ""]


def render_markdown(report: dict[str, Any]) -> str:
    run, engagement, coverage, audit = report["run"], report["engagement"], report["coverage"], report["audit"]
    planned = "unknown" if coverage["planned"] is None else coverage["planned"]
    lines = [
        "# Evidence report",
        "",
        f"Produced by {md_escape(report['tool']['name'])} {md_escape(report['tool']['version'])}. Drafts are not findings: see the notes.",
        "",
        "## Run",
        "",
        f"- run: {_code(run['id'])}",
        f"- state: {_code(run['state'])}, attempt {run['attempt']}, mode {_code(run['mode'])}",
        f"- created {run['created_at']}, started {run['started_at'] or 'not started'}, ended {run['ended_at'] or 'not ended'}",
        f"- engagement: {md_escape(engagement['label'])}, approval reference {_code(engagement['owner_approval_ref'])}",
        f"- scope sha256: {_code(engagement['scope_sha256'])}, expires {engagement['expires_at']}",
        "",
        "## Coverage",
        "",
        f"- planned operations: {planned}",
        f"- observations recorded: {coverage['recorded']}, ok: {coverage['ok']}",
        "- other outcomes: " + (", ".join(f"{k} {v}" for k, v in coverage["other"].items()) or "none"),
        f"- collection complete: {'yes' if coverage['complete'] else 'no'}",
        "",
        "## Observations",
        "",
    ]
    lines += [
        f"- {_code(o['id'])} {o['type']} {o['status']} {md_escape(o['subject'])}, source {_code(o['source_hash'])}, input {_code(o['normalized_input_hash'])}, collected {o['collected_at']}"
        for o in report["observations"]
    ] or ["- none"]
    lines += ["", "## Artifacts", "", "Identified by hash. Their content is not part of this report.", ""]
    lines += [
        f"- {_code(a['sha256'])} {md_escape(a['mime'])}, {a['size']} bytes, {a['redaction_status']}"
        for a in report["artifacts"]
    ] or ["- none"]
    lines += ["", "## Findings", ""]
    if report["findings"]:
        for finding in report["findings"]:
            lines += _finding_markdown(finding)
    else:
        lines += ["No draft was made. That is not proof that nothing is wrong.", ""]
    lines += [
        "## Audit trail",
        "",
        f"- events: {audit['events']}",
        f"- chain verified: {'yes' if audit['chain_verified'] else 'NO: the chain is broken'}",
        f"- head hash: {_code(audit['head_hash'])}",
        "",
        "## Notes",
        "",
        *[f"- {md_escape(n)}" for n in report["notes"]],
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------- writing it ----
def _refuse(message: str) -> ReportError:
    return ReportError(ErrorCode.REPORT_001, message)


def write_report(path: Path, content: str, *, data_dir: Path) -> str:
    """Write `content` to a NEW private file and return its sha256. Never overwrites, follows a link or writes into the data directory."""
    raw = os.fspath(path)
    if ".." in Path(raw).parts:
        raise _refuse("the output path must not contain ..")
    target = Path(os.path.abspath(raw))
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise _refuse("the output path passes through a symbolic link: use the real path")
    parent = target.parent
    if not parent.is_dir():
        raise _refuse("the output directory does not exist: nothing was created")
    real_parent, real_data = Path(os.path.realpath(parent)), Path(os.path.realpath(data_dir))
    if real_parent == real_data or real_data in real_parent.parents:
        raise _refuse("the output path is inside the data directory: write the report somewhere else")
    if os.path.lexists(target):
        raise _refuse("the output file already exists: nothing was written")
    data = content.encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".report-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, target)  # fails if the name appeared meanwhile: an existing file is never replaced
    except FileExistsError:
        raise _refuse("the output file already exists: nothing was written") from None
    except OSError:
        raise _refuse("the report could not be written") from None
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "SCHEMA_VERSION",
    "build_report",
    "md_escape",
    "render_json",
    "render_markdown",
    "subject_of",
    "write_report",
]
