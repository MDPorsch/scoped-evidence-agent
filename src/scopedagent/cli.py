"""The command line (docs/cli.md). The clock and the user come from an injected context, never from an environment
variable."""

from __future__ import annotations

import asyncio
import getpass
import json
import os
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from sqlalchemy import select

from scopedagent import __version__
from scopedagent.adapters.pack import load_pack
from scopedagent.ai.config import AiConfig, AiLimits, Provider, default_config, load_config, save_config
from scopedagent.ai.factory import build_adapter
from scopedagent.ai.fields import label
from scopedagent.ai.prompt import PROMPT_VERSION
from scopedagent.ai.protocol import ModelUnavailable, RewordItem, RewordRequest
from scopedagent.ai.reword import reword_run
from scopedagent.ai.validation import validate_item
from scopedagent.domain.findings import FindingDetails, ReviewDecision
from scopedagent.domain.models import Engagement, FindingDraft, FindingWording, Run
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import AiError, ErrorCode, PolicyError, ScopedAgentError
from scopedagent.live.controller import LiveRequest, run_live
from scopedagent.live.runtime import DockerRuntime, Runtime, Session
from scopedagent.logs import safe_text
from scopedagent.output.report import (
    build_report,
    render_json,
    render_markdown,
    subject_of,
    write_report,
)
from scopedagent.pipeline.orchestrator import execute_run
from scopedagent.policy.authorization import AUTHORIZATION_NOTICE, attestation
from scopedagent.policy.scope import load_scope, parse_scope
from scopedagent.storage.approvals import grant_approval, list_approvals, revoke_approval
from scopedagent.storage.artifacts import ArtifactStore
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.database import DataDir, open_database, upgrade_database_with_backup
from scopedagent.storage.repositories import (
    MAX_PAGE,
    MIN_REF,
    get_finding_details,
    list_findings,
    list_observations,
    list_reviews,
    list_runs,
    resolve_finding,
    review_finding,
)
from scopedagent.storage.wordings import list_wordings
from scopedagent.template import starter_scope


def _now() -> datetime:
    return datetime.now(UTC)


def _user() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError):  # pragma: no cover - no passwd entry
        return "unknown"


@dataclass(frozen=True)
class AppContext:
    clock: Callable[[], datetime] = field(default=_now)
    user: Callable[[], str] = field(default=_user)


def default_data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / "scopedagent"


DataDirOption = Annotated[Path | None, typer.Option("--data-dir", help="Where the database and artifacts live.")]

app = typer.Typer(
    no_args_is_help=True, help="Bounded, auditable reconnaissance evidence from explicitly scoped targets."
)
db_app = typer.Typer(no_args_is_help=True, help="The evidence database.")
scope_app = typer.Typer(no_args_is_help=True, help="Scope files.")
runs_app = typer.Typer(no_args_is_help=True, help="Run history.")
audit_app = typer.Typer(no_args_is_help=True, help="The audit trail.")
observations_app = typer.Typer(no_args_is_help=True, help="Stored observations.")
findings_app = typer.Typer(no_args_is_help=True, help="Draft findings and their review.")
report_app = typer.Typer(no_args_is_help=True, help="Reports.")
approvals_app = typer.Typer(
    no_args_is_help=True, help="Approvals for live runs (a recorded pause, bound to one scope)."
)
live_app = typer.Typer(
    no_args_is_help=True, help="Live remote collection: the only commands that can leave this machine."
)
ai_app = typer.Typer(
    no_args_is_help=True, help="The optional model that may reword a draft's sentences (off by default)."
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"scoped-agent {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show the version and exit.")
    ] = False,
) -> None:
    """Bounded, auditable reconnaissance evidence from explicitly scoped targets."""


app.add_typer(db_app, name="db")
app.add_typer(scope_app, name="scope")
app.add_typer(runs_app, name="runs")
app.add_typer(audit_app, name="audit")
app.add_typer(observations_app, name="observations")
app.add_typer(findings_app, name="findings")
app.add_typer(report_app, name="report")
app.add_typer(ai_app, name="ai")
app.add_typer(approvals_app, name="approvals")
app.add_typer(live_app, name="live")


def _data_dir(chosen: Path | None) -> DataDir:
    """Resolved when the command runs, so a changed XDG_DATA_HOME is honoured."""
    return DataDir(chosen if chosen is not None else default_data_dir())


def _context(ctx: typer.Context) -> AppContext:
    return ctx.obj if isinstance(ctx.obj, AppContext) else AppContext()


def _fail(error: ScopedAgentError) -> typer.Exit:
    typer.echo(f"error {error}", err=True)
    return typer.Exit(error.exit_code)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@db_app.command("upgrade")
def db_upgrade(data_dir: DataDirOption = None) -> None:
    """Create or migrate the database. The only command that changes the schema."""
    try:
        revision, backup = upgrade_database_with_backup(_data_dir(data_dir))
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"database ready: revision {revision} at {_data_dir(data_dir).root}")
    if backup is not None:
        typer.echo(
            f"a copy of the database as it was before this upgrade is kept at {backup} (delete it when you are sure)"
        )


@scope_app.command("validate")
def scope_validate(ctx: typer.Context, file: Annotated[Path, typer.Argument(help="The scope file.")]) -> None:
    """Parse, normalise and print a scope. Stores nothing and touches no data directory."""
    try:
        loaded = load_scope(file, now=_context(ctx).clock())
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    config = loaded.config
    counts = Counter(op.kind for op in loaded.planned)
    typer.echo(f"engagement: {config.engagement_id}   mode: {config.mode}   expires: {_stamp(config.expires_at)}")
    typer.echo(f"scope sha256: {loaded.sha256}")
    breakdown = f"dns {counts['dns_metadata']}, tls {counts['tls_metadata']}, http {counts['http_metadata']}"
    if config.ai_targets:
        breakdown += f", ai metadata {counts['ai_metadata']}, ai probes {counts['ai_probe']}"
    if config.api_targets:
        breakdown += (
            f", api specs {counts['api_spec']}, api reads {counts['api_read']}, api options {counts['api_options']}"
        )
    typer.echo(
        f"targets: {len(config.allowed_targets)}   planned operations: {len(loaded.planned)} ({breakdown})"
        f"   max_requests: {config.max_requests}"
    )
    if config.ai_targets:
        tokens = sum(ai.worst_case_tokens for ai in config.ai_targets)
        typer.echo(
            f"ai targets: {len(config.ai_targets)}   probe requests: {counts['ai_probe']}   worst-case tokens: {tokens}"
        )
        for ai in config.ai_targets:
            typer.echo(f"  {ai.id} ({ai.kind}, {ai.environment})")
    if config.api_targets:
        typer.echo(
            f"api targets: {len(config.api_targets)}   api requests: {sum(a.request_count for a in config.api_targets)}"
        )
        for api in config.api_targets:
            typer.echo(
                f"  {api.id} ({api.kind}, {api.environment}): {api.request_count} of {api.limits.max_api_requests} "
                f"requests, principals: anonymous + {len(api.principals)}"
            )
    if len(loaded.planned) > config.max_requests:
        typer.echo(
            f"warning: the scope plans {len(loaded.planned)} operations but max_requests is {config.max_requests}; "
            "the run will be incomplete (exit 2)"
        )
    typer.echo(f"note: {AUTHORIZATION_NOTICE}")


def _write_starter(path: Path, text: str, *, force: bool) -> None:
    """Create the starter file: no links followed, nothing replaced without --force, no directories created."""
    if not path.parent.is_dir():
        raise PolicyError(ErrorCode.POLICY_003, f"the directory {path.parent} does not exist")
    if path.is_symlink():
        raise PolicyError(ErrorCode.POLICY_003, f"{path} is a symbolic link: choose a plain file name")
    if path.is_dir():
        raise PolicyError(ErrorCode.POLICY_003, f"{path} is a directory: give a file name")
    if path.exists() and not force:
        raise PolicyError(ErrorCode.POLICY_003, f"{path} already exists; use --force to replace it")
    try:
        with path.open("w" if force else "x", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        raise PolicyError(ErrorCode.POLICY_003, f"could not write {path}") from None


@scope_app.command("init")
def scope_init(
    ctx: typer.Context,
    file: Annotated[Path, typer.Argument(help="Where to write the starter scope.")],
    force: Annotated[bool, typer.Option("--force", help="Replace the file if it exists.")] = False,
) -> None:
    """Write a valid starter scope for an offline run, then edit it. Contacts nothing."""
    now = _context(ctx).clock()
    try:
        text = starter_scope(now)
        parse_scope(text, now=now)  # never write a starter this tool would itself refuse
        _write_starter(file, text, force=force)
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"wrote {file}")
    typer.echo(f"edit the placeholders, then check it: scoped-agent scope validate {file}")
    typer.echo(f"note: {AUTHORIZATION_NOTICE}")


@runs_app.command("list")
def runs_list(
    data_dir: DataDirOption = None,
    limit: Annotated[int, typer.Option(help=f"Page size, 1 to {MAX_PAGE}.")] = 20,
    offset: Annotated[int, typer.Option(help="Runs to skip.")] = 0,
) -> None:
    """List runs, newest first."""
    try:
        if not 1 <= limit <= MAX_PAGE or offset < 0:
            raise PolicyError(
                ErrorCode.POLICY_003, f"limit must be from 1 to {MAX_PAGE} and offset must not be negative"
            )
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                runs = list_runs(session, limit=limit, offset=offset)
                if not runs:
                    typer.echo("no runs")
                for run in runs:
                    label = session.scalars(select(Engagement.label).where(Engagement.id == run.engagement_id)).first()
                    typer.echo(f"{run.id}  {run.state:<16} attempt {run.attempt}  {_stamp(run.created_at)}  {label}")
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None


@audit_app.command("verify")
def audit_verify(
    run_id: Annotated[str, typer.Argument(help="The run whose audit chain to verify.")],
    data_dir: DataDirOption = None,
) -> None:
    """Recompute the audit hash chain of one run. Read-only."""
    try:
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                if session.get(Run, run_id) is None:
                    raise PolicyError(ErrorCode.POLICY_002, "no such run")
                count = verify_chain(session, run_id)
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"audit chain ok: {count} event(s) for run {run_id}")


DRAFT_NOTE = (
    "a draft is not a finding: a person must review each one (findings list RUN, findings show ID, findings review ID)."
)
NO_DRAFT_NOTE = (
    "no draft is not proof that nothing is wrong: only what the scope lists was collected, and only the rules in "
    "docs/correlator.md were applied."
)


def _coverage_line(result: object) -> str:
    coverage = result.coverage  # type: ignore[attr-defined]
    if coverage.complete:
        return "coverage: complete"
    parts = [
        f"{status.value}: {count}" for status, count in sorted(coverage.by_status.items(), key=lambda kv: kv[0].value)
    ]
    missing = coverage.planned - coverage.ok - sum(coverage.by_status.values())
    if missing > 0:
        parts.append(f"not run: {missing}")
    return "coverage: incomplete" + (f" ({', '.join(parts)})" if parts else "")


def _ai_hint(root: Path, result: Any) -> None:
    """One line after a run when the model is on and drafts exist. Reads the configuration only: no adapter, no key."""
    if not getattr(result, "findings", 0):
        return
    try:
        config = load_config(root)
    except AiError:
        return  # a broken AI file must not touch a run; `ai status` says what is wrong
    if config is not None and config.enabled:
        typer.echo(
            f"note: AI wording is on: run `scoped-agent findings reword {result.run_id}` to reword the drafts "
            "(the only command that calls a model)"
        )


def _print_result(result: Any) -> None:
    typer.echo(f"run {result.run_id}   state: {result.state}")
    typer.echo(f"scope sha256: {result.scope_sha256}")
    typer.echo(
        f"planned operations: {result.planned}   observations recorded: {result.observations}   "
        f"artifacts stored: {result.artifacts}   redactions: {result.redactions}"
    )
    typer.echo(_coverage_line(result))
    typer.echo(f"findings drafted: {result.findings}" + (" (awaiting review)" if result.findings else ""))
    typer.echo(f"note: {DRAFT_NOTE}")
    typer.echo(f"note: {NO_DRAFT_NOTE}")
    typer.echo(f"note: {AUTHORIZATION_NOTICE}")


@app.command("run")
def run_command(
    ctx: typer.Context,
    scope: Annotated[Path, typer.Option("--scope", help="The scope file.")],
    fixture: Annotated[
        Path, typer.Option("--fixture", help="The fixture pack (a YAML file) that answers the operations.")
    ],
    live: Annotated[bool, typer.Option("--live", help="Refused: live mode is `scoped-agent live run`.")] = False,
    data_dir: DataDirOption = None,
) -> None:
    """Offline run: validate the scope, collect from the pack, store redacted evidence. Opens no network connection."""
    app_ctx = _context(ctx)
    try:
        if live:
            raise PolicyError(
                ErrorCode.POLICY_001, "run never opens a connection: live mode is `scoped-agent live run` (D-E37)"
            )
        now = app_ctx.clock()
        loaded = load_scope(scope, now=now)
        pack = load_pack(fixture)
        directory = _data_dir(data_dir)
        database = open_database(directory)
        try:
            result = asyncio.run(
                execute_run(
                    database,
                    ArtifactStore(directory),
                    loaded=loaded,
                    pack=pack,
                    human=Actor(ActorType.HUMAN, app_ctx.user()),
                    now=now,
                )
            )
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    _print_result(result)
    _ai_hint(directory.root, result)
    raise typer.Exit(int(result.exit_code))


@observations_app.command("show")
def observations_show(
    run_id: Annotated[str, typer.Argument(help="The run whose observations to show.")],
    data_dir: DataDirOption = None,
    limit: Annotated[int, typer.Option(help=f"Page size, 1 to {MAX_PAGE}.")] = MAX_PAGE,
    offset: Annotated[int, typer.Option(help="Observations to skip.")] = 0,
    as_json: Annotated[
        bool, typer.Option("--json", help="Print each stored (redacted) payload as one JSON line.")
    ] = False,
) -> None:
    """Show the redacted observations of one run, in the order they were collected."""
    try:
        if not 1 <= limit <= MAX_PAGE or offset < 0:
            raise PolicyError(
                ErrorCode.POLICY_003, f"limit must be from 1 to {MAX_PAGE} and offset must not be negative"
            )
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                if session.get(Run, run_id) is None:
                    raise PolicyError(ErrorCode.POLICY_002, "no such run")
                rows = list_observations(session, run_id, limit=limit, offset=offset)
                if not rows:
                    typer.echo("no observations")
                elif as_json:
                    for row in rows:
                        typer.echo(row.normalized_json)
                else:
                    typer.echo("  #  type            status            subject")
                    for index, row in enumerate(rows, start=offset + 1):
                        subject = subject_of(row.observation_type, json.loads(row.normalized_json))
                        typer.echo(f"{index:>3}  {row.observation_type:<15} {row.error_status:<17} {subject}")
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None


# --------------------------------------------------------------------------------------------------- findings ----
def _label(status: str) -> str:
    return {
        "DRAFT": "DRAFT: not validated",
        "NEEDS_VALIDATION": "DRAFT: not validated",
        "VALIDATED": "VALIDATED by a reviewer",
        "FALSE_POSITIVE": "FALSE_POSITIVE: closed by a reviewer",
        "REMEDIATED": "REMEDIATED: reported fixed, not yet verified",
        "VERIFIED": "VERIFIED: the fix was checked by a reviewer",
    }[status]


@findings_app.command("list")
def findings_list(
    run_id: Annotated[str, typer.Argument(help="The run whose drafts to list.")], data_dir: DataDirOption = None
) -> None:
    """List the drafts of one run. A draft is not a finding until a person validates it."""
    try:
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                if session.get(Run, run_id) is None:
                    raise PolicyError(ErrorCode.POLICY_002, "no such run")
                findings = list_findings(session, run_id)
                if not findings:
                    typer.echo("no findings drafted")
                else:
                    typer.echo(
                        "id        status                 class                                confidence  title"
                    )
                    for finding in findings:
                        typer.echo(
                            f"{finding.id[:MIN_REF]}  {_label(finding.status):<22} {finding.category:<36} "
                            f"{finding.confidence:>10.2f}  {safe_text(finding.title, 160)}"
                        )
                    typer.echo(f"note: {DRAFT_NOTE}")
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None


def _show_details(details: FindingDetails) -> None:
    echo = typer.echo
    echo(f"rule: {details.rule_id} (version {details.rule_version})")
    echo("cwe: " + (", ".join(details.cwe_candidates) or "none") + " (suggestions to verify)")
    echo(f"severity: unknown (suggested: {details.suggested_severity.value.value})")
    echo(f"  severity basis: {details.suggested_severity.basis}")
    echo("conditions:")
    for condition in details.conditions:
        echo(f"  - {condition}")
    if details.facts:
        echo("facts (quoted from the target, as data):")
        for fact in details.facts:
            echo(f"  - {fact}")
    ex = details.exploitability
    echo(f"exploitability: {ex.assessment.value} (an assessment, not a confirmation)")
    echo(f"  attacker position: {ex.attacker_position}")
    for item in ex.preconditions:
        echo(f"  precondition: {item}")
    for item in ex.unknowns:
        echo(f"  unknown: {item}")
    echo(f"  basis: {ex.basis}")
    echo("validation steps (read-only, run by a person):")
    for step in details.validation_steps:
        echo(f"  {step.order}. {step.kind.value}")
        echo(f"     action: {step.action}")
        if step.example_invocation:
            echo(f"     command: {step.example_invocation}")
        echo(f"     if the condition holds: {step.if_condition_holds}")
        echo(f"     if it does not: {step.if_it_does_not}")
        echo(f"     record: {step.record}")
        echo(f"     must not: {', '.join(step.must_not)}")
        echo(f"     stop if: {step.stop_if}")
    if details.validation_steps_dropped:
        echo(
            "steps dropped by the checker: "
            + ", ".join(f"{d.kind} ({d.rule})" for d in details.validation_steps_dropped)
        )
    echo("decision guide (advice; a person decides):")
    for entry in details.decision_guide:
        echo(f"  - {entry.outcome} -> {entry.suggests.value}")
    echo(f"remediation: {details.remediation}")


def _show(
    finding: FindingDraft,
    details: FindingDetails | None,
    reviews: list[tuple[str, str, str, str]],
    wordings: Sequence[FindingWording] = (),
) -> None:
    echo = typer.echo
    echo(_label(finding.status))
    echo(f"title: {safe_text(finding.title, 160)}")
    echo(f"id: {finding.id}")
    echo(f"status: {finding.status}")
    echo(f"class: {finding.category}")
    echo(f"confidence: {finding.confidence:.2f}")
    echo("evidence: " + ", ".join(finding.evidence_ids))
    if details is not None:
        _show_details(details)
    if wordings:
        echo("wording by a model (not verified; the rule's text above is authoritative):")
        for wording in wordings:
            echo(f"  - {label(wording.field, wording.item_index)}: {safe_text(wording.text, 600)}")
        echo(f"  written by {safe_text(wordings[0].model, 64)}, prompt {safe_text(wordings[0].prompt_version, 32)}")
    if reviews:
        echo("reviews:")
        for decision, reviewer, reason, status_after in reviews:
            echo(f"  - {decision} by {reviewer}: {reason} (status {status_after})")
    else:
        echo("reviews: none")


@findings_app.command("show")
def findings_show(
    finding_ref: Annotated[str, typer.Argument(help="A finding id, or its first eight characters or more.")],
    data_dir: DataDirOption = None,
) -> None:
    """Show one draft in full: its conditions, assessment, validation steps and reviews."""
    try:
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                finding = resolve_finding(session, finding_ref)
                try:
                    details: FindingDetails | None = get_finding_details(session, finding.id)
                except ScopedAgentError:
                    details = None
                reviews = [
                    (r.decision, r.reviewer_id, r.reason, r.status_after) for r in list_reviews(session, finding.id)
                ]
                _show(finding, details, reviews, list_wordings(session, finding.id))
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None


class DecisionChoice(StrEnum):
    CONFIRMED = ReviewDecision.CONFIRMED.value
    NOT_EXPLOITABLE = ReviewDecision.NOT_EXPLOITABLE.value
    INCONCLUSIVE = ReviewDecision.INCONCLUSIVE.value


@findings_app.command("review")
def findings_review(
    ctx: typer.Context,
    finding_ref: Annotated[str, typer.Argument(help="A finding id, or its first eight characters or more.")],
    decision: Annotated[DecisionChoice, typer.Option("--decision", help="confirmed, not_exploitable or inconclusive.")],
    reviewer: Annotated[str, typer.Option("--reviewer", help="Your name, recorded with the decision.")],
    reason: Annotated[str, typer.Option("--reason", help="Why. Required for every decision.")],
    data_dir: DataDirOption = None,
) -> None:
    """Record a person's decision. You must type the first eight characters of the finding id to confirm."""
    app_ctx = _context(ctx)
    try:
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                finding_id = resolve_finding(session, finding_ref).id
            typed = typer.prompt(
                f"Type the first {MIN_REF} characters of the finding id ({finding_id[:MIN_REF]}) to confirm",
                default="",
                show_default=False,
            )
            if typed.strip() != finding_id[:MIN_REF]:
                raise PolicyError(ErrorCode.POLICY_003, "the confirmation did not match: nothing was changed")
            with database.begin() as session:
                finding = review_finding(
                    session,
                    finding_id,
                    ReviewDecision(decision.value),
                    reviewer=Actor(ActorType.HUMAN, reviewer.strip()),
                    reason=reason,
                    now=app_ctx.clock(),
                )
                typer.echo(
                    f"finding {finding_id[:MIN_REF]}: {decision.value} -> {finding.status} "
                    f"(reviewer {safe_text(reviewer, 64)})"
                )
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None


# ----------------------------------------------------------------------------------------------------- report ----
class ReportFormat(StrEnum):
    JSON = "json"
    MD = "md"


@report_app.command("export")
def report_export(
    run_id: Annotated[str, typer.Argument(help="The run to report on.")],
    report_format: Annotated[ReportFormat, typer.Option("--format", help="json or md.")],
    output: Annotated[Path, typer.Option("--output", help="A new file. An existing file is never replaced.")],
    data_dir: DataDirOption = None,
) -> None:
    """Write one local report built from the database. Drafts are labelled; no artifact content is included."""
    try:
        directory = _data_dir(data_dir)
        database = open_database(directory)
        try:
            with database.begin() as session:
                report = build_report(session, run_id, tool_version=__version__)
        finally:
            database.close()
        content = render_json(report) if report_format is ReportFormat.JSON else render_markdown(report)
        digest = write_report(output, content, data_dir=directory.root)
        typer.echo(f"wrote {output} ({len(content.encode('utf-8'))} bytes)")
        typer.echo(f"sha256: {digest}")
    except ScopedAgentError as exc:
        raise _fail(exc) from None


# --------------------------------------------------------------------------------------------------------- ai ----
KEY_HELP = "the environment variable that holds the API key (never the key itself)"
SENT = (
    "what is sent: rule text only (the fixed sentences of a draft: conditions, preconditions, unknowns, attacker "
    "position, basis, remediation, severity basis). It never sends what a target said, observation payloads, "
    "artifacts, headers, bodies, certificates, credentials, the scope file, or reviewer names and reasons."
)
SAMPLE = "The certificate is self-signed, so it cannot be chained to a trusted authority."


def _load_ai(directory: DataDir) -> AiConfig | None:
    return load_config(directory.root)


def _require_on(directory: DataDir) -> AiConfig:
    config = _load_ai(directory)
    if config is None or not config.enabled:
        raise AiError(ErrorCode.AI_002, "AI wording is off: run `scoped-agent ai enable` to turn it on")
    return config


def _key_for(config: AiConfig, environ: Mapping[str, str]) -> str:
    if config.provider == "offline":
        return ""
    key = environ.get(config.key_env, "")
    if not key:
        raise AiError(
            ErrorCode.AI_002,
            f"{config.key_env} is not set: export {config.key_env}=... in the shell that runs this command "
            "(the key is never stored)",
        )
    return key


def _key_line(config: AiConfig, environ: Mapping[str, str]) -> str | None:
    if config.provider == "offline":
        return None
    if environ.get(config.key_env):
        return f"{config.key_env} is set"
    return f"{config.key_env} is not set: export {config.key_env}=... before you use it (the key is never stored)"


@ai_app.command("status")
def ai_status(data_dir: DataDirOption = None) -> None:
    """Whether the model is on, which one, its limits and whether its key variable is set. Never prints the key."""
    try:
        config = _load_ai(_data_dir(data_dir))
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    if config is None or not config.enabled:
        typer.echo("AI wording: off")
        typer.echo("nothing in the tool needs it; turn it on with: scoped-agent ai enable")
        return
    echo = typer.echo
    echo("AI wording: on")
    echo(f"provider: {config.provider}")
    echo(f"model: {config.model}")
    line = _key_line(config, os.environ)
    if line:
        echo(f"key: {line}")
    echo(f"hosts masked: {'yes' if config.mask_hosts else 'no'}")
    limits = config.limits
    echo(
        f"limits: {limits.max_calls_per_run} calls per run, {limits.max_output_tokens} output tokens per call, "
        f"{limits.max_total_tokens} tokens per run"
    )
    echo("sent: rule sentences only; never what a target said (docs/ai-adapter.md)")


@ai_app.command("enable")
def ai_enable(
    provider: Annotated[
        Provider, typer.Option("--provider", help="anthropic (Claude) or offline (no connection).")
    ] = "anthropic",
    model: Annotated[str | None, typer.Option("--model", help="The model to use. Default: claude-opus-5-5.")] = None,
    key_env: Annotated[str, typer.Option("--key-env", help=KEY_HELP)] = "ANTHROPIC_API_KEY",
    mask_hosts: Annotated[
        bool, typer.Option("--mask-hosts/--no-mask-hosts", help="Replace host names before sending.")
    ] = True,
    yes: Annotated[bool, typer.Option("--yes", help="Do not ask for the typed confirmation.")] = False,
    data_dir: DataDirOption = None,
) -> None:
    """Turn the optional model on. Shows what is sent, asks you to type `enable`, writes a private file."""
    try:
        directory = _data_dir(data_dir)
        try:
            base = default_config(provider)
            config = AiConfig(
                enabled=True,
                provider=provider,
                model=model if model is not None else base.model,
                key_env=key_env,
                mask_hosts=mask_hosts,
                limits=AiLimits(),
            )
        except ValidationError:
            raise AiError(
                ErrorCode.AI_001, "the model name or the key variable name is not valid (letters, digits, . _ - only)"
            ) from None
        _load_ai(directory)  # a broken or unsafe file is refused rather than replaced
        if provider == "anthropic" and not yes:
            typer.echo(f"AI wording would use {config.model} through the official SDK at api.anthropic.com.")
            typer.echo(SENT)
            typer.echo(
                "Host names are replaced by placeholders before sending."
                if mask_hosts
                else "Host names are sent as they are (--no-mask-hosts)."
            )
            typer.echo("run never calls the model; only `scoped-agent findings reword` does, within a budget.")
            if typer.prompt("Type enable to turn it on", default="", show_default=False).strip() != "enable":
                raise PolicyError(ErrorCode.POLICY_003, "the confirmation did not match: nothing was changed")
        save_config(directory.root, config)
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    echo = typer.echo
    if provider == "offline":
        echo(f"AI wording is on ({config.provider}, {config.model}): no connection is made")
    else:
        echo(f"AI wording is on ({config.provider}, {config.model})")
        if not mask_hosts:
            echo("warning: host names are sent as they are")
        echo(_key_line(config, os.environ) or "")
        echo("next: scoped-agent ai test, then scoped-agent findings reword RUN")


@ai_app.command("disable")
def ai_disable(data_dir: DataDirOption = None) -> None:
    """Turn the model off. The configuration file and every saved wording stay."""
    try:
        directory = _data_dir(data_dir)
        config = _load_ai(directory)
        if config is None or not config.enabled:
            typer.echo("AI wording was not on")
            return
        save_config(directory.root, config.model_copy(update={"enabled": False}))
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo("AI wording is off: the saved wordings stay and show under the rule's text")


@ai_app.command("test")
def ai_test(data_dir: DataDirOption = None) -> None:
    """Send one fixed sample sentence to check the model, the key and the checks. Nothing is stored."""
    try:
        config = _require_on(_data_dir(data_dir))
        key = _key_for(config, os.environ)
        adapter = build_adapter(config, os.environ)
        request = RewordRequest((RewordItem("condition-0", SAMPLE, 300),), PROMPT_VERSION)
        try:
            reply = adapter.reword(request)
        except ModelUnavailable as exc:
            typer.echo(f"{exc.status}: {exc.detail}")
            raise typer.Exit(1) from None
        text = reply.texts.get("condition-0", "")
        reason = validate_item(SAMPLE, text, limit=300, secrets=[key] if key else [])
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    if reason is not None:
        typer.echo(
            f"rejected: the answer failed the check '{reason}' (the model works, but this answer would be dropped)"
        )
        raise typer.Exit(1)
    typer.echo(f"accepted ({adapter.provider}, {adapter.model}; tokens {reply.input_tokens}+{reply.output_tokens})")
    typer.echo(f"  sent:   {SAMPLE}")
    typer.echo(f"  wording: {safe_text(text, 300)}")


def _scope_hosts(scope_json: str) -> list[str]:
    scope = json.loads(scope_json)
    hosts = [e["host"] for e in scope.get("allowed_targets", []) if isinstance(e.get("host"), str)]
    hosts += [a["host"] for a in scope.get("ai_targets", []) if isinstance(a.get("host"), str)]
    return hosts


@findings_app.command("reword")
def findings_reword(
    ctx: typer.Context,
    run_id: Annotated[str, typer.Argument(help="The run whose drafts to reword.")],
    finding_ref: Annotated[
        str | None, typer.Option("--finding", help="Only this finding (id or first eight characters).")
    ] = None,
    data_dir: DataDirOption = None,
) -> None:
    """Ask the optional model to reword the sentences of a run's drafts. The rule's text is kept and shown first."""
    app_ctx = _context(ctx)
    try:
        directory = _data_dir(data_dir)
        config = _require_on(directory)
        database = open_database(directory)
        try:
            with database.begin() as session:
                run = session.get(Run, run_id)
                if run is None:
                    raise PolicyError(ErrorCode.POLICY_002, "no such run")
                engagement = session.get(Engagement, run.engagement_id)
                hosts = _scope_hosts(engagement.scope_json) if engagement is not None else []
                chosen = resolve_finding(session, finding_ref).id if finding_ref is not None else None
            key = _key_for(config, os.environ)
            adapter = build_adapter(config, os.environ)
            summary = reword_run(
                database,
                run_id,
                adapter=adapter,
                config=config,
                hosts=hosts,
                now=app_ctx.clock(),
                finding_id=chosen,
                secrets=[key] if key else [],
            )
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    noun = "finding" if summary.findings == 1 else "findings"
    typer.echo(
        f"reworded {summary.reworded} sentences in {summary.findings} {noun} ({adapter.model}, prompt {PROMPT_VERSION})"
    )
    calls = ", ".join(f"{count} {name}" for name, count in sorted(summary.statuses.items())) or "0"
    typer.echo(f"calls: {calls}   tokens: {summary.tokens}   kept as the rule wrote them: {summary.kept}")
    typer.echo(
        "note: the rule's own sentences are what every draft shows first; "
        "a wording sits under them, labelled as not verified."
    )
    if any(name != "ok" for name in summary.statuses):
        raise typer.Exit(2)


# ------------------------------------------------------------------------------------------- approvals ----
def _parse_until(text: str, now: datetime) -> datetime:
    try:
        moment = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise PolicyError(ErrorCode.POLICY_003, "--until is a UTC time like 2026-12-01T00:00:00Z") from None
    if moment <= now:
        raise PolicyError(ErrorCode.POLICY_003, "--until must be in the future")
    return moment


@approvals_app.command("grant")
def approvals_grant(
    ctx: typer.Context,
    scope: Annotated[Path, typer.Option("--scope", help="The live scope this approval is for.")],
    until: Annotated[str, typer.Option("--until", help="When it ends, UTC: 2026-12-01T00:00:00Z.")],
    data_dir: DataDirOption = None,
) -> None:
    """Record that live runs of exactly this scope are allowed until a time. You type its hash's start to confirm."""
    app_ctx = _context(ctx)
    try:
        now = app_ctx.clock()
        loaded = load_scope(scope, now=now)
        end = _parse_until(until, now)
        database = open_database(_data_dir(data_dir))
        try:
            typer.echo(f"scope {loaded.config.engagement_id}   sha256 {loaded.sha256}")
            typer.echo(attestation(loaded))
            typed = typer.prompt(
                f"Type the first {MIN_REF} characters of the scope hash ({loaded.sha256[:MIN_REF]}) to approve",
                default="",
                show_default=False,
            )
            if typed.strip() != loaded.sha256[:MIN_REF]:
                raise PolicyError(ErrorCode.POLICY_003, "the confirmation did not match: nothing was recorded")
            with database.begin() as session:
                approval = grant_approval(
                    session, loaded, until=end, actor=Actor(ActorType.HUMAN, app_ctx.user()), now=now
                )
                approval_id = approval.id
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"approval {approval_id} recorded until {_stamp(end)} for scope {loaded.sha256[:MIN_REF]}")
    typer.echo("use it with: scoped-agent live run --approval-id " + approval_id + " --ack-authorization ...")


@approvals_app.command("list")
def approvals_list(ctx: typer.Context, data_dir: DataDirOption = None) -> None:
    """Every approval, with whether it is still valid."""
    now = _context(ctx).clock()
    try:
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                rows = list_approvals(session, now=now)
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    if not rows:
        typer.echo("no approvals")
        return
    typer.echo("id                                scope     expires               status    by / engagement")
    for approval, state in rows:
        typer.echo(
            f"{approval.id}  {approval.scope_sha256[:MIN_REF]}  {_stamp(approval.expires_at)}  {state:<8}  "
            f"{safe_text(approval.granted_by, 40)} / {safe_text(approval.engagement, 60)}"
        )


@approvals_app.command("revoke")
def approvals_revoke(
    ctx: typer.Context,
    approval_id: Annotated[str, typer.Argument(help="The approval to end.")],
    reason: Annotated[str, typer.Option("--reason", help="Why. Required.")],
    data_dir: DataDirOption = None,
) -> None:
    """End an approval. A revoked approval is kept, marked, and never valid again."""
    app_ctx = _context(ctx)
    try:
        database = open_database(_data_dir(data_dir))
        try:
            with database.begin() as session:
                revoke_approval(
                    session,
                    approval_id,
                    actor=Actor(ActorType.HUMAN, app_ctx.user()),
                    reason=reason,
                    now=app_ctx.clock(),
                )
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"approval {approval_id} revoked")


# ---------------------------------------------------------------------------------------------- live run ----
def _credentials(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, env = value.partition("=")
        if not separator or not name or not env or name in result:
            raise PolicyError(
                ErrorCode.POLICY_003,
                "--credential is NAME=ENVIRONMENT_VARIABLE, once per name (the value is never given here)",
            )
        result[name] = env
    return result


@live_app.command("run")
def live_run(
    ctx: typer.Context,
    scope: Annotated[Path, typer.Option("--scope", help="A scope with mode live.")],
    approval_id: Annotated[str, typer.Option("--approval-id", help="From `approvals grant` for this exact scope.")],
    image: Annotated[str, typer.Option("--image", help="The collector image, pinned by digest: name@sha256:...")],
    acknowledge: Annotated[
        bool, typer.Option("--ack-authorization", help="Required on every live run: you are saying yes, now.")
    ] = False,
    credential: Annotated[
        list[str] | None,
        typer.Option(
            "--credential", help="TARGET or TARGET/PRINCIPAL=ENVVAR (the name of the variable that holds the key)."
        ),
    ] = None,
    data_dir: DataDirOption = None,
) -> None:
    """Collect from the declared hosts, inside an isolated container that proves its isolation first."""
    app_ctx = _context(ctx)
    try:
        now = app_ctx.clock()
        loaded = load_scope(scope, now=now)
        request = LiveRequest(
            loaded=loaded,
            human=Actor(ActorType.HUMAN, app_ctx.user()),
            now=now,
            approval_id=approval_id,
            acknowledged=acknowledge,
            image=image,
            credentials=_credentials(credential or []),
        )
        directory = _data_dir(data_dir)
        database = open_database(directory)
        try:
            result = run_live(
                database, ArtifactStore(directory), request, runtime=_LazyRuntime(image), environ=os.environ
            )
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"note: {attestation(loaded)}")
    _print_result(result)
    raise typer.Exit(int(result.exit_code))


def _runtime(image: str) -> Runtime:
    """The container runtime. A function so a test can put a fake in its place without a Docker daemon."""
    return DockerRuntime(image)


class _LazyRuntime:
    """Builds the container runtime only when a container is actually needed: after every gate has passed."""

    def __init__(self, image: str) -> None:
        self._image = image

    def start(self, *, credential_envs: list[str], out_dir: Path) -> Session:
        return _runtime(self._image).start(credential_envs=credential_envs, out_dir=out_dir)
