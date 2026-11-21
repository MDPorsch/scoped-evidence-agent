"""The command line (docs/cli.md). The clock and the user come from an injected context, never from an environment
variable."""

from __future__ import annotations

import asyncio
import getpass
import json
import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy import select

from scopedagent import __version__
from scopedagent.adapters.pack import load_pack
from scopedagent.domain.findings import FindingDetails, ReviewDecision
from scopedagent.domain.models import Engagement, FindingDraft, Run
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, PolicyError, ScopedAgentError
from scopedagent.logs import safe_text
from scopedagent.output.report import (
    build_report,
    render_json,
    render_markdown,
    subject_of,
    write_report,
)
from scopedagent.pipeline.orchestrator import execute_run
from scopedagent.policy.authorization import AUTHORIZATION_NOTICE
from scopedagent.policy.scope import load_scope, parse_scope
from scopedagent.storage.artifacts import ArtifactStore
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.database import DataDir, open_database, upgrade_database
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
        revision = upgrade_database(_data_dir(data_dir))
    except ScopedAgentError as exc:
        raise _fail(exc) from None
    typer.echo(f"database ready: revision {revision} at {_data_dir(data_dir).root}")


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


@app.command("run")
def run_command(
    ctx: typer.Context,
    scope: Annotated[Path, typer.Option("--scope", help="The scope file.")],
    fixture: Annotated[
        Path, typer.Option("--fixture", help="The fixture pack (a YAML file) that answers the operations.")
    ],
    live: Annotated[bool, typer.Option("--live", help="Not available in this version.")] = False,
    data_dir: DataDirOption = None,
) -> None:
    """Offline run: validate the scope, collect from the pack, store redacted evidence. Opens no network connection."""
    app_ctx = _context(ctx)
    try:
        if live:
            raise PolicyError(ErrorCode.POLICY_001, "live mode is not available in this version (D-E01)")
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


def _show(finding: FindingDraft, details: FindingDetails | None, reviews: list[tuple[str, str, str, str]]) -> None:
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
                _show(finding, details, reviews)
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
