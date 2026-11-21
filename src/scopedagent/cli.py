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
from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy import select

from scopedagent import __version__
from scopedagent.adapters.pack import load_pack
from scopedagent.domain.models import Engagement, Run
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, PolicyError, ScopedAgentError
from scopedagent.pipeline.orchestrator import execute_run
from scopedagent.policy.authorization import AUTHORIZATION_NOTICE
from scopedagent.policy.scope import load_scope, parse_scope
from scopedagent.storage.artifacts import ArtifactStore
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.database import DataDir, open_database, upgrade_database
from scopedagent.storage.repositories import MAX_PAGE, list_observations, list_runs
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


CORRELATION_NOTE = (
    "correlation and findings are not built yet: this run collected evidence only, and exit code 0 means "
    "the collection was complete, not that nothing is wrong."
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
    typer.echo(f"note: {CORRELATION_NOTE}")
    typer.echo(f"note: {AUTHORIZATION_NOTICE}")
    raise typer.Exit(int(result.exit_code))


def _subject(kind: str, payload: dict[str, object]) -> str:
    if kind == "dns_metadata":
        return str(payload["host"])
    if kind == "tls_metadata":
        return f"{payload['host']}:{payload['port']}"
    if kind == "ai_probe":
        return f"probe {payload['probe_set']}[{payload['probe_index']}]"
    return f"{payload['scheme']}://{payload['host']}:{payload['port']}{payload['path']}"


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
                        subject = _subject(row.observation_type, json.loads(row.normalized_json))
                        typer.echo(f"{index:>3}  {row.observation_type:<15} {row.error_status:<17} {subject}")
        finally:
            database.close()
    except ScopedAgentError as exc:
        raise _fail(exc) from None
