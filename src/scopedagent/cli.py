"""The command line (docs/cli.md). The clock and the user come from an injected context, never from an environment
variable."""

from __future__ import annotations

import getpass
import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from sqlalchemy import select

from scopedagent.domain.models import Engagement, Run
from scopedagent.errors import ErrorCode, PolicyError, ScopedAgentError
from scopedagent.policy.authorization import AUTHORIZATION_NOTICE
from scopedagent.policy.scope import load_scope
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.database import DataDir, open_database, upgrade_database
from scopedagent.storage.repositories import MAX_PAGE, list_runs


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
app.add_typer(db_app, name="db")
app.add_typer(scope_app, name="scope")
app.add_typer(runs_app, name="runs")
app.add_typer(audit_app, name="audit")


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
