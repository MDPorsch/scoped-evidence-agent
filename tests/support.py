"""Shared test helpers. No hidden clock: every call that needs the time is given one."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)

PACKS = ("healthy", "misconfigured", "poisoned")
SCOPE_FILES = {name: FIXTURES / "approved_scope" / f"lab-{name}.yaml" for name in PACKS}
AI_PACK = "ai-support-bot"
SCOPE_FILES[AI_PACK] = FIXTURES / "approved_scope" / f"{AI_PACK}.yaml"  # the AI-system scope (not one of PACKS)
PASSIVE_PACK = "passive"
SCOPE_FILES[PASSIVE_PACK] = FIXTURES / "approved_scope" / f"{PASSIVE_PACK}.yaml"  # the passive-checks scope (Stage 2a)
API_DRIFT_PACK = "api-drift"
SCOPE_FILES[API_DRIFT_PACK] = (
    FIXTURES / "approved_scope" / f"{API_DRIFT_PACK}.yaml"
)  # api-orders plus the spec_drift check
API_PACK = "api-orders"
SCOPE_FILES[API_PACK] = FIXTURES / "approved_scope" / f"{API_PACK}.yaml"  # the API scope (not one of PACKS)


def assemble(*parts: str) -> str:
    """Join parts at run time. A call cannot be constant-folded, so no secret-shaped literal ever reaches the bytecode either."""
    return "".join(parts)


def scope_text(name: str = "healthy") -> str:
    return SCOPE_FILES[name].read_text(encoding="utf-8")


def scope_dict(name: str = "healthy") -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(scope_text(name))
    return loaded


def dump(data: Any) -> str:
    """YAML text for a scope dict. A str that looks like a timestamp is quoted by the dumper."""
    return yaml.safe_dump(data, sort_keys=False)


def ai_scope_dict() -> dict[str, Any]:
    return scope_dict(AI_PACK)


def pack(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((FIXTURES / "web_responses" / f"{name}.yaml").read_text(encoding="utf-8"))
    return loaded


def finding_golden(name: str) -> list[dict[str, Any]]:
    """The hand-derived expected drafts of a pack (fixtures/expected_findings): the M3 oracle."""
    import json  # noqa: PLC0415

    loaded: list[dict[str, Any]] = json.loads((FIXTURES / "expected_findings" / f"{name}.json").read_text("utf-8"))
    return loaded


def golden(name: str) -> list[dict[str, Any]]:
    import json  # noqa: PLC0415

    loaded: list[dict[str, Any]] = json.loads((FIXTURES / "expected_observations" / f"{name}.json").read_text("utf-8"))
    return loaded


# ------------------------------------------------------------------------------ database helpers ----
STAMP = "%Y-%m-%dT%H:%M:%S.%fZ"  # the stored form of every timestamp (part of the schema contract)


def stamp(moment: datetime = NOW) -> str:
    return moment.astimezone(UTC).strftime(STAMP)


def sql_insert(session: Any, table: str, **columns: Any) -> None:
    from sqlalchemy import text  # noqa: PLC0415

    names = ", ".join(columns)
    marks = ", ".join(f":{name}" for name in columns)
    session.execute(text(f"INSERT INTO {table} ({names}) VALUES ({marks})"), columns)


def seed(session: Any, **overrides: Any) -> dict[str, str]:
    """One engagement, one target, one run: the smallest valid graph, written with raw SQL."""
    ids = {"engagement": "e1", "target": "t1", "run": "r1"}
    sql_insert(
        session,
        "engagements",
        id="e1",
        label="lab",
        owner_approval_ref="local-lab-consent",
        scope_sha256="a" * 64,
        scope_json="{}",
        expires_at=stamp(),
        created_at=stamp(),
        status="active",
    )
    sql_insert(
        session,
        "targets",
        id="t1",
        engagement_id="e1",
        host_canonical="lab.example.invalid",
        scheme="https",
        port=443,
        allowed_path_prefixes="[]",
        verified_scope=1,
    )
    run: dict[str, Any] = {
        "id": "r1",
        "engagement_id": "e1",
        "created_by": "alice",
        "mode": "offline",
        "state": "CREATED",
        "total_budget": 12,
        "budget_spent": 0,
        "attempt": 1,
        "created_at": stamp(),
    }
    run.update(overrides)
    sql_insert(session, "runs", **run)
    return ids


# ------------------------------------------------------------------------------ service helpers ----
def make_database(tmp_path: Path) -> Any:
    from scopedagent.storage.database import DataDir, open_database, upgrade_database  # noqa: PLC0415

    data_dir = DataDir(tmp_path / "data")
    upgrade_database(data_dir)
    return open_database(data_dir)


def healthy_loaded() -> Any:
    from scopedagent.policy.scope import parse_scope  # noqa: PLC0415

    return parse_scope(scope_text("healthy"), now=NOW)


def run_in_state(db: Any, state: str, *, scope: str = "healthy") -> str:
    """Create an engagement and a run and walk it, as a worker, to `state`. Returns the run id."""
    from scopedagent.domain.state_machine import Actor, ActorType, RunState  # noqa: PLC0415
    from scopedagent.policy.scope import parse_scope  # noqa: PLC0415
    from scopedagent.storage.repositories import create_run, register_engagement, transition_run  # noqa: PLC0415

    worker = Actor(ActorType.WORKER, "worker-1")
    human = Actor(ActorType.HUMAN, "alice")
    path = [
        RunState.SCOPE_VALIDATED,
        RunState.QUEUED,
        RunState.COLLECTING,
        RunState.CORRELATING,
        RunState.DRAFTED,
        RunState.HUMAN_REVIEW,
        RunState.EXPORTED,
    ]
    with db.begin() as session:
        engagement = register_engagement(session, parse_scope(scope_text(scope), now=NOW), now=NOW)
        run = create_run(session, engagement, actor=human, now=NOW)
        run_id: str = run.id
    target = RunState(state)
    for step in path:
        if target is RunState.CREATED:
            break
        with db.begin() as session:
            transition_run(session, run_id, step, actor=human if step is RunState.EXPORTED else worker, now=NOW)
        if step is target:
            break
    return run_id


@contextmanager
def raw_connection(path: Path) -> Iterator[Any]:
    """A plain sqlite3 connection that commits on success and is always closed (`with sqlite3.connect()` never closes)."""
    import sqlite3  # noqa: PLC0415

    connection = sqlite3.connect(path)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


# --------------------------------------------------------------------------------- collection helpers ----
def make_env(tmp_path: Path) -> tuple[Any, Any, Any]:
    """(database, artifact store, data dir) on a fresh private store."""
    from scopedagent.storage.artifacts import ArtifactStore  # noqa: PLC0415
    from scopedagent.storage.database import DataDir, open_database, upgrade_database  # noqa: PLC0415

    data_dir = DataDir(tmp_path / "data")
    upgrade_database(data_dir)
    return open_database(data_dir), ArtifactStore(data_dir), data_dir


def observation_rows(db: Any, run_id: str) -> list[dict[str, Any]]:
    """Every observation of a run in insertion order, with its target row."""
    from sqlalchemy import text  # noqa: PLC0415

    with db.begin() as session:
        rows = (
            session.execute(
                text(
                    "SELECT o.adapter, o.observation_type, o.normalized_json, o.normalized_input_hash, o.error_status, o.source_hash, o.collected_at, "
                    "t.host_canonical, t.scheme, t.port, t.kind FROM observations o JOIN targets t ON t.id = o.target_id "
                    "WHERE o.run_id = :run ORDER BY o.rowid"
                ),
                {"run": run_id},
            )
            .mappings()
            .all()
        )
        return [dict(r) for r in rows]


def artifact_hashes(db: Any, run_id: str) -> set[str]:
    from sqlalchemy import text  # noqa: PLC0415

    with db.begin() as session:
        return set(session.execute(text("SELECT sha256 FROM artifacts WHERE run_id = :run"), {"run": run_id}).scalars())


def everything_stored(db: Any, data_dir: Any) -> str:
    """Every text value in every table, and every artifact file, as one string: what an attacker with the files could read."""
    from sqlalchemy import text  # noqa: PLC0415

    parts: list[str] = []
    with db.begin() as session:
        tables = (
            session.execute(text("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
            .scalars()
            .all()
        )
        for table in tables:
            for row in session.execute(text(f"SELECT * FROM {table}")).all():
                parts.extend(str(v) for v in row)
    if data_dir.artifacts_dir.exists():
        parts.extend(p.read_bytes().decode("latin-1") for p in data_dir.artifacts_dir.rglob("*") if p.is_file())
    return "\n".join(parts)


def pack_variant(tmp_path: Path, name: str, edit: Any) -> Path:
    """A copy of a committed pack with `edit(pack_dict)` applied; returns the new file."""
    import yaml  # noqa: PLC0415

    data = pack(name)
    edit(data)
    path = tmp_path / f"{name}-variant.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False, width=10_000), encoding="utf-8")
    return path


def observation_ids(db: Any, run_id: str) -> list[str]:
    """The ids of a run's observations in collection order."""
    from sqlalchemy import text  # noqa: PLC0415

    with db.begin() as session:
        return list(
            session.execute(
                text("SELECT id FROM observations WHERE run_id = :run ORDER BY rowid"), {"run": run_id}
            ).scalars()
        )


def run_pack(env: Any, name: str, pack_path: Path | None = None, *, loaded: Any = None, **kw: Any) -> Any:
    """Collect and correlate one of the committed scope/pack pairs (or a variant pack) as a human named alice."""
    import asyncio  # noqa: PLC0415

    from scopedagent.adapters.pack import load_pack  # noqa: PLC0415
    from scopedagent.domain.state_machine import Actor, ActorType  # noqa: PLC0415
    from scopedagent.pipeline.orchestrator import execute_run  # noqa: PLC0415
    from scopedagent.policy.scope import parse_scope  # noqa: PLC0415

    db, store, _ = env
    the_pack = load_pack(pack_path or FIXTURES / "web_responses" / f"{name}.yaml")
    human = Actor(ActorType.HUMAN, "alice")
    return asyncio.run(
        execute_run(
            db,
            store,
            loaded=loaded or parse_scope(scope_text(name), now=NOW),
            pack=the_pack,
            human=human,
            now=NOW,
            **kw,
        )
    )


def findings_of(db: Any, run_id: str) -> list[tuple[Any, Any]]:
    """Each finding of a run with its stored details, in the order it was drafted."""
    from scopedagent.storage.repositories import get_finding_details, list_findings  # noqa: PLC0415

    with db.begin() as session:
        return [(finding, get_finding_details(session, finding.id)) for finding in list_findings(session, run_id)]
