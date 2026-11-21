"""M5, migration 0004 (docs/migrations.md): two tables are rebuilt so that SQLite admits the API kinds. Every row survives unchanged,
the rebuild is all or nothing, and `db upgrade` keeps a copy of the database as it was."""

from __future__ import annotations

import importlib.util
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from scopedagent.adapters.pack import load_pack
from scopedagent.errors import StoreError
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.database import (
    HEAD_REVISION,
    DataDir,
    _alembic_config,
    open_database,
    upgrade_database,
    upgrade_database_with_backup,
)
from tests.support import AI_PACK, FIXTURES, ROOT, make_env, raw_connection, run_pack

pytestmark = pytest.mark.milestone("M5")

TABLES = (
    "engagements",
    "targets",
    "runs",
    "observations",
    "artifacts",
    "finding_drafts",
    "finding_evidence",
    "finding_details",
    "finding_reviews",
    "audit_events",
    "model_calls",
    "finding_wordings",
)  # fmt: skip  (parents before children, so the rows can be inserted with foreign keys on)
MIGRATION = ROOT / "src" / "scopedagent" / "storage" / "migrations" / "versions" / "0004_api_targets.py"


def dump(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    with raw_connection(path) as connection:
        return {t: connection.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall() for t in TABLES}


def real_rows(tmp_path: Path) -> dict[str, list[tuple[Any, ...]]]:
    """Rows made by the real pipeline on a current database: two runs, with drafts, evidence and a chained audit trail."""
    env = make_env(tmp_path / "source")
    run_pack(env, "misconfigured")
    run_pack(env, AI_PACK)
    env[0].close()
    return dump(env[2].db_path)


def old_database(tmp_path: Path, rows: dict[str, list[tuple[Any, ...]]]) -> DataDir:
    """A database at revision 0003 holding those rows."""
    data_dir = DataDir(tmp_path / "old")
    data_dir.root.mkdir(mode=0o700)
    data_dir.db_path.touch(mode=0o600)
    command.upgrade(_alembic_config(data_dir.db_path), "0003")
    with raw_connection(data_dir.db_path) as connection:
        for table in TABLES:
            for row in rows[table]:
                marks = ", ".join("?" for _ in row)
                connection.execute(f"INSERT INTO {table} VALUES ({marks})", row)
    return data_dir


@pytest.fixture(scope="module")
def source_rows(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[tuple[Any, ...]]]:
    return real_rows(tmp_path_factory.mktemp("rows"))


def revision(path: Path) -> str:
    with raw_connection(path) as connection:
        return str(connection.execute("SELECT version_num FROM alembic_version").fetchone()[0])


def master(path: Path) -> dict[str, str]:
    with raw_connection(path) as connection:
        rows = connection.execute("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
    return dict(rows)


def load_migration() -> Any:
    spec = importlib.util.spec_from_file_location("migration_0004_under_test", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_upgrade_directly(path: Path, module: Any, *, foreign_keys: bool = False) -> None:
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.connect() as connection:
            if foreign_keys:
                connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            with Operations.context(MigrationContext.configure(connection)):
                module.upgrade()
    finally:
        engine.dispose()  # also when the migration raises: no connection is left to the garbage collector


# ------------------------------------------------------------------------------------- the data survives ----
def test_the_fixture_data_is_real_and_substantial(source_rows: dict[str, list[tuple[Any, ...]]]) -> None:
    assert (
        len(source_rows["observations"]) == 11
        and len(source_rows["targets"]) == 2
        and len(source_rows["finding_drafts"]) == 10
    )
    assert (
        len(source_rows["finding_evidence"]) >= 10
        and len(source_rows["audit_events"]) > 50
        and len(source_rows["artifacts"]) > 5
    )


def test_every_row_of_every_table_is_the_same_after_the_upgrade(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    assert revision(data_dir.db_path) == "0003" and dump(data_dir.db_path) == source_rows
    assert upgrade_database(data_dir) == HEAD_REVISION
    assert revision(data_dir.db_path) == HEAD_REVISION and dump(data_dir.db_path) == source_rows


def test_the_audit_chain_of_each_run_still_verifies_and_no_row_refers_to_a_missing_one(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    upgrade_database(data_dir)
    with raw_connection(data_dir.db_path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        run_ids = [r[0] for r in connection.execute("SELECT id FROM runs ORDER BY rowid")]
    db = open_database(data_dir)
    try:
        with db.begin() as session:
            assert [verify_chain(session, run_id) > 0 for run_id in run_ids] == [True, True]
    finally:
        db.close()


def test_the_new_kinds_are_accepted_and_the_old_rules_still_hold_after_the_upgrade(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    upgrade_database(data_dir)
    engagement, run = source_rows["engagements"][0][0], source_rows["runs"][0][0]
    with raw_connection(data_dir.db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO targets (id, engagement_id, host_canonical, scheme, port, allowed_path_prefixes, verified_scope, kind) "
            "VALUES ('t-api', ?, 'api.example.invalid', 'https', 443, '[]', 1, 'api')",
            (engagement,),
        )
        connection.execute(
            "INSERT INTO observations (id, run_id, target_id, adapter, observation_type, normalized_json, collected_at, source_hash, normalized_input_hash, error_status) "
            "VALUES ('o-api', ?, 't-api', 'offline_api', 'api_read', '{}', '2026-11-20T12:00:00.000000Z', ?, ?, 'ok')",
            (run, "a" * 64, "b" * 64),
        )
        for bad in (
            "UPDATE targets SET kind = 'rest' WHERE id = 't-api'",
            "UPDATE observations SET adapter = 'offline_rest' WHERE id = 'o-api'",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(bad)


def test_the_trigger_that_keeps_an_observation_in_its_engagement_is_back_and_works(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    upgrade_database(data_dir)
    assert "observations_target_in_engagement" in master(data_dir.db_path)
    with raw_connection(data_dir.db_path) as connection:
        connection.execute(
            "INSERT INTO engagements VALUES ('e-other', 'other', 'ref-123', ?, '{}', '2026-12-31T00:00:00.000000Z', '2026-11-20T00:00:00.000000Z', 'active')",
            ("c" * 64,),
        )
        connection.execute(
            "INSERT INTO targets (id, engagement_id, host_canonical, scheme, port, allowed_path_prefixes, verified_scope, kind) "
            "VALUES ('t-other', 'e-other', 'x.example.invalid', 'https', 443, '[]', 1, 'api')"
        )
        with pytest.raises(sqlite3.IntegrityError, match="different engagement"):
            connection.execute(
                "INSERT INTO observations (id, run_id, target_id, adapter, observation_type, normalized_json, collected_at, source_hash, normalized_input_hash, error_status) "
                "VALUES ('o-x', ?, 't-other', 'offline_api', 'api_read', '{}', '2026-11-20T12:00:00.000000Z', ?, ?, 'ok')",
                (source_rows["runs"][0][0], "a" * 64, "d" * 64),
            )


def test_the_upgraded_tables_are_exactly_those_of_a_new_database_and_nothing_else_changed(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    before = master(data_dir.db_path)
    upgrade_database(data_dir)
    fresh = DataDir(tmp_path / "fresh")
    upgrade_database(fresh)
    after, new = master(data_dir.db_path), master(fresh.db_path)
    assert after == new  # every table, index and trigger, byte for byte
    changed = {name for name in before if before[name] != after.get(name)}
    assert changed == {"targets", "observations"}, changed  # of what 0003 had: 0005 only adds tables
    assert set(before) <= set(after)


def test_upgrading_a_current_database_changes_nothing_and_makes_no_copy(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    upgrade_database(data_dir)
    revision_before, rows = revision(data_dir.db_path), dump(data_dir.db_path)
    assert upgrade_database_with_backup(data_dir) == (HEAD_REVISION, None)
    assert dump(data_dir.db_path) == rows and revision(data_dir.db_path) == revision_before
    assert sorted(p.name for p in data_dir.root.iterdir() if "before" in p.name) == ["evidence.sqlite.before-0003"]


# ----------------------------------------------------------------------------------------- the copy ----
def test_a_database_that_has_to_change_is_copied_aside_first_privately_and_completely(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    new_revision, backup = upgrade_database_with_backup(data_dir)
    assert new_revision == HEAD_REVISION and backup == data_dir.root / "evidence.sqlite.before-0003"
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert revision(backup) == "0003" and dump(backup) == source_rows  # the database exactly as it was
    assert revision(data_dir.db_path) == HEAD_REVISION


def test_a_copy_never_replaces_an_older_one(tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]) -> None:
    data_dir = old_database(tmp_path, source_rows)
    (data_dir.root / "evidence.sqlite.before-0003").write_text("an older copy")
    _, backup = upgrade_database_with_backup(data_dir)
    assert backup == data_dir.root / "evidence.sqlite.before-0003.1"
    assert (data_dir.root / "evidence.sqlite.before-0003").read_text() == "an older copy"
    assert dump(backup) == source_rows


def test_a_new_database_and_an_empty_one_at_the_head_make_no_copy(tmp_path: Path) -> None:
    fresh = DataDir(tmp_path / "fresh")
    assert upgrade_database_with_backup(fresh) == (HEAD_REVISION, None)
    assert not [p for p in fresh.root.iterdir() if "before" in p.name]


def test_a_database_one_revision_back_is_refused_until_it_is_upgraded(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    with pytest.raises(StoreError):
        open_database(data_dir)


# ------------------------------------------------------------------------------- all or nothing ----
def test_a_database_with_a_dangling_reference_is_left_exactly_as_it_was(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    with raw_connection(
        data_dir.db_path
    ) as connection:  # an orphan that nothing in 0003 stopped (foreign keys were off)
        connection.execute(
            "INSERT INTO finding_evidence VALUES (?, 'no-such-observation', ?)",
            (source_rows["finding_drafts"][0][0], source_rows["runs"][0][0]),
        )
    before_master, before_rows = master(data_dir.db_path), dump(data_dir.db_path)
    with pytest.raises(Exception, match="refers to a row that is not there"):
        upgrade_database(data_dir)
    assert (
        revision(data_dir.db_path) == "0003"
        and master(data_dir.db_path) == before_master
        and dump(data_dir.db_path) == before_rows
    )
    with raw_connection(data_dir.db_path) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name LIKE '%__new'").fetchall() == []


def test_a_failure_after_the_first_table_is_rebuilt_undoes_it(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    before_master, before_rows = master(data_dir.db_path), dump(data_dir.db_path)
    module = load_migration()

    def failing() -> None:
        raise RuntimeError("the second rebuild failed")

    module._create_observations = failing  # the first table is already rebuilt when this runs
    with pytest.raises(RuntimeError, match="second rebuild failed"):
        run_upgrade_directly(data_dir.db_path, module)
    assert master(data_dir.db_path) == before_master and dump(data_dir.db_path) == before_rows
    assert (
        "kind IN ('web', 'ai')" in before_master["targets"]
        and "kind IN ('web', 'ai')" in master(data_dir.db_path)["targets"]
    )


def test_a_failed_rebuild_is_rolled_back_on_its_own_connection_not_just_when_the_connection_is_closed(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    """The explicit ROLLBACK and the connection's closing both undo a half-done rebuild; this checks the first, on the same connection."""
    data_dir = old_database(tmp_path, source_rows)
    module = load_migration()

    def failing() -> None:
        raise RuntimeError("the second rebuild failed")

    module._create_observations = failing
    engine = create_engine(f"sqlite:///{data_dir.db_path}")
    try:
        with engine.connect() as connection, Operations.context(MigrationContext.configure(connection)):
            with pytest.raises(RuntimeError, match="second rebuild failed"):
                module.upgrade()
            names = {r[0] for r in connection.exec_driver_sql("SELECT name FROM sqlite_master").all()}
            assert "targets__new" not in names and "observations__new" not in names and "targets" in names
            assert (
                "kind IN ('web', 'ai')"
                in connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name = 'targets'").scalar_one()
            )
            assert not connection.connection.in_transaction  # nothing is left open for the next statement to join
    finally:
        engine.dispose()


def test_a_copy_that_loses_rows_is_stopped_before_the_old_table_is_dropped(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    before_master, before_rows = master(data_dir.db_path), dump(data_dir.db_path)
    module = load_migration()
    original = module._create_targets

    def lossy() -> None:
        original()
        module.op.get_bind().exec_driver_sql(
            "CREATE TRIGGER lose BEFORE INSERT ON targets__new BEGIN SELECT RAISE(IGNORE); END"
        )

    module._create_targets = lossy
    with pytest.raises(RuntimeError, match="rows before the copy and 0 after"):
        run_upgrade_directly(data_dir.db_path, module)
    assert master(data_dir.db_path) == before_master and dump(data_dir.db_path) == before_rows


def test_the_rebuild_refuses_to_run_with_foreign_keys_enforced(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    data_dir = old_database(tmp_path, source_rows)
    before_master = master(data_dir.db_path)
    with pytest.raises(RuntimeError, match="foreign key enforcement off"):
        run_upgrade_directly(data_dir.db_path, load_migration(), foreign_keys=True)
    assert master(data_dir.db_path) == before_master and revision(data_dir.db_path) == "0003"


def test_downgrades_are_not_supported() -> None:
    with pytest.raises(RuntimeError, match="downgrades are not supported"):
        load_migration().downgrade()


def test_an_empty_database_at_revision_0003_upgrades_too(tmp_path: Path) -> None:
    data_dir = DataDir(tmp_path / "empty")
    data_dir.root.mkdir(mode=0o700)
    data_dir.db_path.touch(mode=0o600)
    command.upgrade(_alembic_config(data_dir.db_path), "0003")
    assert upgrade_database(data_dir) == HEAD_REVISION and load_pack(FIXTURES / "web_responses" / "api-orders.yaml")


def test_the_upgrade_command_says_where_the_copy_of_the_old_database_is(
    tmp_path: Path, source_rows: dict[str, list[tuple[Any, ...]]]
) -> None:
    from typer.testing import CliRunner  # noqa: PLC0415

    from scopedagent.cli import app  # noqa: PLC0415

    data_dir = old_database(tmp_path, source_rows)
    out = CliRunner().invoke(app, ["db", "upgrade", "--data-dir", str(data_dir.root)])
    assert out.exit_code == 0 and "database ready: revision 0005" in out.output
    assert (
        f"kept at {data_dir.root}/evidence.sqlite.before-0003" in out.output
        and "delete it when you are sure" in out.output
    )
    again = CliRunner().invoke(app, ["db", "upgrade", "--data-dir", str(data_dir.root)])
    assert again.exit_code == 0 and "kept at" not in again.output
