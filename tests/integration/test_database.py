"""X-02, X-03, X-04, X-06 and the schema: what the database itself refuses, independent of the application."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from scopedagent.domain.models import Base
from scopedagent.errors import ErrorCode, StoreError
from scopedagent.storage.database import HEAD_REVISION, DataDir, open_database, upgrade_database
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError, OperationalError

from tests.support import seed, sql_insert, stamp

pytestmark = pytest.mark.milestone("M1")

EXPECTED_TABLES = {
    "engagements",
    "targets",
    "runs",
    "observations",
    "artifacts",
    "finding_drafts",
    "finding_evidence",
    "audit_events",
    "alembic_version",
}


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def data_dir(tmp_path: Path) -> DataDir:
    return DataDir(tmp_path / "data")


@pytest.fixture
def db(data_dir: DataDir) -> Any:
    upgrade_database(data_dir)
    database = open_database(data_dir)
    yield database
    database.close()


# -------------------------------------------------------------------------- creation and perms ----
def test_upgrade_creates_the_directory_and_database_privately_and_returns_the_head_revision(data_dir: DataDir) -> None:
    assert upgrade_database(data_dir) == HEAD_REVISION
    assert mode(data_dir.root) == 0o700 and mode(data_dir.db_path) == 0o600
    assert data_dir.db_path.name == "evidence.sqlite" and data_dir.artifacts_dir == data_dir.root / "artifacts"


def test_upgrade_is_idempotent(data_dir: DataDir) -> None:
    upgrade_database(data_dir)
    assert upgrade_database(data_dir) == HEAD_REVISION


def test_an_existing_data_directory_that_is_too_open_is_refused_not_silently_fixed(data_dir: DataDir) -> None:
    data_dir.root.mkdir(mode=0o755)
    os.chmod(data_dir.root, 0o755)
    with pytest.raises(StoreError) as caught:
        upgrade_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_003
    assert mode(data_dir.root) == 0o755  # we did not chmod it behind the owner's back


@pytest.mark.parametrize("loose", [0o644, 0o660, 0o604, 0o666])
def test_a_database_file_that_others_can_read_or_write_is_refused(data_dir: DataDir, loose: int) -> None:
    upgrade_database(data_dir)
    os.chmod(data_dir.db_path, loose)
    with pytest.raises(StoreError) as caught:
        open_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_003


def test_open_refuses_a_loose_data_directory(data_dir: DataDir) -> None:
    upgrade_database(data_dir)
    os.chmod(data_dir.root, 0o750)
    with pytest.raises(StoreError) as caught:
        open_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_003


def test_a_symlinked_database_is_refused(data_dir: DataDir, tmp_path: Path) -> None:
    upgrade_database(data_dir)
    real = tmp_path / "elsewhere.sqlite"
    data_dir.db_path.rename(real)
    data_dir.db_path.symlink_to(real)
    with pytest.raises(StoreError) as caught:
        open_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_003


# --------------------------------------------------------------------------- never auto-migrate ----
def test_open_never_creates_a_missing_database_or_directory(data_dir: DataDir) -> None:
    with pytest.raises(StoreError) as caught:
        open_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_001
    assert not data_dir.root.exists()


def test_open_refuses_an_empty_sqlite_file_and_does_not_migrate_it(data_dir: DataDir) -> None:
    data_dir.root.mkdir(mode=0o700)
    sqlite3.connect(data_dir.db_path).close()
    os.chmod(data_dir.db_path, 0o600)
    with pytest.raises(StoreError) as caught:
        open_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_002
    with sqlite3.connect(data_dir.db_path) as raw:
        assert raw.execute("SELECT count(*) FROM sqlite_master").fetchone() == (0,)


@pytest.mark.parametrize("revision", ["0000", "ffff", "9999", "", "0001; DROP TABLE runs"])
def test_open_refuses_a_schema_revision_it_does_not_know(data_dir: DataDir, revision: str) -> None:
    upgrade_database(data_dir)
    with sqlite3.connect(data_dir.db_path) as raw:
        raw.execute("UPDATE alembic_version SET version_num = ?", (revision,))
    with pytest.raises(StoreError) as caught:
        open_database(data_dir)
    assert caught.value.code is ErrorCode.STORE_002


# ------------------------------------------------------------------------------------ the schema ----
def test_the_migrated_schema_has_exactly_the_expected_tables(db: Any) -> None:
    with db.begin() as session:
        names = set(
            session.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
            ).scalars()
        )
    assert names == EXPECTED_TABLES


def test_the_migrated_schema_matches_the_models_exactly(db: Any) -> None:
    with db.engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    assert diff == []


def test_foreign_keys_are_enforced_on_every_connection(db: Any) -> None:
    with db.begin() as session:
        assert session.execute(text("PRAGMA foreign_keys")).scalar() == 1
        with pytest.raises(DatabaseError):
            sql_insert(
                session,
                "targets",
                id="t9",
                engagement_id="missing",
                host_canonical="h.example.invalid",
                scheme="https",
                port=443,
                allowed_path_prefixes="[]",
                verified_scope=1,
            )


def test_a_write_transaction_takes_the_write_lock_at_once(data_dir: DataDir) -> None:
    upgrade_database(data_dir)
    first = open_database(data_dir)
    second = open_database(data_dir, busy_timeout_ms=100)
    try:
        with first.begin() as holder:
            holder.execute(text("SELECT 1"))  # no write yet: a deferred transaction would not hold the lock
            with pytest.raises(OperationalError), second.begin() as session:
                session.execute(text("SELECT 1"))
    finally:
        first.close()
        second.close()


def test_a_failed_block_rolls_everything_back(db: Any) -> None:
    with pytest.raises(RuntimeError), db.begin() as session:
        seed(session)
        raise RuntimeError("boom")
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM engagements")).scalar() == 0


def test_timestamps_are_stored_as_utc_text_and_read_back_aware(db: Any) -> None:
    with db.begin() as session:
        seed(session)
    with db.begin() as session:
        assert session.execute(text("SELECT created_at FROM runs")).scalar() == "2026-11-20T12:00:00.000000Z"
        from scopedagent.domain.models import Run  # noqa: PLC0415

        run = session.get(Run, "r1")
        assert run is not None and run.created_at.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


def test_a_naive_datetime_cannot_be_stored(db: Any) -> None:
    from datetime import datetime  # noqa: PLC0415

    from scopedagent.domain.models import Engagement  # noqa: PLC0415

    with pytest.raises(Exception, match="(?i)naive|timezone|aware"), db.begin() as session:
        session.add(
            Engagement(
                id="e2",
                label="x",
                owner_approval_ref="local-lab-consent",
                scope_sha256="a" * 64,
                scope_json="{}",
                expires_at=datetime(2026, 12, 31),
                created_at=datetime(2026, 11, 20),
                status="active",
            )
        )
        session.flush()


# ---------------------------------------------------------------------------- CHECK constraints ----
@pytest.mark.parametrize(
    ("overrides"),
    [
        {"state": "WEIRD"},
        {"mode": "online"},
        {"total_budget": -1},
        {"budget_spent": -1},
        {"total_budget": 5, "budget_spent": 6},  # the database backstops a budget overshoot
        {"attempt": 0},
    ],
)
def test_run_constraints(db: Any, overrides: dict[str, Any]) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session, **overrides)


def test_a_run_may_retry_only_an_existing_run(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session, retry_of_run_id="nope")


@pytest.mark.parametrize("bad", [{"port": 0}, {"port": 65536}, {"scheme": "ftp"}, {"verified_scope": 2}])
def test_target_constraints(db: Any, bad: dict[str, Any]) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        row = {
            "id": "t2",
            "engagement_id": "e1",
            "host_canonical": "x.example.invalid",
            "scheme": "https",
            "port": 8443,
            "allowed_path_prefixes": "[]",
            "verified_scope": 1,
        } | bad
        sql_insert(session, "targets", **row)


def test_a_target_is_unique_per_engagement_host_scheme_and_port(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(
            session,
            "targets",
            id="t2",
            engagement_id="e1",
            host_canonical="lab.example.invalid",
            scheme="https",
            port=443,
            allowed_path_prefixes="[]",
            verified_scope=1,
        )


def test_an_engagement_is_unique_per_label_and_scope_hash(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(
            session,
            "engagements",
            id="e2",
            label="lab",
            owner_approval_ref="local-lab-consent",
            scope_sha256="a" * 64,
            scope_json="{}",
            expires_at=stamp(),
            created_at=stamp(),
            status="active",
        )


def test_an_engagement_scope_hash_must_be_64_characters(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        sql_insert(
            session,
            "engagements",
            id="e2",
            label="x",
            owner_approval_ref="local-lab-consent",
            scope_sha256="short",
            scope_json="{}",
            expires_at=stamp(),
            created_at=stamp(),
            status="active",
        )


def obs_row(**over: Any) -> dict[str, Any]:
    row = {
        "id": "o1",
        "run_id": "r1",
        "target_id": "t1",
        "adapter": "offline_dns",
        "observation_type": "dns_metadata",
        "normalized_json": "{}",
        "collected_at": stamp(),
        "source_hash": "b" * 64,
        "normalized_input_hash": "c" * 64,
        "error_status": "ok",
    }
    row.update(over)
    return row


@pytest.mark.parametrize(
    "bad",
    [
        {"observation_type": "port_scan"},
        {"error_status": "clean"},
        {"source_hash": "short"},
        {"normalized_input_hash": "short"},
        {"adapter": "live_anything"},
    ],
)
def test_observation_constraints(db: Any, bad: dict[str, Any]) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "observations", **obs_row(**bad))


def test_observations_are_idempotent_per_run_adapter_target_and_input(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "observations", **obs_row())
        sql_insert(session, "observations", **obs_row(id="o2"))
    with db.begin() as session:
        seed(session)
        sql_insert(session, "observations", **obs_row())
        sql_insert(
            session, "observations", **obs_row(id="o2", normalized_input_hash="d" * 64)
        )  # a different input is fine


def test_an_observation_for_a_target_of_another_engagement_is_refused_by_the_database(db: Any) -> None:
    with pytest.raises(DatabaseError, match="(?i)engagement"), db.begin() as session:
        seed(session)
        sql_insert(
            session,
            "engagements",
            id="e2",
            label="other",
            owner_approval_ref="local-lab-consent",
            scope_sha256="b" * 64,
            scope_json="{}",
            expires_at=stamp(),
            created_at=stamp(),
            status="active",
        )
        sql_insert(
            session,
            "targets",
            id="t2",
            engagement_id="e2",
            host_canonical="other.example.invalid",
            scheme="https",
            port=443,
            allowed_path_prefixes="[]",
            verified_scope=1,
        )
        sql_insert(session, "observations", **obs_row(target_id="t2"))


# ---------------------------------------------------------------------------- artifacts (X-03) ----
def artifact_row(**over: Any) -> dict[str, Any]:
    row = {
        "id": "a1",
        "run_id": "r1",
        "sha256": "e" * 64,
        "mime": "text/plain",
        "redaction_status": "redacted",
        "size": 10,
        "storage_path": "ee/" + "e" * 64,
        "retention_until": stamp(),
        "created_at": stamp(),
    }
    row.update(over)
    return row


@pytest.mark.parametrize("status", ["redacted", "metadata_only"])
def test_only_redacted_or_metadata_only_artifacts_can_be_inserted(db: Any, status: str) -> None:
    with db.begin() as session:
        seed(session)
        sql_insert(session, "artifacts", **artifact_row(redaction_status=status))


@pytest.mark.parametrize("status", ["raw", "pending", "unredacted", "", "REDACTED"])
def test_an_unredacted_artifact_cannot_be_inserted(db: Any, status: str) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "artifacts", **artifact_row(redaction_status=status))


@pytest.mark.parametrize("bad", [{"sha256": "short"}, {"size": -1}, {"size": 2_000_001}])
def test_artifact_constraints(db: Any, bad: dict[str, Any]) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "artifacts", **artifact_row(**bad))


def test_an_artifact_is_unique_per_run_and_hash_but_may_repeat_across_runs(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "artifacts", **artifact_row())
        sql_insert(session, "artifacts", **artifact_row(id="a2"))
    with db.begin() as session:
        seed(session)
        sql_insert(
            session,
            "runs",
            id="r2",
            engagement_id="e1",
            created_by="alice",
            mode="offline",
            state="CREATED",
            total_budget=1,
            budget_spent=0,
            attempt=1,
            created_at=stamp(),
        )
        sql_insert(session, "artifacts", **artifact_row())
        sql_insert(session, "artifacts", **artifact_row(id="a2", run_id="r2"))


# ------------------------------------------------------------------- findings and their evidence ----
def test_finding_constraints(db: Any) -> None:
    base = {
        "id": "f1",
        "run_id": "r1",
        "title": "A finding",
        "category": "headers",
        "confidence": 0.5,
        "status": "DRAFT",
        "revision": 1,
        "created_at": stamp(),
    }
    for bad in (
        {"confidence": 1.5},
        {"confidence": -0.1},
        {"status": "CONFIRMED"},
        {"title": "abc"},
        {"title": "x" * 161},
        {"revision": 0},
    ):
        with pytest.raises(DatabaseError), db.begin() as session:
            seed(session)
            sql_insert(session, "finding_drafts", **(base | bad))


def test_a_finding_cannot_cite_an_observation_of_another_run(db: Any) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(
            session,
            "runs",
            id="r2",
            engagement_id="e1",
            created_by="alice",
            mode="offline",
            state="CREATED",
            total_budget=1,
            budget_spent=0,
            attempt=1,
            created_at=stamp(),
        )
        sql_insert(session, "observations", **obs_row())  # belongs to r1
        sql_insert(
            session,
            "finding_drafts",
            id="f2",
            run_id="r2",
            title="A finding",
            category="headers",
            confidence=0.5,
            status="DRAFT",
            revision=1,
            created_at=stamp(),
        )
        sql_insert(session, "finding_evidence", finding_id="f2", observation_id="o1", run_id="r2")


def test_a_finding_can_cite_an_observation_of_its_own_run(db: Any) -> None:
    with db.begin() as session:
        seed(session)
        sql_insert(session, "observations", **obs_row())
        sql_insert(
            session,
            "finding_drafts",
            id="f1",
            run_id="r1",
            title="A finding",
            category="headers",
            confidence=0.5,
            status="DRAFT",
            revision=1,
            created_at=stamp(),
        )
        sql_insert(session, "finding_evidence", finding_id="f1", observation_id="o1", run_id="r1")


# --------------------------------------------------------------------------- the audit trail (X-02) ----
def audit_row(**over: Any) -> dict[str, Any]:
    row = {
        "run_id": "r1",
        "actor_type": "worker",
        "actor_id": "w1",
        "action": "run.created",
        "decision": "allowed",
        "reason": "",
        "ts": stamp(),
        "prev_hash": "0" * 64,
        "entry_hash": "f" * 64,
    }
    row.update(over)
    return row


def test_audit_events_cannot_be_updated_or_deleted(db: Any) -> None:
    with db.begin() as session:
        seed(session)
        sql_insert(session, "audit_events", **audit_row())
    with pytest.raises(DatabaseError, match="(?i)append-only"), db.begin() as session:
        session.execute(text("UPDATE audit_events SET reason = 'edited'"))
    with pytest.raises(DatabaseError, match="(?i)append-only"), db.begin() as session:
        session.execute(text("DELETE FROM audit_events"))
    with db.begin() as session:
        assert session.execute(text("SELECT reason FROM audit_events")).scalar() == ""


@pytest.mark.parametrize(
    "bad", [{"actor_type": "robot"}, {"decision": "maybe"}, {"prev_hash": "short"}, {"entry_hash": "short"}]
)
def test_audit_constraints(db: Any, bad: dict[str, Any]) -> None:
    with pytest.raises(DatabaseError), db.begin() as session:
        seed(session)
        sql_insert(session, "audit_events", **audit_row(**bad))


def test_audit_events_may_have_no_run_for_cross_run_receipts(db: Any) -> None:
    with db.begin() as session:
        sql_insert(session, "audit_events", **audit_row(run_id=None, action="artifacts.purge"))
