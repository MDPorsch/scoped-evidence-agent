"""API targets (D-E48): two new kinds of record that SQLite can only admit by rebuilding two tables.

A CHECK constraint cannot be altered in SQLite, so `targets` (its `kind` list) and `observations` (its `observation_type` and
`adapter` lists) are rebuilt with the wider lists: the new table is created, every row is copied unchanged, the old table is
dropped and the new one takes its name. Nothing else changes, and nothing is read, edited or dropped except as part of that copy.

The whole rebuild is one transaction, so a failure anywhere leaves the database exactly as it was (revision 0003). It also
checks that no row was lost or orphaned before it commits. `db upgrade` copies the database file aside before it runs this
revision (docs/migrations.md). The append-only trigger on the audit trail is not touched; the trigger that keeps an observation
inside its run's engagement is dropped for the rebuild and recreated.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

ERROR_STATUSES = "'ok', 'timeout', 'dns_failure', 'tls_failure', 'http_error', 'refused_by_policy', 'budget_exhausted', 'size_limit', 'parse_error', 'adapter_error'"
TYPES = (
    "'dns_metadata', 'tls_metadata', 'http_metadata', 'ai_metadata', 'ai_probe', 'api_spec', 'api_read', 'api_options'"
)
ADAPTERS = "'offline_dns', 'offline_tls', 'offline_http', 'offline_ai', 'offline_api'"
TRIGGER = (
    "CREATE TRIGGER observations_target_in_engagement BEFORE INSERT ON observations "
    "WHEN (SELECT engagement_id FROM runs WHERE id = NEW.run_id) IS NOT (SELECT engagement_id FROM targets WHERE id = NEW.target_id) "
    "BEGIN SELECT RAISE(ABORT, 'the target belongs to a different engagement than the run'); END"
)


def _create_targets() -> None:
    op.create_table(
        "targets__new",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("engagement_id", sa.String(), nullable=False),
        sa.Column("host_canonical", sa.String(), nullable=False),
        sa.Column("scheme", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("allowed_path_prefixes", sa.JSON(), nullable=False),
        sa.Column("verified_scope", sa.Boolean(), nullable=False),
        sa.Column("kind", sa.String(), server_default="web", nullable=False),
        sa.Column("ai_target_id", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "kind", "host_canonical", "scheme", "port", name="uq_targets_endpoint"),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_targets_port"),
        sa.CheckConstraint("scheme IN ('http', 'https')", name="ck_targets_scheme"),
        sa.CheckConstraint("verified_scope IN (0, 1)", name="ck_targets_verified"),
        sa.CheckConstraint("kind IN ('web', 'ai', 'api')", name="ck_targets_kind"),
        sa.CheckConstraint("(kind = 'ai') = (ai_target_id IS NOT NULL)", name="ck_targets_ai_target_id"),
    )


def _create_observations() -> None:
    op.create_table(
        "observations__new",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("adapter", sa.String(), nullable=False),
        sa.Column("observation_type", sa.String(), nullable=False),
        sa.Column("normalized_json", sa.Text(), nullable=False),
        sa.Column("collected_at", sa.String(), nullable=False),
        sa.Column("source_hash", sa.String(), nullable=False),
        sa.Column("normalized_input_hash", sa.String(), nullable=False),
        sa.Column("error_status", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id", "adapter", "target_id", "normalized_input_hash", name="uq_observations_idempotency"
        ),
        sa.UniqueConstraint("id", "run_id", name="uq_observations_id_run"),
        sa.CheckConstraint(f"observation_type IN ({TYPES})", name="ck_observations_type"),
        sa.CheckConstraint(f"adapter IN ({ADAPTERS})", name="ck_observations_adapter"),
        sa.CheckConstraint(f"error_status IN ({ERROR_STATUSES})", name="ck_observations_error_status"),
        sa.CheckConstraint("length(source_hash) = 64", name="ck_observations_source_hash"),
        sa.CheckConstraint("length(normalized_input_hash) = 64", name="ck_observations_input_hash"),
    )


def _rebuild(table: str, create: object) -> int:
    """Create `<table>__new`, copy every row, drop the old table, rename. Returns the number of rows copied."""
    connection = op.get_bind()
    before = connection.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar_one()
    create()  # type: ignore[operator]
    connection.exec_driver_sql(f"INSERT INTO {table}__new SELECT * FROM {table}")
    after = connection.exec_driver_sql(f"SELECT count(*) FROM {table}__new").scalar_one()
    if before != after:
        raise RuntimeError(f"{table}: {before} rows before the copy and {after} after: the migration is stopped")
    connection.exec_driver_sql(f"DROP TABLE {table}")
    connection.exec_driver_sql(f"ALTER TABLE {table}__new RENAME TO {table}")
    return int(after)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 0:
        raise RuntimeError("the rebuild needs foreign key enforcement off; it is run by `scoped-agent db upgrade` only")
    connection.exec_driver_sql("BEGIN IMMEDIATE")  # SQLite DDL is transactional: all of it, or none of it
    try:
        connection.exec_driver_sql("DROP TRIGGER observations_target_in_engagement")
        _rebuild("targets", _create_targets)
        _rebuild("observations", _create_observations)
        connection.exec_driver_sql(TRIGGER)
        if connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError("a row refers to a row that is not there after the rebuild: the migration is stopped")
        connection.exec_driver_sql("COMMIT")
    except BaseException:
        connection.exec_driver_sql("ROLLBACK")
        raise


def downgrade() -> None:
    raise RuntimeError("downgrades are not supported: restore the database from a backup (docs/migrations.md)")
