"""Approvals for live runs (D-E41) and what a live run was done under (D-E46): a record bound to a scope hash, the row that ends it,
and one append-only row per live run.

Written as explicit DDL, like the others. Nothing here changes an existing table. An approval is never edited or deleted (a trigger
refuses both) and a revocation is one row per approval that is never edited or deleted either, so the record of who allowed what,
and until when, cannot be rewritten below the application.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("scope_sha256", sa.String(), nullable=False),
        sa.Column("engagement", sa.String(), nullable=False),
        sa.Column("granted_by", sa.String(), nullable=False),
        sa.Column("granted_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("length(scope_sha256) = 64", name="ck_approvals_scope_sha256"),
        sa.CheckConstraint("length(granted_by) BETWEEN 1 AND 128", name="ck_approvals_granted_by"),
        sa.CheckConstraint("expires_at > granted_at", name="ck_approvals_window"),
    )
    op.create_table(
        "approval_revocations",
        sa.Column("approval_id", sa.String(), nullable=False),
        sa.Column("revoked_by", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], name="fk_revocations_approval"),
        sa.PrimaryKeyConstraint("approval_id"),
        sa.CheckConstraint("length(revoked_by) BETWEEN 1 AND 128", name="ck_revocations_revoked_by"),
        sa.CheckConstraint("length(reason) BETWEEN 1 AND 500", name="ck_revocations_reason"),
    )
    op.create_table(
        "live_runs",
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("approval_id", sa.String(), nullable=False),
        sa.Column("engagement", sa.String(), nullable=False),
        sa.Column("image", sa.String(), nullable=False),
        sa.Column("proof_json", sa.Text(), nullable=False),
        sa.Column("resolutions_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], name="fk_live_runs_run"),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], name="fk_live_runs_approval"),
        sa.PrimaryKeyConstraint("run_id"),
        sa.CheckConstraint("length(image) BETWEEN 1 AND 300", name="ck_live_runs_image"),
    )
    for table in ("approvals", "approval_revocations", "live_runs"):
        for verb in ("update", "delete"):
            op.execute(
                f"CREATE TRIGGER {table}_no_{verb} BEFORE {verb.upper()} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
            )


def downgrade() -> None:
    raise RuntimeError("downgrades are not supported: restore the database from a backup (docs/migrations.md)")
