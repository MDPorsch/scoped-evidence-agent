"""Findings (M3): immutable assessments, append-only reviews, and the number of operations a run planned.

Written as explicit DDL, like 0001. A finding's details can never be changed or deleted once stored (a trigger refuses it), and a
review is a row that is only ever added, so the record of who decided what cannot be rewritten below the application (D-E62).

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

FINDING_STATUSES = "'DRAFT', 'NEEDS_VALIDATION', 'VALIDATED', 'FALSE_POSITIVE', 'REMEDIATED', 'VERIFIED'"


def upgrade() -> None:
    # NULL for a run made before this revision: a report then says the plan is unknown rather than guessing.
    op.execute(
        "ALTER TABLE runs ADD COLUMN planned_operations INTEGER "
        "CONSTRAINT ck_runs_planned_operations CHECK (planned_operations IS NULL OR planned_operations >= 0)"
    )
    op.create_table(
        "finding_details",
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "run_id"], ["finding_drafts.id", "finding_drafts.run_id"], name="fk_details_finding_run"
        ),
        sa.PrimaryKeyConstraint("finding_id"),
        sa.CheckConstraint("rule_version >= 1", name="ck_finding_details_rule_version"),
    )
    op.create_table(
        "finding_reviews",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("reviewer_id", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status_after", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "run_id"], ["finding_drafts.id", "finding_drafts.run_id"], name="fk_reviews_finding_run"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "decision IN ('confirmed', 'not_exploitable', 'inconclusive')", name="ck_finding_reviews_decision"
        ),
        sa.CheckConstraint(f"status_after IN ({FINDING_STATUSES})", name="ck_finding_reviews_status_after"),
        sa.CheckConstraint("length(reviewer_id) BETWEEN 1 AND 64", name="ck_finding_reviews_reviewer"),
        sa.CheckConstraint("length(reason) BETWEEN 1 AND 1000", name="ck_finding_reviews_reason"),
    )
    for table, message in (
        ("finding_details", "finding details are immutable"),
        ("finding_reviews", "finding_reviews is append-only"),
    ):
        for verb in ("update", "delete"):
            op.execute(
                f"CREATE TRIGGER {table}_no_{verb} BEFORE {verb.upper()} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
            )


def downgrade() -> None:
    raise RuntimeError("downgrades are not supported: restore the database from a backup (docs/migrations.md)")
