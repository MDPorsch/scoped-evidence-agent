"""The optional model adapter (M4): its calls and the wordings it produced, both append-only.

Written as explicit DDL, like 0001 and 0002. Nothing here changes an existing table, so a database made by M3 upgrades without touching
its data. A wording sits beside a rule's sentence and never replaces it; a call row records what was asked and what happened, never the
sentences or the key (D-E66 to D-E69).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_calls",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("prompt_version", sa.String(), nullable=False),
        sa.Column("input_sha256", sa.String(), nullable=False),
        sa.Column("items_sent", sa.Integer(), nullable=False),
        sa.Column("items_accepted", sa.Integer(), nullable=False),
        sa.Column("items_rejected", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "run_id"], ["finding_drafts.id", "finding_drafts.run_id"], name="fk_model_calls_finding_run"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('ok', 'unavailable', 'refused', 'invalid', 'budget_exhausted')", name="ck_model_calls_status"
        ),
        sa.CheckConstraint(
            "items_sent >= 0 AND items_accepted >= 0 AND items_rejected >= 0 AND items_accepted + items_rejected <= items_sent",
            name="ck_model_calls_items",
        ),
        sa.CheckConstraint("input_tokens >= 0 AND output_tokens >= 0", name="ck_model_calls_tokens"),
        sa.CheckConstraint("length(input_sha256) = 64", name="ck_model_calls_hash"),
    )
    op.create_table(
        "finding_wordings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("field", sa.String(), nullable=False),
        sa.Column("item_index", sa.Integer(), nullable=False),
        sa.Column("original_sha256", sa.String(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("prompt_version", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "run_id"], ["finding_drafts.id", "finding_drafts.run_id"], name="fk_wordings_finding_run"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "field", "item_index", name="uq_finding_wordings_item"),
        sa.CheckConstraint(
            "field IN ('condition', 'precondition', 'unknown', 'attacker_position', 'basis', 'remediation', 'severity_basis')",
            name="ck_finding_wordings_field",
        ),
        sa.CheckConstraint("item_index >= 0", name="ck_finding_wordings_index"),
        sa.CheckConstraint("length(original_sha256) = 64", name="ck_finding_wordings_hash"),
        sa.CheckConstraint("length(text) BETWEEN 1 AND 500", name="ck_finding_wordings_text"),
    )
    for table in ("model_calls", "finding_wordings"):
        for verb in ("update", "delete"):
            op.execute(
                f"CREATE TRIGGER {table}_no_{verb} BEFORE {verb.upper()} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
            )


def downgrade() -> None:
    raise RuntimeError("downgrades are not supported: restore the database from a backup (docs/migrations.md)")
