"""Initial schema (M1): engagements, targets, runs, observations, artifacts, findings, audit.

Written as explicit DDL, not generated from the models, so that a later change to a model can never rewrite what
revision 0001 means. tests/integration/test_database.py compares the result with the models.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

RUN_STATES = "'CREATED', 'SCOPE_VALIDATED', 'QUEUED', 'COLLECTING', 'CORRELATING', 'DRAFTED', 'HUMAN_REVIEW', 'EXPORTED', 'FAILED', 'CANCELED', 'RETRIED'"
ERROR_STATUSES = "'ok', 'timeout', 'dns_failure', 'tls_failure', 'http_error', 'refused_by_policy', 'budget_exhausted', 'size_limit', 'parse_error', 'adapter_error'"
FINDING_STATUSES = "'DRAFT', 'NEEDS_VALIDATION', 'VALIDATED', 'FALSE_POSITIVE', 'REMEDIATED', 'VERIFIED'"


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("owner_approval_ref", sa.String(), nullable=False),
        sa.Column("scope_sha256", sa.String(), nullable=False),
        sa.Column("scope_json", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("label", "scope_sha256", name="uq_engagements_label_scope"),
        sa.CheckConstraint("length(scope_sha256) = 64", name="ck_engagements_scope_sha256"),
        sa.CheckConstraint("status IN ('active', 'expired', 'closed')", name="ck_engagements_status"),
    )
    op.create_table(
        "targets",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("engagement_id", sa.String(), nullable=False),
        sa.Column("host_canonical", sa.String(), nullable=False),
        sa.Column("scheme", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("allowed_path_prefixes", sa.JSON(), nullable=False),
        sa.Column("verified_scope", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "host_canonical", "scheme", "port", name="uq_targets_endpoint"),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_targets_port"),
        sa.CheckConstraint("scheme IN ('http', 'https')", name="ck_targets_scheme"),
        sa.CheckConstraint("verified_scope IN (0, 1)", name="ck_targets_verified"),
    )
    op.create_table(
        "runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("engagement_id", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("total_budget", sa.Integer(), nullable=False),
        sa.Column("budget_spent", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.String(), nullable=True),
        sa.Column("ended_at", sa.String(), nullable=True),
        sa.Column("error_code", sa.String(), nullable=True),
        sa.Column("retry_of_run_id", sa.String(), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"]),
        sa.ForeignKeyConstraint(["retry_of_run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(f"state IN ({RUN_STATES})", name="ck_runs_state"),
        sa.CheckConstraint("mode IN ('offline', 'live')", name="ck_runs_mode"),
        sa.CheckConstraint("total_budget >= 0", name="ck_runs_total_budget"),
        sa.CheckConstraint("budget_spent >= 0", name="ck_runs_budget_spent"),
        sa.CheckConstraint("budget_spent <= total_budget", name="ck_runs_budget_within_total"),
        sa.CheckConstraint("attempt >= 1", name="ck_runs_attempt"),
    )
    op.create_table(
        "observations",
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
        sa.CheckConstraint(
            "observation_type IN ('dns_metadata', 'tls_metadata', 'http_metadata')", name="ck_observations_type"
        ),
        sa.CheckConstraint("adapter IN ('offline_dns', 'offline_tls', 'offline_http')", name="ck_observations_adapter"),
        sa.CheckConstraint(f"error_status IN ({ERROR_STATUSES})", name="ck_observations_error_status"),
        sa.CheckConstraint("length(source_hash) = 64", name="ck_observations_source_hash"),
        sa.CheckConstraint("length(normalized_input_hash) = 64", name="ck_observations_input_hash"),
    )
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("mime", sa.String(), nullable=False),
        sa.Column("redaction_status", sa.String(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("storage_path", sa.String(), nullable=False),
        sa.Column("retention_until", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sha256", name="uq_artifacts_run_sha256"),
        sa.CheckConstraint("length(sha256) = 64", name="ck_artifacts_sha256"),
        sa.CheckConstraint("size BETWEEN 0 AND 2000000", name="ck_artifacts_size"),
        sa.CheckConstraint("redaction_status IN ('redacted', 'metadata_only')", name="ck_artifacts_redaction"),
    )
    op.create_table(
        "finding_drafts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("reviewer_id", sa.String(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "run_id", name="uq_finding_drafts_id_run"),
        sa.CheckConstraint("length(title) BETWEEN 5 AND 160", name="ck_finding_drafts_title"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_finding_drafts_confidence"),
        sa.CheckConstraint(f"status IN ({FINDING_STATUSES})", name="ck_finding_drafts_status"),
        sa.CheckConstraint("revision >= 1", name="ck_finding_drafts_revision"),
    )
    op.create_table(
        "finding_evidence",
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("observation_id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id", "run_id"], ["finding_drafts.id", "finding_drafts.run_id"], name="fk_evidence_finding_run"
        ),
        sa.ForeignKeyConstraint(
            ["observation_id", "run_id"], ["observations.id", "observations.run_id"], name="fk_evidence_observation_run"
        ),
        sa.PrimaryKeyConstraint("finding_id", "observation_id"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("actor_type", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ts", sa.String(), nullable=False),
        sa.Column("prev_hash", sa.String(), nullable=False),
        sa.Column("entry_hash", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("actor_type IN ('human', 'worker', 'model')", name="ck_audit_events_actor_type"),
        sa.CheckConstraint("decision IN ('allowed', 'denied', 'recorded')", name="ck_audit_events_decision"),
        sa.CheckConstraint("length(prev_hash) = 64", name="ck_audit_events_prev_hash"),
        sa.CheckConstraint("length(entry_hash) = 64", name="ck_audit_events_entry_hash"),
    )
    # The audit trail is append-only (D-E11): the database itself refuses to edit or remove an event.
    op.execute(
        "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
    )
    # An observation must belong to a target of the run's own engagement (the scope boundary, enforced below the application).
    op.execute(
        "CREATE TRIGGER observations_target_in_engagement BEFORE INSERT ON observations "
        "WHEN (SELECT engagement_id FROM runs WHERE id = NEW.run_id) IS NOT (SELECT engagement_id FROM targets WHERE id = NEW.target_id) "
        "BEGIN SELECT RAISE(ABORT, 'the target belongs to a different engagement than the run'); END"
    )


def downgrade() -> None:
    raise RuntimeError("downgrades are not supported: restore the database from a backup (docs/migrations.md)")
