"""The database schema as SQLAlchemy models. Migration 0001 creates exactly this (a test compares the two)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

STAMP = "%Y-%m-%dT%H:%M:%S.%fZ"  # the stored form of every timestamp


class UtcDateTime(TypeDecorator[datetime]):
    """UTC text with a fixed format. A naive datetime is refused: a time without a zone is a guess."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("a naive datetime cannot be stored: use a timezone-aware one")
        return value.astimezone(UTC).strftime(STAMP)

    def process_result_value(self, value: str | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return datetime.strptime(value, STAMP).replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


RUN_STATES = (
    "CREATED",
    "SCOPE_VALIDATED",
    "QUEUED",
    "COLLECTING",
    "CORRELATING",
    "DRAFTED",
    "HUMAN_REVIEW",
    "EXPORTED",
    "FAILED",
    "CANCELED",
    "RETRIED",
)
OBSERVATION_TYPES = ("dns_metadata", "tls_metadata", "http_metadata", "ai_metadata", "ai_probe")
ADAPTERS = ("offline_dns", "offline_tls", "offline_http", "offline_ai")
ERROR_STATUSES = (
    "ok",
    "timeout",
    "dns_failure",
    "tls_failure",
    "http_error",
    "refused_by_policy",
    "budget_exhausted",
    "size_limit",
    "parse_error",
    "adapter_error",
)
FINDING_STATUSES = ("DRAFT", "NEEDS_VALIDATION", "VALIDATED", "FALSE_POSITIVE", "REMEDIATED", "VERIFIED")


class Engagement(Base):
    __tablename__ = "engagements"
    __table_args__ = (
        UniqueConstraint("label", "scope_sha256", name="uq_engagements_label_scope"),
        CheckConstraint("length(scope_sha256) = 64", name="ck_engagements_scope_sha256"),
        CheckConstraint(_in("status", ("active", "expired", "closed")), name="ck_engagements_status"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    label: Mapped[str] = mapped_column(String)
    owner_approval_ref: Mapped[str] = mapped_column(String)
    scope_sha256: Mapped[str] = mapped_column(String)
    scope_json: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
    status: Mapped[str] = mapped_column(String)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "kind", "host_canonical", "scheme", "port", name="uq_targets_endpoint"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_targets_port"),
        CheckConstraint(_in("scheme", ("http", "https")), name="ck_targets_scheme"),
        CheckConstraint("verified_scope IN (0, 1)", name="ck_targets_verified"),
        CheckConstraint(_in("kind", ("web", "ai")), name="ck_targets_kind"),
        CheckConstraint("(kind = 'ai') = (ai_target_id IS NOT NULL)", name="ck_targets_ai_target_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"))
    host_canonical: Mapped[str] = mapped_column(String)
    scheme: Mapped[str] = mapped_column(String)
    port: Mapped[int] = mapped_column(Integer)
    allowed_path_prefixes: Mapped[list[str]] = mapped_column(JSON)  # exact paths: the spec's column name, D-E05
    verified_scope: Mapped[bool] = mapped_column(Boolean)
    kind: Mapped[str] = mapped_column(String, server_default="web")  # web or ai (D-E34)
    ai_target_id: Mapped[str | None] = mapped_column(String, nullable=True)


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint(_in("state", RUN_STATES), name="ck_runs_state"),
        CheckConstraint(_in("mode", ("offline", "live")), name="ck_runs_mode"),
        CheckConstraint("total_budget >= 0", name="ck_runs_total_budget"),
        CheckConstraint("budget_spent >= 0", name="ck_runs_budget_spent"),
        CheckConstraint("budget_spent <= total_budget", name="ck_runs_budget_within_total"),
        CheckConstraint("attempt >= 1", name="ck_runs_attempt"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"))
    created_by: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
    state: Mapped[str] = mapped_column(String)
    total_budget: Mapped[int] = mapped_column(Integer)
    budget_spent: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String, nullable=True)
    retry_of_run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    attempt: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("run_id", "adapter", "target_id", "normalized_input_hash", name="uq_observations_idempotency"),
        UniqueConstraint("id", "run_id", name="uq_observations_id_run"),
        CheckConstraint(_in("observation_type", OBSERVATION_TYPES), name="ck_observations_type"),
        CheckConstraint(_in("adapter", ADAPTERS), name="ck_observations_adapter"),
        CheckConstraint(_in("error_status", ERROR_STATUSES), name="ck_observations_error_status"),
        CheckConstraint("length(source_hash) = 64", name="ck_observations_source_hash"),
        CheckConstraint("length(normalized_input_hash) = 64", name="ck_observations_input_hash"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    adapter: Mapped[str] = mapped_column(String)
    observation_type: Mapped[str] = mapped_column(String)
    normalized_json: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(UtcDateTime)
    source_hash: Mapped[str] = mapped_column(String)
    normalized_input_hash: Mapped[str] = mapped_column(String)
    error_status: Mapped[str] = mapped_column(String)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("run_id", "sha256", name="uq_artifacts_run_sha256"),
        CheckConstraint("length(sha256) = 64", name="ck_artifacts_sha256"),
        CheckConstraint("size BETWEEN 0 AND 2000000", name="ck_artifacts_size"),
        CheckConstraint(_in("redaction_status", ("redacted", "metadata_only")), name="ck_artifacts_redaction"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    sha256: Mapped[str] = mapped_column(String)
    mime: Mapped[str] = mapped_column(String)
    redaction_status: Mapped[str] = mapped_column(String)
    size: Mapped[int] = mapped_column(Integer)
    storage_path: Mapped[str] = mapped_column(String)
    retention_until: Mapped[datetime] = mapped_column(UtcDateTime)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class FindingDraft(Base):
    __tablename__ = "finding_drafts"
    __table_args__ = (
        UniqueConstraint("id", "run_id", name="uq_finding_drafts_id_run"),
        CheckConstraint("length(title) BETWEEN 5 AND 160", name="ck_finding_drafts_title"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_finding_drafts_confidence"),
        CheckConstraint(_in("status", FINDING_STATUSES), name="ck_finding_drafts_status"),
        CheckConstraint("revision >= 1", name="ck_finding_drafts_revision"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"))
    title: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String)
    reviewer_id: Mapped[str | None] = mapped_column(String, nullable=True)
    revision: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)

    evidence_links: Mapped[list[FindingEvidence]] = relationship(
        "FindingEvidence",
        primaryjoin="FindingDraft.id == foreign(FindingEvidence.finding_id)",
        viewonly=True,
        lazy="selectin",
    )

    @property
    def evidence_ids(self) -> list[str]:
        """The spec's `evidence_ids`: the observations this draft cites."""
        return sorted(link.observation_id for link in self.evidence_links)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (
        ForeignKeyConstraint(
            ["finding_id", "run_id"], ["finding_drafts.id", "finding_drafts.run_id"], name="fk_evidence_finding_run"
        ),
        ForeignKeyConstraint(
            ["observation_id", "run_id"], ["observations.id", "observations.run_id"], name="fk_evidence_observation_run"
        ),
    )

    finding_id: Mapped[str] = mapped_column(String, primary_key=True)
    observation_id: Mapped[str] = mapped_column(String, primary_key=True)
    run_id: Mapped[str] = mapped_column(String)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(_in("actor_type", ("human", "worker", "model")), name="ck_audit_events_actor_type"),
        CheckConstraint(_in("decision", ("allowed", "denied", "recorded")), name="ck_audit_events_decision"),
        CheckConstraint("length(prev_hash) = 64", name="ck_audit_events_prev_hash"),
        CheckConstraint("length(entry_hash) = 64", name="ck_audit_events_entry_hash"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    actor_type: Mapped[str] = mapped_column(String)
    actor_id: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    decision: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(UtcDateTime)
    prev_hash: Mapped[str] = mapped_column(String)
    entry_hash: Mapped[str] = mapped_column(String)


__all__ = [
    "Artifact",
    "AuditEvent",
    "Base",
    "Engagement",
    "FindingDraft",
    "FindingEvidence",
    "Observation",
    "Run",
    "Target",
    "UtcDateTime",
]
_ = Any  # keep the typing import explicit for readers of the module
