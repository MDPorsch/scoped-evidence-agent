"""Redacted evidence on disk: content-addressed, private, written atomically, checked against its hash on every read
(D-E12, D-E13).

Only redacted or metadata-only content is accepted (the database also refuses anything else). A file is named by the
SHA-256
of its bytes, so a changed file is detected, never trusted. A purge deletes only files whose name is a recorded
SHA-256 under
the artifact root, and refuses links and anything that resolves elsewhere (AE-14).
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from scopedagent.domain.models import Artifact
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, StateError, StoreError
from scopedagent.storage.audit import append_event
from scopedagent.storage.database import DataDir, check_private

MAX_ARTIFACT_BYTES = 2_000_000
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 365
DEFAULT_RETENTION_DAYS = 30
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MIME = re.compile(r"[a-z0-9][a-z0-9.+-]{0,62}/[a-z0-9][a-z0-9.+-]{0,62}")
_REDACTION = ("redacted", "metadata_only")


@dataclass(frozen=True)
class PurgeReceipt:
    rows_deleted: int
    files_deleted: int


class ArtifactStore:
    def __init__(self, data_dir: DataDir) -> None:
        self.root = data_dir.artifacts_dir

    # ----------------------------------------------------------------------------------- paths ----
    def path_for(self, sha256: str) -> Path:
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise StoreError(ErrorCode.STORE_004, "an artifact is named by a lower-case SHA-256 digest")
        return self.root / sha256[:2] / sha256

    def _ensure_directory(self, path: Path, *, kind: str) -> None:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise StoreError(ErrorCode.STORE_004, f"the {kind} is a link or not a directory")
            check_private(path, kind="data directory")
            return
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)

    def _regular_file_or_none(self, path: Path) -> bool:
        """True for an existing regular file, False if absent; a link or anything else is refused."""
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode):
            raise StoreError(ErrorCode.STORE_004, "an artifact path is a link or not a regular file")
        return True

    def _verify_file(self, path: Path, sha256: str) -> bytes:
        try:
            with path.open("rb") as handle:
                content = handle.read(MAX_ARTIFACT_BYTES + 1)
        except OSError:
            raise StoreError(ErrorCode.STORE_004, "the artifact file could not be read") from None
        if len(content) > MAX_ARTIFACT_BYTES or hashlib.sha256(content).hexdigest() != sha256:
            raise StoreError(ErrorCode.STORE_005, "the stored bytes do not match their hash: the file was changed")
        return content

    # ------------------------------------------------------------------------------------ write ----
    def put(
        self,
        session: Session,
        *,
        run_id: str,
        content: bytes,
        mime: str,
        now: datetime,
        actor: Actor,
        redaction_status: str = "redacted",
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> Artifact:
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        if not content:
            raise ValueError("empty content is not stored: an empty body has no artifact")
        if len(content) > MAX_ARTIFACT_BYTES:
            raise StoreError(ErrorCode.STORE_006, f"an artifact is at most {MAX_ARTIFACT_BYTES} bytes")
        if redaction_status not in _REDACTION:
            raise ValueError("redaction_status must be redacted or metadata_only: raw content is never stored")
        if not isinstance(mime, str) or not _MIME.fullmatch(mime):
            raise ValueError("mime must be a plain lower-case media type such as text/plain")
        if not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS:
            raise ValueError(f"retention_days must be from {MIN_RETENTION_DAYS} to {MAX_RETENTION_DAYS}")
        if actor.type is not ActorType.WORKER:
            append_event(
                session,
                run_id=None,
                actor=actor,
                action="artifact.store",
                decision="denied",
                reason="only the adapter process stores artifacts",
                now=now,
            )
            session.commit()
            raise StateError(ErrorCode.STATE_003, "only the adapter process may store artifacts")
        sha256 = hashlib.sha256(content).hexdigest()
        path = self.path_for(sha256)
        self._ensure_directory(self.root, kind="artifact directory")
        self._ensure_directory(path.parent, kind="artifact subdirectory")
        created_file = False
        if self._regular_file_or_none(path):
            self._verify_file(path, sha256)  # a duplicate must not trust a file whose bytes no longer match
        else:
            self._write_atomically(path, content)
            created_file = True
        try:
            existing = session.scalars(
                select(Artifact).where(Artifact.run_id == run_id, Artifact.sha256 == sha256)
            ).first()
            if existing is not None:
                return existing
            artifact = Artifact(
                id=_new_id(),
                run_id=run_id,
                sha256=sha256,
                mime=mime,
                redaction_status=redaction_status,
                size=len(content),
                storage_path=f"{sha256[:2]}/{sha256}",
                retention_until=now + timedelta(days=retention_days),
                created_at=now,
            )
            session.add(artifact)
            session.flush()
            append_event(
                session,
                run_id=run_id,
                actor=actor,
                action="artifact.stored",
                decision="allowed",
                reason=f"{sha256} {mime} {len(content)} bytes",
                now=now,
            )
            return artifact
        except BaseException:
            if created_file:  # never leave an orphan that no row accounts for
                path.unlink(missing_ok=True)
            raise

    def _write_atomically(self, path: Path, content: bytes) -> None:
        temporary = path.parent / f".tmp-{secrets.token_hex(8)}"
        descriptor = -1
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(descriptor, content)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            if descriptor != -1:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            path.unlink(missing_ok=True) if self._is_ours(path, content) else None
            raise StoreError(ErrorCode.STORE_005, "the artifact could not be written") from None

    def _is_ours(self, path: Path, content: bytes) -> bool:
        """After a failed rename-and-sync, remove the file only if it is exactly what we were writing."""
        try:
            return path.is_file() and not path.is_symlink() and path.read_bytes() == content
        except OSError:  # pragma: no cover - best effort cleanup
            return False

    # ------------------------------------------------------------------------------------- read ----
    def read(self, sha256: str) -> bytes:
        path = self.path_for(sha256)
        if not self._regular_file_or_none(path):
            raise StoreError(ErrorCode.STORE_004, "the artifact file is missing")
        return self._verify_file(path, sha256)

    # ------------------------------------------------------------------------------------ purge ----
    def purge(self, session: Session, *, before: datetime, now: datetime, actor: Actor) -> PurgeReceipt:
        """Delete artifacts whose retention ended before `before`, and the files nothing else needs. All or nothing on
        refusal."""
        if actor.type is not ActorType.HUMAN:
            append_event(
                session,
                run_id=None,
                actor=actor,
                action="artifacts.purge",
                decision="denied",
                reason="only a human purges",
                now=now,
            )
            session.commit()
            raise StateError(ErrorCode.STATE_003, "only a human may purge artifacts")
        if before.tzinfo is None:
            raise ValueError("before must be timezone-aware")
        due = list(session.scalars(select(Artifact).where(Artifact.retention_until < before)))
        for row in due:
            if row.storage_path != f"{row.sha256[:2]}/{row.sha256}":
                raise StoreError(ErrorCode.STORE_004, "a recorded artifact path does not match its hash")
        due_ids = {row.id for row in due}
        still_needed = {
            sha
            for sha in {row.sha256 for row in due}
            if session.scalars(select(Artifact.id).where(Artifact.sha256 == sha, Artifact.id.not_in(due_ids))).first()
            is not None
        }
        doomed = sorted({row.sha256 for row in due} - still_needed)
        existing_files = [
            self.path_for(sha) for sha in doomed if self._regular_file_or_none(self.path_for(sha))
        ]  # refuses links
        if due_ids:
            session.execute(delete(Artifact).where(Artifact.id.in_(due_ids)))
        files_deleted = 0
        for path in existing_files:
            path.unlink(missing_ok=True)
            files_deleted += 1
        append_event(
            session,
            run_id=None,
            actor=actor,
            action="artifacts.purge",
            decision="allowed",
            reason=f"rows={len(due_ids)} files={files_deleted} before={before.isoformat()}",
            now=now,
        )
        return PurgeReceipt(rows_deleted=len(due_ids), files_deleted=files_deleted)


def _new_id() -> str:
    from scopedagent.ids import new_id  # noqa: PLC0415

    return new_id()
