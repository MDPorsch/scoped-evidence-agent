"""AE-11, AE-13, AE-14, X-03, X-04: artifacts are redacted-only, private, atomic, hash-checked and purged safely."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from scopedagent.domain.models import Artifact, AuditEvent
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, StateError, StoreError
from scopedagent.storage.artifacts import ArtifactStore
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.database import DataDir, open_database, upgrade_database
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from tests.support import NOW, seed, sql_insert, stamp

pytestmark = pytest.mark.milestone("M1")

HUMAN = Actor(ActorType.HUMAN, "alice")
WORKER = Actor(ActorType.WORKER, "worker-1")
BODY = b"User-agent: *\nDisallow: /admin\n"
SHA = hashlib.sha256(BODY).hexdigest()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def env(tmp_path: Path) -> Any:
    data_dir = DataDir(tmp_path / "data")
    upgrade_database(data_dir)
    db = open_database(data_dir)
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
    yield db, ArtifactStore(data_dir), data_dir
    db.close()


def put(env: Any, content: bytes = BODY, *, run_id: str = "r1", now: Any = NOW, **kw: Any) -> Artifact:
    db, store, _ = env
    with db.begin() as session:
        return store.put(
            session,
            run_id=run_id,
            content=content,
            mime=kw.pop("mime", "text/plain"),
            now=now,
            actor=kw.pop("actor", WORKER),
            **kw,
        )


# ------------------------------------------------------------------------------------- storing ----
def test_content_is_stored_by_its_hash_with_private_permissions(env: Any) -> None:
    _, store, data_dir = env
    artifact = put(env)
    assert artifact.sha256 == SHA and artifact.size == len(BODY) and artifact.redaction_status == "redacted"
    assert artifact.storage_path == f"{SHA[:2]}/{SHA}" and artifact.mime == "text/plain"
    path = store.path_for(SHA)
    assert path == data_dir.artifacts_dir / SHA[:2] / SHA and path.read_bytes() == BODY
    assert mode(data_dir.artifacts_dir) == 0o700 and mode(path.parent) == 0o700 and mode(path) == 0o600


def test_permissions_do_not_depend_on_the_process_umask(env: Any) -> None:
    previous = os.umask(0)
    try:
        put(env)
    finally:
        os.umask(previous)
    _, store, data_dir = env
    assert mode(store.path_for(SHA)) == 0o600 and mode(data_dir.artifacts_dir) == 0o700


def test_retention_defaults_to_30_days_and_is_bounded(env: Any) -> None:
    assert put(env).retention_until == NOW + timedelta(days=30)
    assert put(env, b"other", retention_days=1).retention_until == NOW + timedelta(days=1)
    assert put(env, b"third", retention_days=365).retention_until == NOW + timedelta(days=365)
    for bad in (0, -1, 366):
        with pytest.raises(ValueError, match="retention"):
            put(env, b"x" + bytes([bad % 256]), retention_days=bad)


def test_the_same_content_twice_in_one_run_is_one_row_and_one_file(env: Any) -> None:
    first, second = put(env), put(env)
    assert first.id == second.id
    db, _, data_dir = env
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM artifacts")).scalar() == 1
    assert len([p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()]) == 1


def test_the_same_content_in_two_runs_is_two_rows_sharing_one_file(env: Any) -> None:
    a, b = put(env, run_id="r1"), put(env, run_id="r2")
    assert a.id != b.id and a.run_id == "r1" and b.run_id == "r2"
    _, _, data_dir = env
    assert len([p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()]) == 1


def test_only_redacted_or_metadata_only_content_is_accepted(env: Any) -> None:
    put(env, b"meta", redaction_status="metadata_only")
    for bad in ("raw", "pending", "unredacted", "", None):
        with pytest.raises(ValueError, match="redaction"):
            put(env, b"x", redaction_status=bad)
    _, _, data_dir = env
    assert (
        len([p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()]) == 1
    )  # nothing was written for the refusals


@pytest.mark.parametrize(
    "mime",
    ["", "text", "TEXT/PLAIN", "text/plain; charset=utf-8", "text/plain\n", "a/b/c", "x" * 120 + "/y", "text/ plain"],
)
def test_the_media_type_must_be_a_plain_lower_case_type(env: Any, mime: str) -> None:
    with pytest.raises(ValueError, match="mime"):
        put(env, b"x", mime=mime)


def test_the_size_cap_is_2_000_000_bytes_and_empty_content_is_refused(env: Any) -> None:
    assert put(env, b"a" * 2_000_000).size == 2_000_000
    with pytest.raises(StoreError) as caught:
        put(env, b"a" * 2_000_001)
    assert caught.value.code is ErrorCode.STORE_006
    with pytest.raises(ValueError, match="empty"):
        put(env, b"")


def test_only_content_that_is_bytes_is_accepted(env: Any) -> None:
    for bad in ("text", bytearray(b"x"), None, 5):
        with pytest.raises(TypeError):
            put(env, bad)  # type: ignore[arg-type]


def test_storing_is_audited(env: Any) -> None:
    put(env)
    db, _, _ = env
    with db.begin() as session:
        (event,) = session.scalars(select(AuditEvent).where(AuditEvent.action == "artifact.stored")).all()
        assert event.run_id == "r1" and SHA in event.reason
        verify_chain(session, "r1")


# --------------------------------------------------------------------------- permissions refused ----
def test_an_artifact_directory_that_is_too_open_is_refused_not_silently_fixed(env: Any) -> None:
    _, _, data_dir = env
    data_dir.artifacts_dir.mkdir(mode=0o700)
    os.chmod(data_dir.artifacts_dir, 0o755)
    with pytest.raises(StoreError) as caught:
        put(env)
    assert caught.value.code is ErrorCode.STORE_003 and mode(data_dir.artifacts_dir) == 0o755


def test_a_symlinked_prefix_directory_is_refused(env: Any, tmp_path: Path) -> None:
    _, _, data_dir = env
    data_dir.artifacts_dir.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (data_dir.artifacts_dir / SHA[:2]).symlink_to(elsewhere)
    with pytest.raises(StoreError) as caught:
        put(env)
    assert caught.value.code is ErrorCode.STORE_004
    assert list(elsewhere.iterdir()) == []


def test_a_planted_symlink_in_place_of_the_file_is_refused(env: Any, tmp_path: Path) -> None:
    _, _, data_dir = env
    prefix = data_dir.artifacts_dir / SHA[:2]
    prefix.mkdir(parents=True, mode=0o700)
    target = tmp_path / "victim"
    target.write_bytes(b"do not touch")
    (prefix / SHA).symlink_to(target)
    with pytest.raises(StoreError) as caught:
        put(env)
    assert caught.value.code is ErrorCode.STORE_004 and target.read_bytes() == b"do not touch"


@pytest.mark.parametrize(
    "sha",
    ["", "x", "../../etc/passwd", "A" * 64, "a" * 63, "a" * 65, "a" * 63 + "/", "a" * 62 + "..", "ab/" + "c" * 60],
)
def test_path_for_accepts_only_a_lower_case_sha256(env: Any, sha: str) -> None:
    _, store, _ = env
    with pytest.raises(StoreError) as caught:
        store.path_for(sha)
    assert caught.value.code is ErrorCode.STORE_004


# ---------------------------------------------------------------------------- reading and tamper ----
def test_read_returns_the_bytes_and_verifies_their_hash(env: Any) -> None:
    _, store, _ = env
    put(env)
    assert store.read(SHA) == BODY


def test_a_file_changed_after_it_was_stored_is_detected_on_read_and_on_store(env: Any) -> None:
    _, store, _ = env
    put(env)
    path = store.path_for(SHA)
    os.chmod(path, 0o600)
    path.write_bytes(b"tampered")
    with pytest.raises(StoreError) as caught:
        store.read(SHA)
    assert caught.value.code is ErrorCode.STORE_005
    with pytest.raises(StoreError) as again:
        put(env)  # a dedupe must not trust a file whose hash no longer matches
    assert again.value.code is ErrorCode.STORE_005


def test_reading_a_missing_artifact_is_an_error_not_an_empty_result(env: Any) -> None:
    _, store, _ = env
    with pytest.raises(StoreError) as caught:
        store.read(SHA)
    assert caught.value.code is ErrorCode.STORE_004


# -------------------------------------------------------------------------------- AE-11: atomic ----
def test_a_failed_rename_leaves_no_file_no_temp_file_and_no_row(env: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import scopedagent.storage.artifacts as module  # noqa: PLC0415

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("disk went away")

    monkeypatch.setattr(module.os, "replace", boom)
    with pytest.raises(StoreError) as caught:
        put(env)
    assert caught.value.code is ErrorCode.STORE_005
    db, _, data_dir = env
    assert [p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()] == []
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM artifacts")).scalar() == 0


def test_a_failed_fsync_leaves_nothing_behind(env: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import scopedagent.storage.artifacts as module  # noqa: PLC0415

    monkeypatch.setattr(module.os, "fsync", lambda *_a: (_ for _ in ()).throw(OSError("no space left")))
    with pytest.raises(StoreError) as caught:
        put(env)
    assert caught.value.code is ErrorCode.STORE_005
    _, _, data_dir = env
    assert [p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()] == []


def test_a_database_failure_after_the_file_was_written_removes_the_new_file(env: Any) -> None:
    _, store, data_dir = env
    db, _, _ = env
    with pytest.raises(DatabaseError), db.begin() as session:
        store.put(session, run_id="no-such-run", content=BODY, mime="text/plain", now=NOW, actor=WORKER)
    assert [p for p in data_dir.artifacts_dir.rglob("*") if p.is_file()] == []


def test_a_database_failure_does_not_remove_a_file_another_run_already_owns(env: Any) -> None:
    _, store, _ = env
    db, _, _ = env
    put(env, run_id="r1")
    with pytest.raises(DatabaseError), db.begin() as session:
        store.put(session, run_id="no-such-run", content=BODY, mime="text/plain", now=NOW, actor=WORKER)
    assert store.read(SHA) == BODY


def test_only_the_adapter_process_stores_artifacts(env: Any) -> None:
    for actor in (Actor(ActorType.MODEL, "model-x"), HUMAN):
        with pytest.raises(StateError) as caught:
            put(env, actor=actor)
        assert caught.value.code is ErrorCode.STATE_003


# ------------------------------------------------------------------------------------- purging ----
def purge(env: Any, before: Any, *, actor: Actor = HUMAN) -> Any:
    db, store, _ = env
    with db.begin() as session:
        return store.purge(session, before=before, now=NOW + timedelta(days=60), actor=actor)


def test_purge_deletes_expired_rows_and_their_files_and_writes_a_receipt(env: Any) -> None:
    _, store, data_dir = env
    put(env, b"old", retention_days=1)
    put(env, b"new", retention_days=90)
    receipt = purge(env, NOW + timedelta(days=30))
    assert (receipt.rows_deleted, receipt.files_deleted) == (1, 1)
    assert not store.path_for(hashlib.sha256(b"old").hexdigest()).exists()
    assert store.path_for(hashlib.sha256(b"new").hexdigest()).exists()
    db, _, _ = env
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM artifacts")).scalar() == 1
        (event,) = session.scalars(select(AuditEvent).where(AuditEvent.action == "artifacts.purge")).all()
        assert (
            event.run_id is None
            and event.actor_id == "alice"
            and "rows=1" in event.reason
            and "files=1" in event.reason
        )
        verify_chain(session, None)
    assert data_dir.artifacts_dir.exists()


def test_purge_keeps_a_shared_file_until_every_row_that_needs_it_is_gone(env: Any) -> None:
    _, store, _ = env
    put(env, run_id="r1", retention_days=1)
    put(env, run_id="r2", retention_days=90)
    first = purge(env, NOW + timedelta(days=30))
    assert (first.rows_deleted, first.files_deleted) == (1, 0) and store.path_for(SHA).exists()
    second = purge(env, NOW + timedelta(days=200))
    assert (second.rows_deleted, second.files_deleted) == (1, 1) and not store.path_for(SHA).exists()


def test_purge_with_nothing_due_still_writes_a_receipt(env: Any) -> None:
    put(env, retention_days=90)
    receipt = purge(env, NOW)
    assert (receipt.rows_deleted, receipt.files_deleted) == (0, 0)
    db, _, _ = env
    with db.begin() as session:
        assert session.scalars(select(AuditEvent).where(AuditEvent.action == "artifacts.purge")).all()


def test_the_cut_off_is_exclusive(env: Any) -> None:
    put(env, retention_days=1)
    assert purge(env, NOW + timedelta(days=1)).rows_deleted == 0
    assert purge(env, NOW + timedelta(days=1, seconds=1)).rows_deleted == 1


def test_only_a_human_may_purge(env: Any) -> None:
    put(env, retention_days=1)
    for actor in (WORKER, Actor(ActorType.MODEL, "model-x")):
        with pytest.raises(StateError) as caught:
            purge(env, NOW + timedelta(days=30), actor=actor)
        assert caught.value.code is ErrorCode.STATE_003
    assert purge(env, NOW + timedelta(days=30)).rows_deleted == 1


def test_a_forged_storage_path_is_refused_and_nothing_is_deleted_outside_the_root(env: Any, tmp_path: Path) -> None:
    db, store, _ = env
    put(env, retention_days=1)
    secret = tmp_path / "secret"
    secret.write_text("keep me")
    with db.begin() as session:
        session.execute(text("UPDATE artifacts SET storage_path = :p"), {"p": "../../../" + secret.name})
    with pytest.raises(StoreError) as caught:
        purge(env, NOW + timedelta(days=30))
    assert caught.value.code is ErrorCode.STORE_004
    assert secret.read_text() == "keep me" and store.path_for(SHA).exists()
    with db.begin() as session:
        assert (
            session.execute(text("SELECT count(*) FROM artifacts")).scalar() == 1
        )  # all-or-nothing: the rows were not deleted either


def test_a_symlink_in_place_of_an_artifact_file_stops_the_purge(env: Any, tmp_path: Path) -> None:
    db, store, _ = env
    put(env, retention_days=1)
    path = store.path_for(SHA)
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    path.unlink()
    path.symlink_to(victim)
    with pytest.raises(StoreError) as caught:
        purge(env, NOW + timedelta(days=30))
    assert caught.value.code is ErrorCode.STORE_004 and victim.read_text() == "keep me"
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM artifacts")).scalar() == 1


def test_a_file_that_is_already_gone_is_not_an_error_for_purge(env: Any) -> None:
    _, store, _ = env
    put(env, retention_days=1)
    store.path_for(SHA).unlink()
    receipt = purge(env, NOW + timedelta(days=30))
    assert (receipt.rows_deleted, receipt.files_deleted) == (1, 0)
