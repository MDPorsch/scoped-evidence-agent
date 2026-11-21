"""The SQLite store: private files, enforced foreign keys, write transactions that take the lock at once, and no
automatic migration.

`upgrade_database` is the only thing that changes the schema, and only when the operator runs `scoped-agent db
upgrade` (D-E10).
`open_database` refuses a store that does not exist, has loose permissions, or is at a revision this code does not know.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session

from scopedagent.errors import ErrorCode, StoreError

HEAD_REVISION = "0002"
_MIGRATIONS = Path(__file__).parent / "migrations"


@dataclass(frozen=True)
class DataDir:
    root: Path

    @property
    def db_path(self) -> Path:
        return self.root / "evidence.sqlite"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def key_path(self) -> Path:
        return self.root / "hmac.key"


def check_private(path: Path, *, kind: str) -> None:
    """A path that others can read or write, that is not ours, or that is a link, is refused (STORE-003). Never
    silently fixed."""
    try:
        info = path.lstat()
    except OSError:
        raise StoreError(ErrorCode.STORE_001, f"the {kind} does not exist") from None
    if stat.S_ISLNK(info.st_mode):
        raise StoreError(ErrorCode.STORE_003, f"the {kind} is a symbolic link")
    wanted = stat.S_ISDIR if kind == "data directory" else stat.S_ISREG
    if not wanted(info.st_mode):
        raise StoreError(ErrorCode.STORE_003, f"the {kind} is not the kind of file expected")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise StoreError(
            ErrorCode.STORE_003,
            f"the {kind} is accessible to other users (mode {stat.S_IMODE(info.st_mode):o}); run: chmod go-rwx on it",
        )
    if info.st_uid != os.getuid():
        raise StoreError(ErrorCode.STORE_003, f"the {kind} is owned by another user")


def _ensure_directory(root: Path) -> None:
    if root.exists() or root.is_symlink():
        check_private(root, kind="data directory")
        return
    root.mkdir(mode=0o700, parents=True)
    os.chmod(root, 0o700)  # the process umask must not decide this


def _alembic_config(path: Path) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
    return config


def _read_revision(path: Path) -> str | None:
    """The stored schema revision, or None when the file has no version table."""
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        try:
            rows = connection.execute("SELECT version_num FROM alembic_version").fetchall()
        except sqlite3.OperationalError:
            return None
    finally:
        connection.close()
    if len(rows) != 1:
        return None
    revision: str = rows[0][0]
    return revision


def upgrade_database(data_dir: DataDir) -> str:
    """Create the store if needed and bring it to the head revision. Returns the revision."""
    _ensure_directory(data_dir.root)
    path = data_dir.db_path
    if not path.exists() and not path.is_symlink():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)
    check_private(path, kind="database file")
    command.upgrade(_alembic_config(path), "head")
    check_private(path, kind="database file")
    revision = _read_revision(path)
    if revision != HEAD_REVISION:  # pragma: no cover - alembic reached head, so this would be a bug
        raise StoreError(ErrorCode.STORE_002, "the schema is not at the expected revision after the upgrade")
    return revision


class Database:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    @contextmanager
    def begin(self) -> Iterator[Session]:
        """One write transaction: the lock is taken at its start, it commits at the end, and any error rolls it all
        back."""
        session = Session(self.engine, expire_on_commit=False)
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def close(self) -> None:
        self.engine.dispose()


def open_database(data_dir: DataDir, *, busy_timeout_ms: int = 5000) -> Database:
    """Open an existing, private, current-revision store. It creates nothing and migrates nothing."""
    if not data_dir.root.exists() and not data_dir.root.is_symlink():
        raise StoreError(ErrorCode.STORE_001, f"no database at {data_dir.root}: run `scoped-agent db upgrade` first")
    check_private(data_dir.root, kind="data directory")
    if not data_dir.db_path.exists() and not data_dir.db_path.is_symlink():
        raise StoreError(ErrorCode.STORE_001, f"no database at {data_dir.db_path}: run `scoped-agent db upgrade` first")
    check_private(data_dir.db_path, kind="database file")
    if _read_revision(data_dir.db_path) != HEAD_REVISION:
        raise StoreError(
            ErrorCode.STORE_002,
            "the database is not at a schema revision this version knows: run `scoped-agent db upgrade`",
        )
    engine = create_engine(f"sqlite:///{data_dir.db_path}", connect_args={"timeout": busy_timeout_ms / 1000})

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None  # we issue BEGIN ourselves
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _on_begin(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return Database(engine)
