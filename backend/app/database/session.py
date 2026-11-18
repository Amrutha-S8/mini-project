"""SQLAlchemy engines and session factories.

Two engines are created deliberately:

* ``writer`` — normal read/write access used by the deterministic core.
* ``readonly`` — opened with the SQLite ``mode=ro`` URI, which makes writes
  fail **inside the database engine itself**. This is the handle the AI tier
  (M15-M18) receives, so SR-AI-05/06 is enforced structurally rather than by
  convention. A bug or a prompt injection in the AI tier cannot write, because
  the connection physically cannot.

SQLite pragmas are applied on every connection: WAL for concurrent readers,
``foreign_keys=ON`` because SQLite disables FK enforcement by default, and a
busy timeout to absorb brief writer contention.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings


def _register_pragmas(engine: Engine, *, busy_timeout_ms: int) -> None:
    """Attach a connect-time hook that applies the required pragmas."""

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()


def _register_readonly_pragmas(engine: Engine) -> None:
    """Read-only connections cannot change journal mode, so apply only FK."""

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


def resolve_database_path(settings: Settings) -> Path:
    """Absolute database path, creating the parent directory if needed."""
    path = Path(settings.database_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def create_writer_engine(settings: Settings | None = None) -> Engine:
    """Read/write engine for the deterministic core."""
    settings = settings or get_settings()
    path = resolve_database_path(settings)
    engine = create_engine(
        f"sqlite:///{path}",
        echo=False,
        future=True,
        connect_args={"check_same_thread": False},
    )
    _register_pragmas(engine, busy_timeout_ms=settings.sqlite_busy_timeout_ms)
    return engine


def create_readonly_engine(settings: Settings | None = None) -> Engine:
    """Read-only engine handed to the AI/advisory tier.

    ``mode=ro`` is enforced by SQLite: any INSERT/UPDATE/DELETE/CREATE/DROP
    raises ``sqlite3.OperationalError: attempt to write a readonly database``.
    """
    settings = settings or get_settings()
    path = resolve_database_path(settings)
    engine = create_engine(
        f"sqlite:///file:{path}?mode=ro&uri=true",
        echo=False,
        future=True,
        connect_args={"check_same_thread": False, "uri": True},
    )
    _register_readonly_pragmas(engine)
    return engine


_writer_engine: Engine | None = None
_readonly_engine: Engine | None = None
_WriterSession: sessionmaker[Session] | None = None
_ReadOnlySession: sessionmaker[Session] | None = None


def init_engines(settings: Settings | None = None) -> None:
    """Create both engines and their session factories (called at startup)."""
    global _writer_engine, _readonly_engine, _WriterSession, _ReadOnlySession
    settings = settings or get_settings()
    _writer_engine = create_writer_engine(settings)
    _readonly_engine = create_readonly_engine(settings)
    _WriterSession = sessionmaker(
        bind=_writer_engine, autoflush=False, expire_on_commit=False
    )
    _ReadOnlySession = sessionmaker(
        bind=_readonly_engine, autoflush=False, expire_on_commit=False
    )


def dispose_engines() -> None:
    """Release pooled connections (called at shutdown)."""
    global _writer_engine, _readonly_engine
    for engine in (_writer_engine, _readonly_engine):
        if engine is not None:
            engine.dispose()
    _writer_engine = None
    _readonly_engine = None


def get_writer_engine() -> Engine:
    if _writer_engine is None:
        raise RuntimeError("engines not initialised; call init_engines() first")
    return _writer_engine


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a read/write session.

    Commits on success, rolls back on exception. Transactions stay short to
    respect SQLite's single-writer constraint.
    """
    if _WriterSession is None:
        raise RuntimeError("engines not initialised; call init_engines() first")
    session = _WriterSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_readonly_session() -> Iterator[Session]:
    """FastAPI dependency yielding the READ-ONLY session.

    This is the ONLY database handle the AI tier may receive. It never commits.
    """
    if _ReadOnlySession is None:
        raise RuntimeError("engines not initialised; call init_engines() first")
    session = _ReadOnlySession()
    try:
        yield session
    finally:
        session.close()


def healthcheck(connection_factory: Engine | None = None) -> bool:
    """Execute a trivial query to prove the database is reachable."""
    from sqlalchemy import text

    engine = connection_factory or get_writer_engine()
    conn: Connection
    with engine.connect() as conn:
        return conn.execute(text("SELECT 1")).scalar_one() == 1
