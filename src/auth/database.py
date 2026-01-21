"""Database configuration with WAL mode support for multi-process access."""

from __future__ import annotations

from collections.abc import Callable, Generator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import Session, sessionmaker

from .config import AuthConfig


def enable_wal_mode(
    dbapi_conn: DBAPIConnection,
    connection_record: object,
) -> None:
    """Enable WAL mode and set optimization pragmas for SQLite.

    This function should be registered as an event listener on SQLite engines.
    WAL mode enables concurrent reads and single writer, critical for multi-process access.
    """
    _ = connection_record
    cursor = dbapi_conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA mmap_size=30000000000")
        cursor.execute("PRAGMA wal_autocheckpoint=1000")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def create_db_engine(
    db_url: str,
    *,
    echo: bool = False,
) -> Engine:
    """Create SQLAlchemy engine with WAL mode for SQLite.

    Args:
        db_url: Database URL (SQLite or other)
        echo: Enable SQL query logging

    Returns:
        SQLAlchemy engine instance
    """
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        echo=echo,
        pool_size=20,
        max_overflow=40,
    )

    # Register WAL mode listener for SQLite
    if db_url.lower().startswith("sqlite"):
        event.listen(engine, "connect", enable_wal_mode)

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create session factory from engine.

    Args:
        engine: SQLAlchemy engine

    Returns:
        Session factory
    """
    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        class_=Session,
    )


def get_db_session(
    session_factory: Callable[[], Session],
) -> Generator[Session, None, None]:
    """Database session dependency for FastAPI.

    Args:
        session_factory: Session factory callable

    Yields:
        Database session
    """
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


# Global session factory
SessionLocal: sessionmaker[Session] | None = None


def init_db(config: AuthConfig) -> None:
    """Initialize database connection."""
    global SessionLocal
    engine = create_db_engine(config.database_url, echo=False)
    SessionLocal = create_session_factory(engine)


def get_db() -> Generator[Session, None, None]:
    """Get database session for FastAPI dependency injection."""
    if SessionLocal is None:
        raise RuntimeError("Database not initialized")
    yield from get_db_session(SessionLocal)
