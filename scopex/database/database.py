"""
SCOPEX database management.

Provides the SQLite database engine and session management
used throughout the application.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from scopex.core.config import DATABASE_PATH, ensure_directories


# ============================================================
# Database Configuration
# ============================================================

def get_database_url() -> str:
    """
    Build the SQLAlchemy connection URL for the SCOPEX database.
    """

    database_path = Path(DATABASE_PATH).resolve()

    return f"sqlite:///{database_path.as_posix()}"


# ============================================================
# Engine
# ============================================================

ensure_directories()

DATABASE_URL = get_database_url()

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
    },
    echo=False,
)


# ============================================================
# Session Factory
# ============================================================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# ============================================================
# Database Initialization
# ============================================================

def init_database() -> None:
    """
    Initialize the SCOPEX database.

    Tables will be created by the ORM models once they are
    registered with the SQLAlchemy metadata.
    """

    from scopex.database.models import Base

    Base.metadata.create_all(bind=engine)


# ============================================================
# Session Management
# ============================================================

def get_session() -> Session:
    """
    Create and return a new database session.

    The caller is responsible for closing the session.
    """

    return SessionLocal()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional database session.

    Automatically commits successful operations and rolls back
    if an exception occurs.
    """

    session = SessionLocal()

    try:
        yield session
        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


# ============================================================
# Health Check
# ============================================================

def check_database_connection() -> bool:
    """
    Check whether SCOPEX can successfully communicate with
    the SQLite database.

    Returns:
        True if the connection succeeds.
        False otherwise.
    """

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return True

    except Exception:
        return False