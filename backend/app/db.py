"""Database session management.

Two engines:
- async_engine: asyncpg (or aiosqlite when DATABASE_URL=sqlite),
  used by FastAPI handlers and the orchestrator's async agents.
- sync_engine: psycopg2 (or sqlite3 fallback), used by Celery.

SQLite fallback lets the API run locally without Docker/Postgres
(e.g. for the Playwright e2e suite). Production uses Postgres + JSONB.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import AsyncIterator, Iterator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


# Default to sqlite file in /tmp for local dev / e2e if nothing is set.
DEFAULT_SQLITE = f"sqlite:///{Path(os.getenv('KANGAL_SQLITE_PATH', '/tmp/kangal.db')).as_posix()}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE)


def _async_url(url: str) -> str:
    if _is_sqlite(url):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


DATABASE_URL_ASYNC = os.getenv("DATABASE_URL_ASYNC", _async_url(DATABASE_URL))


def _engine_kwargs(url: str) -> dict:
    if _is_sqlite(url):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}


async_engine = create_async_engine(
    DATABASE_URL_ASYNC, echo=False, **_engine_kwargs(DATABASE_URL)
)
AsyncSessionLocal = async_sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)

sync_engine = create_engine(DATABASE_URL, echo=False, **_engine_kwargs(DATABASE_URL))
SyncSessionLocal = sessionmaker(sync_engine, expire_on_commit=False, class_=Session)


async def init_db() -> None:
    """Create all tables. Idempotent."""
    # SQLite needs ForeignKeys enabled for cascade to work.
    if _is_sqlite(DATABASE_URL):
        from sqlalchemy import event, text

        @event.listens_for(sync_engine, "connect")
        def _fk_on(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


def session_scope() -> Iterator[Session]:
    """Context-manager style sync session for Celery tasks."""
    s = SyncSessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
