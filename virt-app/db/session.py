"""Session factories and FastAPI dependencies for async SQLAlchemy usage."""

from __future__ import annotations

from functools import lru_cache
from typing import AsyncIterator, Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .engine import get_async_engine


@lru_cache
def get_async_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the shared async session factory bound to the app engine."""

    engine = get_async_engine()
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_async_session() -> AsyncIterator[AsyncSession]:
    """Yield an application-scoped async SQLAlchemy session."""

    async_session_factory = get_async_session_factory()
    async with async_session_factory() as session:
        yield session


def async_session_dependency() -> Callable[[], AsyncIterator[AsyncSession]]:
    """Provide a FastAPI dependency factory for async DB sessions."""

    return get_async_session


__all__ = ["get_async_session", "async_session_dependency", "get_async_session_factory"]
