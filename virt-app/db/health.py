"""Database health-check utilities."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def ensure_connection(session: AsyncSession) -> None:
    """Run a lightweight query to confirm the database connection is healthy."""

    await session.execute(text("SELECT 1"))


__all__ = ["ensure_connection"]
