"""SQLAlchemy engine factories for async runtime and sync migrations."""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from .config import get_database_settings


def _build_async_engine() -> AsyncEngine:
    settings = get_database_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.echo,
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_timeout=settings.pool_timeout,
        pool_pre_ping=True,
    )


@lru_cache
def get_async_engine() -> AsyncEngine:
    """Return a cached async SQLAlchemy engine for application use."""

    return _build_async_engine()


def _derive_sync_url(async_url: str) -> str:
    url: URL = make_url(async_url)
    if "+" in url.drivername:
        driver, _async_driver = url.drivername.split("+", 1)
        url = url.set(drivername=driver)
    return str(url)


@lru_cache
def get_sync_engine(*, use_null_pool: bool = True) -> Engine:
    """Return a sync engine for Alembic migrations and scripts."""

    settings = get_database_settings()
    connect_args: Optional[dict[str, object]] = None
    poolclass = NullPool if use_null_pool else None
    engine = create_engine(
        _derive_sync_url(settings.database_url),
        echo=settings.echo,
        poolclass=poolclass,
        connect_args=connect_args,
    )
    return engine


__all__ = ["get_async_engine", "get_sync_engine"]
