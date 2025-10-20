"""Database configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _load_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    truthy = {"1", "true", "t", "yes", "y", "on"}
    falsy = {"0", "false", "f", "no", "n", "off"}
    lowered = raw.strip().lower()
    if lowered in truthy:
        return True
    if lowered in falsy:
        return False
    return default


def _load_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class DatabaseSettings:
    """Application database settings sourced from environment variables."""

    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/virtlab"
    )
    pool_size: int = _load_int("DATABASE_POOL_SIZE", 5)
    max_overflow: int = _load_int("DATABASE_MAX_OVERFLOW", 10)
    pool_timeout: int = _load_int("DATABASE_POOL_TIMEOUT", 30)
    echo: bool = _load_bool("DATABASE_ECHO", False)


@lru_cache
def get_database_settings() -> DatabaseSettings:
    """Return cached database settings for reuse across the app."""

    return DatabaseSettings()


__all__ = ["DatabaseSettings", "get_database_settings"]
