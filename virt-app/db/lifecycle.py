"""Application lifecycle helpers for database access."""

from __future__ import annotations

import asyncio
import logging

from .engine import get_async_engine
from .ingestion import set_main_loop
from app.core.auto_eject import shutdown_auto_eject_watchers

logger = logging.getLogger(__name__)


async def on_startup() -> None:
    """Ensure the async engine can connect on application startup."""

    loop = asyncio.get_running_loop()
    set_main_loop(loop)

    engine = get_async_engine()
    try:
        async with engine.begin() as connection:
            await connection.run_sync(lambda _: None)
        logger.info("Database connectivity verified during startup")
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Database connection check failed; continuing without DB: %s", exc)


async def on_shutdown() -> None:
    """Dispose the async engine when the application shuts down."""

    shutdown_auto_eject_watchers()
    engine = get_async_engine()
    await engine.dispose()


__all__ = ["on_startup", "on_shutdown"]
