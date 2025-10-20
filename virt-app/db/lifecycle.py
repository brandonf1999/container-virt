"""Application lifecycle helpers for database access."""

from __future__ import annotations

import asyncio

from typing import Any

from .engine import get_async_engine
from .ingestion import set_main_loop


async def on_startup() -> None:
    """Ensure the async engine can connect on application startup."""

    loop = asyncio.get_running_loop()
    set_main_loop(loop)

    engine = get_async_engine()
    async with engine.begin() as connection:
        await connection.run_sync(lambda _: None)


async def on_shutdown() -> None:
    """Dispose the async engine when the application shuts down."""

    engine = get_async_engine()
    await engine.dispose()


__all__ = ["on_startup", "on_shutdown"]
