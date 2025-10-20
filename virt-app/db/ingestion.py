"""Helpers that bridge synchronous libvirt inventory collection with async DB persistence."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Coroutine

from .repositories.hosts import ensure_host
from .repositories.domains import sync_domain_inventory
from .repositories.network import sync_network_inventory
from .repositories.storage import sync_storage_inventory
from .session import get_async_session_factory

logger = logging.getLogger(__name__)

_MAIN_LOOP: Optional[asyncio.AbstractEventLoop] = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Record the application event loop to schedule ingestion work on."""

    global _MAIN_LOOP
    _MAIN_LOOP = loop


def _run_async(coro: Coroutine[Any, Any, None]) -> None:
    """Execute the coroutine on the main loop or a temporary loop."""

    if _MAIN_LOOP is not None:
        if _MAIN_LOOP.is_running():
            future = asyncio.run_coroutine_threadsafe(coro, _MAIN_LOOP)
            future.result()
            return
        _MAIN_LOOP.run_until_complete(coro)
        return

    # Fallback for early calls before startup
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(coro)
    finally:
        loop.close()


def _attach_logging(task: asyncio.Task) -> None:
    def _log_failure(done: asyncio.Task) -> None:
        try:
            exc = done.exception()
        except asyncio.CancelledError:
            return
        if exc:
            logger.error("Inventory ingestion task failed", exc_info=exc)

    task.add_done_callback(_log_failure)


async def _ingest_storage_async(
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str],
    ssh_options: Optional[dict],
    inventory: Dict[str, Any],
) -> None:
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        host = await ensure_host(
            session,
            hostname=hostname,
            uri=uri,
            user=user,
            ssh_options=ssh_options,
        )
        await sync_storage_inventory(session, host=host, inventory=inventory)
        await session.commit()
        logger.debug(
            "Storage inventory synced",
            extra={"host": hostname, "pool_count": len(inventory.get("pools") or [])},
        )


async def _ingest_network_async(
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str],
    ssh_options: Optional[dict],
    inventory: Dict[str, Any],
) -> None:
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        host = await ensure_host(
            session,
            hostname=hostname,
            uri=uri,
            user=user,
            ssh_options=ssh_options,
        )
        await sync_network_inventory(session, host=host, inventory=inventory)
        await session.commit()
        logger.debug(
            "Network inventory synced",
            extra={"host": hostname, "network_count": len(inventory.get("networks") or [])},
        )


async def _ingest_domain_async(
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str],
    ssh_options: Optional[dict],
    inventory: Dict[str, Any],
) -> None:
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        host = await ensure_host(
            session,
            hostname=hostname,
            uri=uri,
            user=user,
            ssh_options=ssh_options,
        )
        await sync_domain_inventory(session, host=host, inventory=inventory)
        await session.commit()
        logger.debug(
            "Domain inventory synced",
            extra={"host": hostname, "vm_count": len(inventory.get("vms") or [])},
        )


def ingest_storage_inventory(
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str],
    ssh_options: Optional[dict],
    inventory: Dict[str, Any],
) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _run_async(
            _ingest_storage_async(
                hostname=hostname,
                uri=uri,
                user=user,
                ssh_options=ssh_options,
                inventory=inventory,
            )
        )
        return

    task = loop.create_task(
        _ingest_storage_async(
            hostname=hostname,
            uri=uri,
            user=user,
            ssh_options=ssh_options,
            inventory=inventory,
        )
    )
    _attach_logging(task)


def ingest_network_inventory(
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str],
    ssh_options: Optional[dict],
    inventory: Dict[str, Any],
) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _run_async(
            _ingest_network_async(
                hostname=hostname,
                uri=uri,
                user=user,
                ssh_options=ssh_options,
                inventory=inventory,
            )
        )
        return

    task = loop.create_task(
        _ingest_network_async(
            hostname=hostname,
            uri=uri,
            user=user,
            ssh_options=ssh_options,
            inventory=inventory,
        )
    )
    _attach_logging(task)


def ingest_domain_inventory(
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str],
    ssh_options: Optional[dict],
    inventory: Dict[str, Any],
) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _run_async(
            _ingest_domain_async(
                hostname=hostname,
                uri=uri,
                user=user,
                ssh_options=ssh_options,
                inventory=inventory,
            )
        )
        return

    task = loop.create_task(
        _ingest_domain_async(
            hostname=hostname,
            uri=uri,
            user=user,
            ssh_options=ssh_options,
            inventory=inventory,
        )
    )
    _attach_logging(task)


__all__ = [
    "ingest_storage_inventory",
    "ingest_network_inventory",
    "ingest_domain_inventory",
    "set_main_loop",
]
