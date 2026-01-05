"""Auto-eject helpers that remove installer ISOs after the first reboot."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Iterable, Optional

from fastapi.concurrency import run_in_threadpool

logger = logging.getLogger(__name__)

_RUNNING_STATES = {"running", "blocked"}
_SHUTOFF_STATES = {"shutoff", "shutdown"}

_watch_tasks: dict[tuple[str, str], asyncio.Task[None]] = {}


def collect_cdrom_targets(details: dict | None, *, limit: int | None = None) -> list[str]:
    """Return CD-ROM target identifiers from a domain detail payload."""

    if not isinstance(details, dict):
        return []
    block_devices = details.get("block_devices")
    if not isinstance(block_devices, list):
        return []
    targets: list[str] = []
    for entry in block_devices:
        if not isinstance(entry, dict):
            continue
        device_type = str(entry.get("device") or "").lower()
        if device_type != "cdrom":
            continue
        target = entry.get("target")
        if isinstance(target, str) and target:
            targets.append(target)
            if limit is not None and len(targets) >= limit:
                break
    return targets


def schedule_iso_auto_eject(
    cluster,
    hostname: str,
    domain: str,
    *,
    max_targets: Optional[int] = None,
    timeout_seconds: int = 20 * 60,
    poll_interval: float = 5.0,
) -> None:
    """Start a watcher that ejects installer ISOs after the first reboot."""

    key = (hostname, domain)
    existing = _watch_tasks.get(key)
    if existing and not existing.done():
        logger.debug("Auto-eject watcher already active for %s on %s", domain, hostname)
        return

    loop = asyncio.get_running_loop()
    task = loop.create_task(
        _auto_eject_worker(
            cluster,
            hostname,
            domain,
            max_targets=max_targets,
            timeout_seconds=timeout_seconds,
            poll_interval=poll_interval,
        )
    )
    _watch_tasks[key] = task

    def _cleanup(_task: asyncio.Task) -> None:
        _watch_tasks.pop(key, None)

    task.add_done_callback(_cleanup)


def shutdown_auto_eject_watchers() -> None:
    """Cancel any scheduled auto-eject watchers (used on app shutdown)."""

    tasks = list(_watch_tasks.values())
    _watch_tasks.clear()
    for task in tasks:
        task.cancel()


async def _auto_eject_worker(
    cluster,
    hostname: str,
    domain: str,
    *,
    max_targets: Optional[int],
    timeout_seconds: int,
    poll_interval: float,
) -> None:
    start = time.monotonic()
    seen_running = False
    logger.info(
        "Auto-eject watcher armed for %s on %s (max_targets=%s)",
        domain,
        hostname,
        max_targets if max_targets is not None else "all",
    )

    detach_targets: list[str] = []

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout_seconds:
            logger.warning(
                "Auto-eject watcher for %s on %s timed out after %.0fs",
                domain,
                hostname,
                elapsed,
            )
            return

        details = await _fetch_domain_details(cluster, hostname, domain)
        if not details:
            await asyncio.sleep(poll_interval)
            continue

        state = str(details.get("state") or "").lower()
        if state in _RUNNING_STATES:
            seen_running = True
        elif seen_running and state in _SHUTOFF_STATES:
            detach_targets = collect_cdrom_targets(details, limit=max_targets)
            if not detach_targets:
                logger.warning(
                    "No CD-ROM targets discovered for %s on %s during auto-eject",
                    domain,
                    hostname,
                )
                return
            break

        await asyncio.sleep(poll_interval)

    logger.info(
        "Installer reboot detected for %s on %s; detaching targets %s",
        domain,
        hostname,
        ",".join(detach_targets),
    )

    for target in detach_targets:
        await _detach_cdrom(cluster, hostname, domain, target)

    logger.info("Auto-eject completed for %s on %s", domain, hostname)


async def _fetch_domain_details(cluster, hostname: str, domain: str) -> dict | None:
    result = await _call_cluster(cluster.get_domain_details, hostname, domain)
    if not isinstance(result, dict):
        return None
    details = result.get("details")
    if isinstance(details, dict):
        return details
    return None


async def _detach_cdrom(cluster, hostname: str, domain: str, target: str) -> None:
    result = await _call_cluster(cluster.detach_guest_block_device, hostname, domain, target)
    if result is None:
        logger.warning("Auto-eject failed for %s on %s target %s", domain, hostname, target)
    else:
        logger.info("Detached %s from %s on %s", target, domain, hostname)


async def _call_cluster(operation, *args, **kwargs):
    try:
        return await run_in_threadpool(lambda: operation(*args, **kwargs))
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning(
            "Cluster operation %s failed for %s@%s: %s",
            getattr(operation, "__name__", str(operation)),
            args[1] if len(args) > 1 else args[0],
            args[0] if args else "?",
            exc,
        )
        return None


__all__ = [
    "collect_cdrom_targets",
    "schedule_iso_auto_eject",
    "shutdown_auto_eject_watchers",
]
