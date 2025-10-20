"""Bootstrap helpers that populate required database records on startup."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import select

from app.core.config import LIBVIRT_HOSTS

from .models import Host, HostStatus
from .repositories.hosts import DEFAULT_CLUSTER_NAME, ensure_cluster, ensure_host
from .session import get_async_session_factory

logger = logging.getLogger(__name__)


async def _seed_default_cluster() -> None:
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        cluster = await ensure_cluster(session, name=DEFAULT_CLUSTER_NAME)

        hosts_config: list[dict[str, Any]] = []
        if isinstance(LIBVIRT_HOSTS, list):
            hosts_config = [entry for entry in LIBVIRT_HOSTS if isinstance(entry, dict)]

        created_hosts = 0
        for entry in hosts_config:
            hostname = entry.get("hostname")
            if not hostname:
                continue

            existing = await session.scalar(
                select(Host).where(
                    Host.cluster_id == cluster.id,
                    Host.libvirt_id == hostname,
                )
            )
            if existing:
                continue

            user = entry.get("user")
            ssh_options = entry.get("ssh") if isinstance(entry.get("ssh"), dict) else None
            uri = entry.get("uri")

            host = await ensure_host(
                session,
                hostname=hostname,
                uri=uri,
                user=user,
                ssh_options=ssh_options,
                cluster_name=DEFAULT_CLUSTER_NAME,
            )
            host.status = HostStatus.OFFLINE
            host.last_seen = None
            created_hosts += 1

        if created_hosts:
            await session.commit()
            logger.info("Bootstrap created %s host records", created_hosts)
        else:
            await session.commit()
            logger.info("Bootstrap found existing host records; no changes applied")


def main() -> None:
    try:
        asyncio.run(_seed_default_cluster())
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Bootstrap failed: %s", exc)
        raise


if __name__ == "__main__":
    main()

