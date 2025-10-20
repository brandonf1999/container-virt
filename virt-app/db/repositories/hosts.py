"""Repository helpers for ensuring cluster and host records exist."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Cluster, Host, HostStatus

DEFAULT_CLUSTER_NAME = "default"


async def ensure_cluster(
    session: AsyncSession,
    *,
    name: str = DEFAULT_CLUSTER_NAME,
    connection_uri: Optional[str] = None,
    description: Optional[str] = None,
) -> Cluster:
    cluster = await session.scalar(select(Cluster).where(Cluster.name == name))
    if cluster is None:
        cluster = Cluster(
            name=name,
            connection_uri=connection_uri or "libvirt",
            description=description,
        )
        session.add(cluster)
        await session.flush()
    else:
        if connection_uri and cluster.connection_uri != connection_uri:
            cluster.connection_uri = connection_uri
        if description and cluster.description != description:
            cluster.description = description
    return cluster


async def ensure_host(
    session: AsyncSession,
    *,
    hostname: str,
    uri: Optional[str],
    user: Optional[str] = None,
    ssh_options: Optional[dict] = None,
    cluster_name: str = DEFAULT_CLUSTER_NAME,
) -> Host:
    cluster = await ensure_cluster(session, name=cluster_name)

    stmt = select(Host).where(
        Host.cluster_id == cluster.id,
        Host.libvirt_id == hostname,
    )
    host = await session.scalar(stmt)
    now = datetime.now(timezone.utc)

    facts = {
        "uri": uri,
        "user": user,
        "ssh_options": ssh_options or {},
    }

    if host is None:
        host = Host(
            cluster_id=cluster.id,
            libvirt_id=hostname,
            name=hostname,
            status=HostStatus.ONLINE,
            facts=facts,
            last_seen=now,
        )
        session.add(host)
        await session.flush()
    else:
        host.name = host.name or hostname
        host.status = HostStatus.ONLINE
        host.last_seen = now
        merged_facts = dict(host.facts or {})
        merged_facts.update({k: v for k, v in facts.items() if v is not None})
        host.facts = merged_facts
    return host


__all__ = ["ensure_cluster", "ensure_host", "DEFAULT_CLUSTER_NAME"]
