"""Repository helpers for persisting storage inventory snapshots."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Set

from sqlalchemy import Select, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    Host,
    HostStorageScope,
    HostStorageStatus,
    HostStorageStatusState,
    StorageDomain,
    StorageDomainType,
)

_SHARED_STORAGE_TYPES = {
    StorageDomainType.NETFS,
    StorageDomainType.ISCSI,
    StorageDomainType.GLUSTER,
    StorageDomainType.RBD,
    StorageDomainType.SHEEPDOG,
}

_STATE_MAPPING = {
    "running": HostStorageStatusState.AVAILABLE,
    "building": HostStorageStatusState.DEGRADED,
    "degraded": HostStorageStatusState.DEGRADED,
    "inactive": HostStorageStatusState.MISSING,
    "inaccessible": HostStorageStatusState.MISSING,
}

_TYPE_LOOKUP = {
    "dir": StorageDomainType.DIR,
    "fs": StorageDomainType.FS,
    "netfs": StorageDomainType.NETFS,
    "logical": StorageDomainType.LOGICAL,
    "iscsi": StorageDomainType.ISCSI,
    "gluster": StorageDomainType.GLUSTER,
    "rbd": StorageDomainType.RBD,
    "sheepdog": StorageDomainType.SHEEPDOG,
    "zfs": StorageDomainType.ZFS,
}


def _coerce_domain_type(value: Any) -> StorageDomainType:
    if not value:
        return StorageDomainType.UNKNOWN
    key = str(value).strip().lower()
    return _TYPE_LOOKUP.get(key, StorageDomainType.UNKNOWN)


def _derive_status(state: Any) -> HostStorageStatusState:
    if not state:
        return HostStorageStatusState.MISSING
    key = str(state).strip().lower()
    return _STATE_MAPPING.get(key, HostStorageStatusState.DEGRADED)


async def _upsert_storage_domain(
    session: AsyncSession,
    *,
    name: str,
    domain_type: StorageDomainType,
    is_shared: bool,
    host: Host,
) -> StorageDomain:
    if is_shared:
        stmt: Select[StorageDomain] = select(StorageDomain).where(
            StorageDomain.name == name,
            StorageDomain.type == domain_type,
            StorageDomain.is_shared.is_(True),
        )
    else:
        stmt = select(StorageDomain).where(
            StorageDomain.name == name,
            StorageDomain.type == domain_type,
            StorageDomain.is_shared.is_(False),
            StorageDomain.source_host == host.libvirt_id,
        )
    storage_domain = await session.scalar(stmt)
    if storage_domain is None:
        storage_domain = StorageDomain(
            name=name,
            type=domain_type,
            is_shared=is_shared,
            source_host=host.libvirt_id if not is_shared else host.libvirt_id,
        )
        session.add(storage_domain)
        await session.flush()
    else:
        if storage_domain.is_shared != is_shared:
            storage_domain.is_shared = is_shared
        if not is_shared and storage_domain.source_host != host.libvirt_id:
            storage_domain.source_host = host.libvirt_id
    return storage_domain


async def _upsert_host_storage_status(
    session: AsyncSession,
    *,
    host: Host,
    storage_domain: StorageDomain,
) -> HostStorageStatus:
    stmt: Select[HostStorageStatus] = select(HostStorageStatus).where(
        HostStorageStatus.host_id == host.id,
        HostStorageStatus.storage_domain_id == storage_domain.id,
    )
    status = await session.scalar(stmt)
    if status is None:
        status = HostStorageStatus(
            host_id=host.id,
            storage_domain_id=storage_domain.id,
            scope=HostStorageScope.SHARED if storage_domain.is_shared else HostStorageScope.LOCAL,
            status=HostStorageStatusState.MISSING,
        )
        session.add(status)
        await session.flush()
    return status


async def sync_storage_inventory(
    session: AsyncSession,
    *,
    host: Host,
    inventory: Dict[str, Any],
) -> None:
    pools: Iterable[Dict[str, Any]] = inventory.get("pools") or []
    volumes: Iterable[Dict[str, Any]] = inventory.get("volumes") or []
    errors: Iterable[str] = inventory.get("errors") or []

    last_checked = datetime.now(timezone.utc)
    volume_counts: Dict[str, int] = defaultdict(int)
    for volume in volumes:
        pool_name = volume.get("pool")
        if pool_name:
            volume_counts[str(pool_name)] += 1

    seen_status_ids: Set[Any] = set()

    for pool in pools:
        name = str(pool.get("name")) if pool.get("name") else None
        if not name:
            continue
        domain_type = _coerce_domain_type(pool.get("type"))
        is_shared = domain_type in _SHARED_STORAGE_TYPES
        storage_domain = await _upsert_storage_domain(
            session,
            name=name,
            domain_type=domain_type,
            is_shared=is_shared,
            host=host,
        )

        status = await _upsert_host_storage_status(
            session,
            host=host,
            storage_domain=storage_domain,
        )

        status.scope = HostStorageScope.SHARED if storage_domain.is_shared else HostStorageScope.LOCAL
        status.status = _derive_status(pool.get("state"))
        status.capacity_bytes = _safe_int(pool.get("capacity_bytes"))
        status.allocation_bytes = _safe_int(pool.get("allocation_bytes"))
        status.available_bytes = _safe_int(pool.get("available_bytes"))
        status.last_checked_at = last_checked
        status.message = "; ".join(errors) if errors else None
        status.attributes = {
            "autostart": pool.get("autostart"),
            "persistent": pool.get("persistent"),
            "state": pool.get("state"),
            "type": pool.get("type"),
            "volume_count": volume_counts.get(name, 0),
        }

        storage_domain.description = storage_domain.description or pool.get("description")
        storage_domain.source_path = storage_domain.source_path or pool.get("path")
        storage_domain.source_host = storage_domain.source_host or host.libvirt_id
        existing_options = dict(storage_domain.options or {})
        existing_options.update(
            {
                "autostart": pool.get("autostart"),
                "persistent": pool.get("persistent"),
                "state": pool.get("state"),
            }
        )
        storage_domain.options = existing_options

        seen_status_ids.add(status.id)

    await _prune_missing_storage_status(session, host, seen_status_ids)


async def _prune_missing_storage_status(
    session: AsyncSession,
    host: Host,
    seen_ids: Iterable[Any],
) -> None:
    seen = {sid for sid in seen_ids if sid}
    stmt = delete(HostStorageStatus).where(HostStorageStatus.host_id == host.id)
    if seen:
        stmt = stmt.where(HostStorageStatus.id.notin_(seen))
    await session.execute(stmt)


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["sync_storage_inventory"]
