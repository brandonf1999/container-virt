"""Query helpers for aggregated storage domain views."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Host, HostStorageScope, HostStorageStatus, HostStorageStatusState, StorageDomain, StorageDomainType


def _derive_domain_status(status_counts: Counter[str]) -> str:
    """Summarise a domain's overall health from individual host states."""

    if not status_counts:
        return "unknown"

    priority = (
        HostStorageStatusState.MISSING.value,
        HostStorageStatusState.DEGRADED.value,
        HostStorageStatusState.AVAILABLE.value,
    )

    for state in priority:
        if status_counts.get(state):
            return state

    for state, count in status_counts.items():
        if count:
            return state

    return "unknown"


async def list_storage_domains(session: AsyncSession) -> List[Dict[str, Any]]:
    stmt = (
        select(
            StorageDomain.id,
            StorageDomain.name,
            StorageDomain.type,
            StorageDomain.is_shared,
            StorageDomain.description,
            StorageDomain.source_host,
            StorageDomain.source_path,
            StorageDomain.options,
        )
        .order_by(StorageDomain.name)
    )
    rows = (await session.execute(stmt)).all()

    domain_map: Dict[Any, Dict[str, Any]] = {}
    status_trackers: Dict[Any, Counter[str]] = {}
    last_checked_map: Dict[Any, Optional[Any]] = {}
    for row in rows:
        domain_map[row.id] = {
            "id": str(row.id),
            "name": row.name,
            "type": row.type.value if isinstance(row.type, StorageDomainType) else row.type,
            "is_shared": row.is_shared,
            "description": row.description,
            "source_host": row.source_host,
            "source_path": row.source_path,
            "options": row.options or {},
            "hosts": [],
            "status": "unknown",
            "summary": {
                "host_count": 0,
                "status_counts": {},
                "last_checked_at": None,
            },
        }
        status_trackers[row.id] = Counter()
        last_checked_map[row.id] = None

    if not domain_map:
        return []

    status_stmt = (
        select(
            HostStorageStatus.storage_domain_id,
            HostStorageStatus.scope,
            HostStorageStatus.status,
            HostStorageStatus.capacity_bytes,
            HostStorageStatus.allocation_bytes,
            HostStorageStatus.available_bytes,
            HostStorageStatus.last_checked_at,
            HostStorageStatus.message,
            HostStorageStatus.attributes,
            Host.libvirt_id,
            Host.name,
        )
        .join(Host, HostStorageStatus.host_id == Host.id)
        .where(HostStorageStatus.storage_domain_id.in_(domain_map.keys()))
        .order_by(Host.name)
    )
    status_rows = (await session.execute(status_stmt)).all()

    for row in status_rows:
        entry = domain_map.get(row.storage_domain_id)
        if not entry:
            continue
        status_value = row.status.value if hasattr(row.status, "value") else str(row.status)
        entry["hosts"].append(
            {
                "hostname": row.libvirt_id,
                "display_name": row.name or row.libvirt_id,
                "scope": row.scope.value if hasattr(row.scope, "value") else str(row.scope),
                "status": status_value,
                "capacity_bytes": row.capacity_bytes,
                "allocation_bytes": row.allocation_bytes,
                "available_bytes": row.available_bytes,
                "last_checked_at": row.last_checked_at,
                "message": row.message,
                "attributes": row.attributes or {},
            }
        )
        status_trackers[row.storage_domain_id][status_value] += 1
        existing_last = last_checked_map[row.storage_domain_id]
        if row.last_checked_at and (existing_last is None or row.last_checked_at > existing_last):
            last_checked_map[row.storage_domain_id] = row.last_checked_at

    domains: List[Dict[str, Any]] = []
    for domain_id, entry in domain_map.items():
        hosts = entry["hosts"]
        hosts.sort(key=lambda item: item.get("display_name") or item.get("hostname"))
        status_counts = dict(status_trackers.get(domain_id, Counter()))
        entry["summary"] = {
            "host_count": len(hosts),
            "status_counts": status_counts,
            "last_checked_at": last_checked_map.get(domain_id),
        }
        entry["status"] = _derive_domain_status(status_trackers.get(domain_id, Counter()))
        domains.append(entry)
    return domains


async def get_storage_domain(session: AsyncSession, storage_id: UUID) -> Optional[Dict[str, Any]]:
    domain = await session.scalar(
        select(StorageDomain).where(StorageDomain.id == storage_id)
    )
    if domain is None:
        return None

    record: Dict[str, Any] = {
        "id": str(domain.id),
        "name": domain.name,
        "type": domain.type.value if isinstance(domain.type, StorageDomainType) else domain.type,
        "is_shared": domain.is_shared,
        "description": domain.description,
        "source_host": domain.source_host,
        "source_path": domain.source_path,
        "options": domain.options or {},
        "hosts": [],
        "status": "unknown",
    }

    status_stmt = (
        select(
            HostStorageStatus.scope,
            HostStorageStatus.status,
            HostStorageStatus.capacity_bytes,
            HostStorageStatus.allocation_bytes,
            HostStorageStatus.available_bytes,
            HostStorageStatus.last_checked_at,
            HostStorageStatus.message,
            HostStorageStatus.attributes,
            Host.libvirt_id,
            Host.name,
        )
        .join(Host, HostStorageStatus.host_id == Host.id)
        .where(HostStorageStatus.storage_domain_id == storage_id)
        .order_by(Host.name)
    )
    status_rows = (await session.execute(status_stmt)).all()

    last_checked = None
    status_counter: Counter[str] = Counter()

    for row in status_rows:
        status_value = row.status.value if hasattr(row.status, "value") else str(row.status)
        scope_value = row.scope.value if hasattr(row.scope, "value") else str(row.scope)
        entry = {
            "hostname": row.libvirt_id,
            "display_name": row.name or row.libvirt_id,
            "scope": scope_value,
            "status": status_value,
            "capacity_bytes": row.capacity_bytes,
            "allocation_bytes": row.allocation_bytes,
            "available_bytes": row.available_bytes,
            "last_checked_at": row.last_checked_at,
            "message": row.message,
            "attributes": row.attributes or {},
        }
        record["hosts"].append(entry)
        status_counter[status_value] += 1
        if row.last_checked_at and (last_checked is None or row.last_checked_at > last_checked):
            last_checked = row.last_checked_at

    record["hosts"].sort(key=lambda item: item.get("display_name") or item.get("hostname"))
    record["summary"] = {
        "host_count": len(record["hosts"]),
        "status_counts": dict(status_counter),
        "last_checked_at": last_checked,
    }
    record["status"] = _derive_domain_status(status_counter)

    return record


__all__ = ["list_storage_domains", "get_storage_domain"]
