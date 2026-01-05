"""Repository helpers for synchronising libvirt domain inventory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Sequence
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Domain, DomainState, Host

_STATE_LOOKUP = {
    "running": DomainState.RUNNING,
    "blocked": DomainState.BLOCKED,
    "paused": DomainState.PAUSED,
    "shutdown": DomainState.SHUTDOWN,
    "shutoff": DomainState.SHUTOFF,
    "crashed": DomainState.CRASHED,
    "pmsuspended": DomainState.PMSUSPENDED,
    "suspended": DomainState.SUSPENDED,
}


def _coerce_state(value: Any) -> DomainState:
    if not value:
        return DomainState.UNKNOWN
    key = str(value).strip().lower()
    return _STATE_LOOKUP.get(key, DomainState.UNKNOWN)


def _coerce_uuid(value: Any) -> Optional[UUID]:
    if not value:
        return None
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _normalise_metrics(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    metrics: Dict[str, Any] = {}
    for key in (
        "vcpu_count",
        "memory_mb",
        "max_memory_mb",
        "total_memory_mb",
        "used_memory_mb",
        "cpu_time_seconds",
        "uptime_seconds",
    ):
        if key in payload:
            metrics[key] = payload[key]
    return metrics


def _normalise_ips(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        candidate = values.strip()
        return [candidate] if candidate else []
    if not isinstance(values, Iterable):
        return []
    ips: list[str] = []
    for value in values:
        if not value:
            continue
        text = str(value).strip()
        if text:
            ips.append(text)
    return ips


def _apply_payload_to_domain(domain: Domain, payload: Dict[str, Any], now: datetime) -> None:
    domain.state = _coerce_state(payload.get("state"))
    state_code = payload.get("state_code")
    domain.state_code = int(state_code) if isinstance(state_code, int) else None
    persistent = payload.get("persistent")
    if isinstance(persistent, bool):
        domain.persistent = persistent
    else:
        domain.persistent = None

    metrics = _normalise_metrics(payload.get("metrics"))
    domain.metrics = metrics
    domain.vcpu_count = (
        int(metrics["vcpu_count"]) if "vcpu_count" in metrics and metrics["vcpu_count"] is not None else None
    )
    memory_mb = metrics.get("memory_mb")
    domain.memory_mb = int(memory_mb) if isinstance(memory_mb, (int, float)) else None
    domain.guest_agent_ips = _normalise_ips(payload.get("guest_agent_ips"))
    domain.last_seen = now


async def sync_domain_inventory(
    session: AsyncSession,
    *,
    host: Host,
    inventory: Dict[str, Any],
) -> None:
    domains: Iterable[Dict[str, Any]] = inventory.get("vms") or []
    errors: Iterable[Any] = inventory.get("errors") or []
    now = datetime.now(timezone.utc)

    existing = (
        await session.execute(select(Domain).where(Domain.host_id == host.id))
    ).scalars()
    by_uuid: Dict[UUID, Domain] = {}
    by_name: Dict[str, Domain] = {}
    for domain in existing:
        by_uuid[domain.uuid] = domain
        by_name[domain.name] = domain

    seen_ids: set[UUID] = set()

    for payload in domains:
        if not isinstance(payload, dict):
            continue
        name = payload.get("name")
        uuid_value = _coerce_uuid(payload.get("uuid"))
        if not uuid_value:
            # Without a stable UUID we cannot reconcile records safely.
            continue
        if not name:
            name = str(uuid_value)

        domain = by_uuid.get(uuid_value) or by_name.get(str(name))
        if domain is None:
            domain = Domain(host_id=host.id, uuid=uuid_value, name=str(name))
            session.add(domain)
            await session.flush()
            by_uuid[uuid_value] = domain
        else:
            if domain.uuid != uuid_value:
                domain.uuid = uuid_value
            domain.name = str(name)
        by_name[str(name)] = domain

        _apply_payload_to_domain(domain, payload, now)

        seen_ids.add(domain.id)

    if seen_ids:
        await session.execute(
            delete(Domain).where(
                Domain.host_id == host.id,
                ~Domain.id.in_(seen_ids),
            )
        )
    else:
        await session.execute(delete(Domain).where(Domain.host_id == host.id))

    facts = dict(host.facts or {})
    sanitised_errors = []
    for value in errors:
        if not value:
            continue
        text = str(value).strip()
        if text:
            sanitised_errors.append(text)
    facts["domain_errors"] = sanitised_errors
    host.facts = facts
    host.last_seen = now


async def list_domain_uuids_for_host(
    session: AsyncSession,
    *,
    host: Host,
) -> set[str]:
    """Return the UUIDs of domains tracked for the given host."""

    stmt = select(Domain.uuid).where(Domain.host_id == host.id)
    uuids: Sequence[UUID] = (await session.scalars(stmt)).all()
    return {str(value) for value in uuids if value}


async def adopt_domain_from_inventory(
    session: AsyncSession,
    *,
    host: Host,
    payload: Dict[str, Any],
) -> Domain:
    """Create or update a domain record using a libvirt inventory payload."""

    uuid_value = _coerce_uuid(payload.get("uuid"))
    if uuid_value is None:
        raise ValueError("VM payload missing a valid UUID")
    name = payload.get("name") or str(uuid_value)

    stmt = select(Domain).where(Domain.host_id == host.id, Domain.uuid == uuid_value)
    domain = await session.scalar(stmt)
    now = datetime.now(timezone.utc)

    if domain is None:
        domain = Domain(host_id=host.id, uuid=uuid_value, name=str(name))
        session.add(domain)
    else:
        domain.name = str(name)

    _apply_payload_to_domain(domain, payload, now)
    host.last_seen = now
    await session.flush()
    return domain


__all__ = [
    "sync_domain_inventory",
    "list_domain_uuids_for_host",
    "adopt_domain_from_inventory",
]
