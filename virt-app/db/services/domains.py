"""Query helpers for presenting VM/domain inventory out of the database."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Domain, DomainState, Host

_RUNNING_STATES = {DomainState.RUNNING.value, DomainState.BLOCKED.value}
_FAILED_STATES = {DomainState.CRASHED.value}
_STOPPED_STATES = {
    DomainState.SHUTDOWN.value,
    DomainState.SHUTOFF.value,
    DomainState.PAUSED.value,
    DomainState.PMSUSPENDED.value,
    DomainState.SUSPENDED.value,
    DomainState.UNKNOWN.value,
}


def _classify_for_summary(state: str) -> str:
    if state in _RUNNING_STATES:
        return "online"
    if state in _FAILED_STATES:
        return "failed"
    return "stopped"


def _extract_metrics(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    metrics = {}
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


def _extract_ips(payload: Any) -> Iterable[str]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, tuple):
        return list(payload)
    return []


async def list_domains_by_host(session: AsyncSession) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, int]]:
    hosts_stmt = select(Host).order_by(Host.libvirt_id)
    hosts = (await session.execute(hosts_stmt)).scalars().all()

    inventory: Dict[str, Dict[str, Any]] = {}
    for host in hosts:
        errors = host.facts.get("domain_errors") if isinstance(host.facts, dict) else None
        error_list = []
        if isinstance(errors, list):
            error_list = [str(entry) for entry in errors if entry]
        inventory[host.libvirt_id] = {
            "vms": [],
            "errors": error_list or None,
        }

    if not hosts:
        return {}, {"online": 0, "stopped": 0, "failed": 0, "total": 0}

    host_ids = [host.id for host in hosts]
    domains_stmt = (
        select(
            Domain,
            Host.libvirt_id,
        )
        .join(Host, Domain.host_id == Host.id)
        .where(Domain.host_id.in_(host_ids))
        .order_by(Host.libvirt_id, Domain.name)
    )
    rows = await session.execute(domains_stmt)

    counts = defaultdict(int)

    for domain, hostname in rows.all():
        state = domain.state.value if isinstance(domain.state, DomainState) else str(domain.state)
        metrics = _extract_metrics(domain.metrics)
        ips = [str(ip) for ip in _extract_ips(domain.guest_agent_ips)]
        vm_entry = {
            "name": domain.name,
            "state": state,
            "state_code": domain.state_code,
            "persistent": domain.persistent,
            "metrics": metrics or None,
            "guest_agent_ips": ips or None,
        }
        host_entry = inventory.get(hostname)
        if host_entry is None:
            host_entry = {"vms": [], "errors": None}
            inventory[hostname] = host_entry
        host_entry["vms"].append(vm_entry)

        bucket = _classify_for_summary(state)
        counts[bucket] += 1
        counts["total"] += 1

    for entry in inventory.values():
        entry["vms"].sort(key=lambda vm: vm.get("name") or "")
        if entry["errors"] is None:
            entry.pop("errors", None)

    summary = {
        "online": counts.get("online", 0),
        "stopped": counts.get("stopped", 0),
        "failed": counts.get("failed", 0),
        "total": counts.get("total", 0),
    }
    return inventory, summary
