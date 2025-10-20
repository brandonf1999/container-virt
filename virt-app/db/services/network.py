"""Query helpers for aggregated network views."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Host, HostNetworkStatus, HostNetworkStatusState, Network


async def list_networks(session: AsyncSession) -> List[Dict[str, Any]]:
    stmt = (
        select(
            Network.id,
            Network.name,
            Network.forward_mode,
            Network.bridge_name,
            Network.vlan_id,
            Network.is_shared,
            Network.description,
            Network.options,
        )
        .order_by(Network.name)
    )
    rows = (await session.execute(stmt)).all()

    network_map: Dict[Any, Dict[str, Any]] = {}
    for row in rows:
        network_map[row.id] = {
            "id": str(row.id),
            "name": row.name,
            "forward_mode": row.forward_mode,
            "bridge_name": row.bridge_name,
            "vlan_id": row.vlan_id,
            "is_shared": row.is_shared,
            "description": row.description,
            "options": row.options or {},
            "hosts": [],
        }

    if not network_map:
        return []

    status_stmt = (
        select(
            HostNetworkStatus.network_id,
            HostNetworkStatus.status,
            HostNetworkStatus.bridge_active,
            HostNetworkStatus.last_checked_at,
            HostNetworkStatus.mac_prefix,
            HostNetworkStatus.message,
            HostNetworkStatus.attributes,
            Host.libvirt_id,
            Host.name,
        )
        .join(Host, HostNetworkStatus.host_id == Host.id)
        .where(HostNetworkStatus.network_id.in_(network_map.keys()))
        .order_by(Host.name)
    )
    status_rows = (await session.execute(status_stmt)).all()

    for row in status_rows:
        entry = network_map.get(row.network_id)
        if not entry:
            continue
        status_val = (
            row.status.value if isinstance(row.status, HostNetworkStatusState) else str(row.status)
        )
        status_val = status_val.lower()
        entry["hosts"].append(
            {
                "hostname": row.libvirt_id,
                "display_name": row.name or row.libvirt_id,
                "status": status_val,
                "bridge_active": row.bridge_active,
                "last_checked_at": row.last_checked_at,
                "mac_prefix": row.mac_prefix,
                "message": row.message,
                "attributes": row.attributes or {},
            }
        )

    networks: List[Dict[str, Any]] = []
    for network_id, network in network_map.items():
        hosts = network["hosts"]
        hosts.sort(key=lambda item: item.get("display_name") or item.get("hostname"))

        status_counter: Counter[str] = Counter()
        for host_entry in hosts:
            status = host_entry.get("status")
            if status:
                status_counter[status] += 1

        total_hosts = len(hosts)
        active_count = status_counter.get("active", 0)
        if total_hosts == 0:
            derived_state = "missing"
        elif active_count == total_hosts:
            derived_state = "active"
        elif active_count == 0:
            derived_state = "inactive"
        else:
            derived_state = "degraded"

        attention_hosts = [
            {
                "hostname": host_entry.get("hostname"),
                "display_name": host_entry.get("display_name"),
                "status": host_entry.get("status"),
                "message": host_entry.get("message"),
                "attributes": host_entry.get("attributes") or {},
            }
            for host_entry in hosts
            if (host_entry.get("status") or "").lower() != "active"
        ]

        network["summary"] = {
            "host_count": total_hosts,
            "status_counts": dict(status_counter),
            "state": derived_state,
            "attention_hosts": attention_hosts,
        }

        networks.append(network)

    return networks


async def get_network(session: AsyncSession, network_id: Any) -> Dict[str, Any] | None:
    network_stmt = select(Network).where(Network.id == network_id)
    network = await session.scalar(network_stmt)
    if network is None:
        return None

    record: Dict[str, Any] = {
        "id": str(network.id),
        "name": network.name,
        "forward_mode": network.forward_mode,
        "bridge_name": network.bridge_name,
        "vlan_id": network.vlan_id,
        "is_shared": network.is_shared,
        "description": network.description,
        "options": network.options or {},
        "hosts": [],
    }

    status_stmt = (
        select(
            HostNetworkStatus.status,
            HostNetworkStatus.bridge_active,
            HostNetworkStatus.last_checked_at,
            HostNetworkStatus.mac_prefix,
            HostNetworkStatus.message,
            HostNetworkStatus.attributes,
            Host.libvirt_id,
            Host.name,
        )
        .join(Host, HostNetworkStatus.host_id == Host.id)
        .where(HostNetworkStatus.network_id == network_id)
        .order_by(Host.name)
    )
    status_rows = (await session.execute(status_stmt)).all()

    status_counter: Counter[str] = Counter()
    for row in status_rows:
        status_val = (
            row.status.value if isinstance(row.status, HostNetworkStatusState) else str(row.status)
        )
        status_val = status_val.lower()
        record["hosts"].append(
            {
                "hostname": row.libvirt_id,
                "display_name": row.name or row.libvirt_id,
                "status": status_val,
                "bridge_active": row.bridge_active,
                "last_checked_at": row.last_checked_at,
                "mac_prefix": row.mac_prefix,
                "message": row.message,
                "attributes": row.attributes or {},
            }
        )
        status_counter[status_val] += 1

    record["hosts"].sort(key=lambda item: item.get("display_name") or item.get("hostname"))

    total_hosts = len(record["hosts"])
    active_count = status_counter.get("active", 0)
    if total_hosts == 0:
        derived_state = "missing"
    elif active_count == total_hosts:
        derived_state = "active"
    elif active_count == 0:
        derived_state = "inactive"
    else:
        derived_state = "degraded"

    attention_hosts = [
        {
            "hostname": host_entry.get("hostname"),
            "display_name": host_entry.get("display_name"),
            "status": host_entry.get("status"),
            "message": host_entry.get("message"),
            "attributes": host_entry.get("attributes") or {},
        }
        for host_entry in record["hosts"]
        if (host_entry.get("status") or "").lower() != "active"
    ]

    record["summary"] = {
        "host_count": total_hosts,
        "status_counts": dict(status_counter),
        "state": derived_state,
        "attention_hosts": attention_hosts,
    }

    return record


__all__ = ["list_networks", "get_network"]
