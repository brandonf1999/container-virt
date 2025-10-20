"""Repository helpers for persisting network inventory snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Set

from sqlalchemy import Select, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Host, HostNetworkStatus, HostNetworkStatusState, Network

_STATUS_MAPPING = {
    True: HostNetworkStatusState.ACTIVE,
    False: HostNetworkStatusState.INACTIVE,
}


async def _upsert_network(
    session: AsyncSession,
    *,
    name: str,
    is_shared: bool,
    forward_mode: Any,
    bridge_name: Any,
    vlan_id: Any,
) -> Network:
    stmt: Select[Network] = select(Network).where(
        Network.name == name,
        Network.is_shared.is_(True) if is_shared else Network.is_shared.is_(False),
    )
    network = await session.scalar(stmt)
    if network is None:
        network = Network(
            name=name,
            is_shared=is_shared,
            forward_mode=str(forward_mode) if forward_mode else None,
            bridge_name=str(bridge_name) if bridge_name else None,
            vlan_id=_safe_int(vlan_id),
        )
        session.add(network)
        await session.flush()
    else:
        if network.forward_mode != forward_mode:
            network.forward_mode = str(forward_mode) if forward_mode else None
        if network.bridge_name != bridge_name:
            network.bridge_name = str(bridge_name) if bridge_name else None
        network.vlan_id = _safe_int(vlan_id)
        if network.is_shared != is_shared:
            network.is_shared = is_shared
    return network


async def _upsert_host_network_status(
    session: AsyncSession,
    *,
    host: Host,
    network: Network,
) -> HostNetworkStatus:
    stmt: Select[HostNetworkStatus] = select(HostNetworkStatus).where(
        HostNetworkStatus.host_id == host.id,
        HostNetworkStatus.network_id == network.id,
    )
    status = await session.scalar(stmt)
    if status is None:
        status = HostNetworkStatus(
            host_id=host.id,
            network_id=network.id,
        )
        session.add(status)
        await session.flush()
    return status


async def sync_network_inventory(
    session: AsyncSession,
    *,
    host: Host,
    inventory: Dict[str, Any],
) -> None:
    networks: Iterable[Dict[str, Any]] = inventory.get("networks") or []
    interfaces: Iterable[Dict[str, Any]] = inventory.get("interfaces") or []
    errors: Iterable[str] = inventory.get("errors") or []

    iface_summary = _summarize_interfaces(interfaces)
    last_checked = datetime.now(timezone.utc)

    seen_status_ids: Set[Any] = set()

    for entry in networks:
        name = entry.get("name")
        if not name:
            continue
        forward_mode = entry.get("forward_mode")
        bridge = entry.get("bridge") or {}
        bridge_name = bridge.get("name")
        vlan_info = None
        portgroups = entry.get("portgroups") or []
        if portgroups:
            for pg in portgroups:
                vlan = pg.get("vlan")
                if vlan and "id" in vlan:
                    vlan_info = vlan.get("id")
                    break
        vlan_id = vlan_info or entry.get("vlan")

        is_shared = True  # Default to shared networks for deduplication
        network = await _upsert_network(
            session,
            name=name,
            is_shared=is_shared,
            forward_mode=forward_mode,
            bridge_name=bridge_name,
            vlan_id=vlan_id,
        )

        status = await _upsert_host_network_status(session, host=host, network=network)
        active_flag = bool(entry.get("active"))
        status.status = _STATUS_MAPPING.get(active_flag, HostNetworkStatusState.MISSING)
        status.bridge_active = active_flag
        status.last_checked_at = last_checked
        status.mac_prefix = entry.get("mac_prefix")
        status.message = "; ".join(errors) if errors else None
        status.attributes = {
            "forward_mode": forward_mode,
            "bridge": bridge,
            "ips": entry.get("ips"),
            "dhcp": entry.get("dhcp"),
            "dns": entry.get("dns"),
            "mtu": entry.get("mtu"),
            "interfaces": iface_summary,
        }

        existing_options = dict(network.options or {})
        existing_options.update(
            {
                "forward_dev": entry.get("forward_dev"),
                "portgroups": portgroups,
            }
        )
        network.options = existing_options

        seen_status_ids.add(status.id)

    await _prune_missing_networks(session, host, seen_status_ids)


async def _prune_missing_networks(
    session: AsyncSession,
    host: Host,
    seen_ids: Iterable[Any],
) -> None:
    seen = {sid for sid in seen_ids if sid}
    stmt = delete(HostNetworkStatus).where(HostNetworkStatus.host_id == host.id)
    if seen:
        stmt = stmt.where(HostNetworkStatus.id.notin_(seen))
    await session.execute(stmt)


def _summarize_interfaces(interfaces: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    interfaces = list(interfaces or [])
    return {
        "count": len(interfaces),
        "names": [iface.get("name") for iface in interfaces if iface.get("name")],
    }


def _safe_int(value: Any) -> Any:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["sync_network_inventory"]
