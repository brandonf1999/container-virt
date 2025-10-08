import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import libvirt

logger = logging.getLogger(__name__)

_STATE_LABELS = {
    getattr(libvirt, "VIR_STORAGE_POOL_INACTIVE", None): "inactive",
    getattr(libvirt, "VIR_STORAGE_POOL_BUILDING", None): "building",
    getattr(libvirt, "VIR_STORAGE_POOL_RUNNING", None): "running",
    getattr(libvirt, "VIR_STORAGE_POOL_DEGRADED", None): "degraded",
    getattr(libvirt, "VIR_STORAGE_POOL_INACCESSIBLE", None): "inaccessible",
}


def _map_state(state_code: int) -> str:
    return _STATE_LABELS.get(state_code, f"state:{state_code}")


def _detect_pool_type(pool: libvirt.virStoragePool) -> Optional[str]:
    try:
        xml_desc = pool.XMLDesc(0)
    except libvirt.libvirtError as exc:
        logger.debug("XMLDesc failed for pool %s: %s", pool.name(), exc)
        return None

    try:
        root = ET.fromstring(xml_desc)
    except ET.ParseError as exc:
        logger.debug("Failed to parse storage pool XML for %s: %s", pool.name(), exc)
        return None

    return root.attrib.get("type")


_VOLUME_TYPE_LABELS = {
    getattr(libvirt, "VIR_STORAGE_VOL_FILE", None): "file",
    getattr(libvirt, "VIR_STORAGE_VOL_BLOCK", None): "block",
    getattr(libvirt, "VIR_STORAGE_VOL_DIR", None): "directory",
    getattr(libvirt, "VIR_STORAGE_VOL_NETWORK", None): "network",
    getattr(libvirt, "VIR_STORAGE_VOL_NETDIR", None): "network-dir",
    getattr(libvirt, "VIR_STORAGE_VOL_PLOOP", None): "ploop",
}


def _map_volume_type(kind: int) -> str:
    return _VOLUME_TYPE_LABELS.get(kind, f"type:{kind}")


def _collect_attached_volume_identifiers(conn: libvirt.virConnect) -> Set[str]:
    identifiers: Set[str] = set()

    try:
        domain_ids = conn.listDomainsID()
    except libvirt.libvirtError as exc:
        logger.debug("listDomainsID failed when collecting volume usage: %s", exc)
        domain_ids = []

    for dom_id in domain_ids or []:
        try:
            domain = conn.lookupByID(dom_id)
        except libvirt.libvirtError as exc:
            logger.debug("lookupByID(%s) failed when collecting volume usage: %s", dom_id, exc)
            continue

        domain_name = domain.name()
        try:
            xml_desc = domain.XMLDesc(0)
        except libvirt.libvirtError as exc:
            logger.debug("XMLDesc failed for domain %s when collecting volume usage: %s", domain_name, exc)
            continue

        try:
            root = ET.fromstring(xml_desc)
        except ET.ParseError as exc:
            logger.debug("Failed to parse domain XML for %s when collecting volume usage: %s", domain_name, exc)
            continue

        for disk in root.findall("./devices/disk"):
            source = disk.find("source")
            if source is None:
                continue
            for attr_val in source.attrib.values():
                if attr_val:
                    identifiers.add(attr_val)
            pool = source.attrib.get("pool")
            volume = source.attrib.get("volume") or source.attrib.get("name")
            if pool and volume:
                identifiers.add(f"{pool}/{volume}")

    return identifiers


def _derive_volume_state(
    allocation: Optional[int],
    capacity: Optional[int],
    *,
    attached: bool = False,
    context: Optional[str] = None,
) -> str:
    if allocation is None:
        return "unknown"
    if allocation < 0:
        if context:
            logger.warning(
                "Volume %s flagged as error: negative allocation (%s)",
                context,
                allocation,
            )
        return "error"
    if capacity is None:
        if allocation == 0:
            return "available"
        return "in-use" if attached else "available"

    if capacity < 0:
        if context:
            logger.warning(
                "Volume %s flagged as error: negative capacity (%s)",
                context,
                capacity,
            )
        return "error"

    if allocation == 0:
        return "available"

    # Allow minor rounding differences before flagging overflow (0.25 MiB)
    overflow_tolerance = 256 * 1024
    if allocation > capacity + overflow_tolerance:
        if context:
            logger.warning(
                "Volume %s flagged as error: allocation (%s) exceeds capacity (%s) with tolerance %s",
                context,
                allocation,
                capacity,
                overflow_tolerance,
            )
        return "error"

    if attached:
        return "in-use"

    return "available"


def _collect_storage_pool_objects(conn: libvirt.virConnect) -> Dict[str, "libvirt.virStoragePool"]:
    pools: Dict[str, libvirt.virStoragePool] = {}

    list_flags = 0
    for attr in (
        "VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE",
        "VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE",
        "VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART",
        "VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT",
    ):
        flag = getattr(libvirt, attr, None)
        if flag is not None:
            list_flags |= flag

    def _list_all() -> Iterable[libvirt.virStoragePool]:
        list_all = getattr(conn, "listAllStoragePools", None)
        if callable(list_all):
            try:
                return list_all(list_flags) or []
            except libvirt.libvirtError as exc:
                logger.debug("listAllStoragePools failed: %s", exc)
        return []

    for pool in _list_all():
        pools[pool.name()] = pool

    try:
        for name in conn.listStoragePools():
            if name not in pools:
                pools[name] = conn.storagePoolLookupByName(name)
    except libvirt.libvirtError as exc:
        logger.debug("listStoragePools failed: %s", exc)

    try:
        for name in conn.listDefinedStoragePools():
            if name not in pools:
                pools[name] = conn.storagePoolLookupByName(name)
    except libvirt.libvirtError:
        pass

    return pools


def _collect_pool_volumes(pool: libvirt.virStoragePool) -> Tuple[List[Dict[str, Any]], List[str]]:
    volumes: Dict[str, libvirt.virStorageVol] = {}
    errors: List[str] = []

    def _list_all() -> Iterable[libvirt.virStorageVol]:
        list_all = getattr(pool, "listAllVolumes", None)
        if callable(list_all):
            try:
                return list_all(0) or []
            except libvirt.libvirtError as exc:
                logger.debug("listAllVolumes failed for pool %s: %s", pool.name(), exc)
        return []

    for vol in _list_all():
        volumes[vol.name()] = vol

    if not volumes:
        try:
            for name in pool.listVolumes():
                if name in volumes:
                    continue
                try:
                    volumes[name] = pool.storageVolLookupByName(name)
                except libvirt.libvirtError as exc:
                    logger.debug("storageVolLookupByName(%s) failed: %s", name, exc)
                    errors.append(f"{pool.name()}::{name}: {exc}")
        except libvirt.libvirtError as exc:
            logger.debug("listVolumes failed for pool %s: %s", pool.name(), exc)

    details: List[Dict[str, Any]] = []
    for name, vol in volumes.items():
        try:
            info = vol.info()
            vol_entry: Dict[str, Any] = {
                "name": name,
                "type": _map_volume_type(int(info[0]) if isinstance(info[0], (int, float)) else info[0]),
                "capacity_bytes": int(info[1]) if len(info) > 1 else None,
                "allocation_bytes": int(info[2]) if len(info) > 2 else None,
            }
            try:
                vol_entry["key"] = vol.key()
            except libvirt.libvirtError:
                vol_entry["key"] = None
            try:
                vol_entry["path"] = vol.path()
            except libvirt.libvirtError:
                vol_entry["path"] = None
            capacity = vol_entry.get("capacity_bytes")
            allocation = vol_entry.get("allocation_bytes")
            if capacity is not None and allocation is not None:
                vol_entry["available_bytes"] = max(capacity - allocation, 0)
            else:
                vol_entry["available_bytes"] = None
            details.append(vol_entry)
        except libvirt.libvirtError as exc:
            logger.debug("Failed to inspect storage volume %s: %s", name, exc)
            errors.append(f"{pool.name()}::{name}: {exc}")

    details.sort(key=lambda entry: entry.get("name") or "")
    return details, errors


def gather_host_storage_inventory(conn: libvirt.virConnect) -> Dict[str, Any]:
    pools: List[Dict[str, Any]] = []
    volumes: List[Dict[str, Any]] = []
    errors: List[str] = []
    attached_identifiers = _collect_attached_volume_identifiers(conn)

    for name, pool in _collect_storage_pool_objects(conn).items():
        try:
            try:
                pool.refresh(0)
            except libvirt.libvirtError as exc:
                logger.debug("refresh(%s) failed: %s", name, exc)
            state, capacity, allocation, available = pool.info()
            pool_type = _detect_pool_type(pool)
            pool_entry: Dict[str, Any] = {
                "name": name,
                "state": _map_state(state),
                "persistent": bool(pool.isPersistent()) if hasattr(pool, "isPersistent") else None,
                "autostart": bool(pool.autostart()) if hasattr(pool, "autostart") else None,
                "capacity_bytes": int(capacity),
                "allocation_bytes": int(allocation),
                "available_bytes": int(available),
                "type": pool_type,
            }

            pool_volumes, volume_errors = _collect_pool_volumes(pool)
            if pool_volumes:
                for vol in pool_volumes:
                    vol["pool"] = name
                    allocation = vol.get("allocation_bytes")
                    capacity = vol.get("capacity_bytes")
                    identifiers = set()
                    if vol.get("path"):
                        identifiers.add(vol["path"])
                    if vol.get("key"):
                        identifiers.add(vol["key"])
                    if vol.get("name"):
                        identifiers.add(f"{name}/{vol['name']}")
                    attached = any(identifier in attached_identifiers for identifier in identifiers)
                    vol["state"] = _derive_volume_state(
                        allocation if isinstance(allocation, int) else None,
                        capacity if isinstance(capacity, int) else None,
                        attached=attached,
                        context=f"{name}::{vol.get('name')}",
                    )
                volumes.extend(pool_volumes)
            if volume_errors:
                errors.extend(volume_errors)

            pools.append(pool_entry)
        except libvirt.libvirtError as exc:
            logger.debug("Failed to inspect storage pool %s: %s", name, exc)
            errors.append(f"{name}: {exc}")

    pools.sort(key=lambda entry: entry.get("name") or "")
    volumes.sort(key=lambda entry: (entry.get("pool") or "", entry.get("name") or ""))

    inventory: Dict[str, Any] = {
        "pools": pools,
        "volumes": volumes,
    }
    if errors:
        inventory["errors"] = errors

    return inventory
