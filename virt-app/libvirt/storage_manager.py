from __future__ import annotations

import os
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, TYPE_CHECKING

import libvirt
from xml.sax.saxutils import escape

from .errors import (
    StorageError,
    StoragePoolNotEmptyError,
    StoragePoolNotFoundError,
    StorageVolumeExistsError,
    StorageVolumeInUseError,
    StorageVolumeNotFoundError,
)
from .storage import gather_host_storage_inventory, _derive_volume_state, _detect_pool_type

if TYPE_CHECKING:
    from .host import LibvirtHost


logger = logging.getLogger(__name__)


_POOL_STATE_LABELS = {
    getattr(libvirt, "VIR_STORAGE_POOL_INACTIVE", None): "inactive",
    getattr(libvirt, "VIR_STORAGE_POOL_BUILDING", None): "building",
    getattr(libvirt, "VIR_STORAGE_POOL_RUNNING", None): "running",
    getattr(libvirt, "VIR_STORAGE_POOL_DEGRADED", None): "degraded",
    getattr(libvirt, "VIR_STORAGE_POOL_INACCESSIBLE", None): "inaccessible",
}


def _map_pool_state(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return _POOL_STATE_LABELS.get(value, f"state:{value}")


class LibvirtStorageManager:
    """Encapsulates storage-centric operations for a libvirt host."""

    def __init__(self, host: "LibvirtHost", retry_decider: Callable[[libvirt.libvirtError], bool]):
        self._host = host
        self._should_retry = retry_decider

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def get_inventory(self) -> Dict[str, Any]:
        if not self._host._ensure_connection():
            raise RuntimeError(f"Not connected to {self._host.hostname}")
        if not self._host.conn:
            raise RuntimeError(f"Not connected to {self._host.hostname}")
        return gather_host_storage_inventory(self._host.conn)

    def describe_volume(self, pool_name: str, volume_name: str) -> Dict[str, Any]:
        pool, volume = self._lookup_storage_volume(pool_name, volume_name)
        return self._summarize_storage_volume(pool_name, volume_name, pool, volume)

    def delete_volume(self, pool_name: str, volume_name: str, *, force: bool = False) -> Dict[str, Any]:
        pool, volume = self._lookup_storage_volume(pool_name, volume_name)
        details = self._summarize_storage_volume(pool_name, volume_name, pool, volume)

        conflicts = details.get("attached_domains") or []
        if conflicts and not force:
            raise StorageVolumeInUseError(pool_name, volume_name, conflicts)

        delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
        try:
            volume.delete(delete_flags)
        except libvirt.libvirtError as exc:
            logger.error(
                "Failed to delete volume %s/%s on %s: %s",
                pool_name,
                volume_name,
                self._host.hostname,
                exc,
            )
            raise StorageError(
                f"Failed to delete volume '{volume_name}' in pool '{pool_name}': {exc}"
            ) from exc

        try:
            pool.refresh(0)
        except libvirt.libvirtError as exc:
            logger.debug(
                "refresh(%s) after delete failed on %s: %s",
                pool_name,
                self._host.hostname,
                exc,
            )

        return {
            "host": self._host.hostname,
            "pool": pool_name,
            "volume": volume_name,
            "path": details.get("volume", {}).get("path"),
            "capacity_bytes": details.get("volume", {}).get("capacity_bytes"),
            "allocation_bytes": details.get("volume", {}).get("allocation_bytes"),
            "deleted": True,
            "force": force,
            "attached_domains": conflicts,
        }

    def upload_volume(
        self,
        pool_name: str,
        volume_name: str,
        source_path: str,
        *,
        size_bytes: int,
        overwrite: bool = False,
        volume_format: Optional[str] = "raw",
    ) -> Dict[str, Any]:
        if size_bytes <= 0:
            raise StorageError("Uploaded file is empty")

        if not os.path.exists(source_path):
            raise StorageError("Uploaded file is no longer available on disk")

        pool = self._lookup_storage_pool(pool_name)

        existing_volume = None
        try:
            existing_volume = pool.storageVolLookupByName(volume_name)
        except libvirt.libvirtError:
            existing_volume = None

        if existing_volume:
            summary = self._summarize_storage_volume(pool_name, volume_name, pool, existing_volume)
            attached_domains = summary.get("attached_domains") or []
            if attached_domains:
                raise StorageVolumeInUseError(pool_name, volume_name, attached_domains)
            if not overwrite:
                raise StorageVolumeExistsError(pool_name, volume_name)

        pool_type = None
        try:
            pool_type = _detect_pool_type(pool)
        except Exception:
            pool_type = None

        volume_type = self._infer_volume_type(pool_type)
        fmt = (volume_format or "raw").lower() if volume_format else None
        if fmt not in {None, "raw", "qcow2", "qcow", "vmdk"}:
            raise StorageError(f"Unsupported volume format '{volume_format}'")

        volume_xml = self._build_volume_xml(
            volume_name,
            size_bytes,
            volume_type=volume_type,
            volume_format=fmt,
        )

        if existing_volume and overwrite:
            delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
            try:
                existing_volume.delete(delete_flags)
            except libvirt.libvirtError as exc:
                logger.error(
                    "Failed to delete existing volume %s/%s on %s prior to upload: %s",
                    pool_name,
                    volume_name,
                    self._host.hostname,
                    exc,
                )
                raise StorageError(
                    f"Failed to remove existing volume '{volume_name}' before upload: {exc}"
                ) from exc

        try:
            volume = pool.createXML(volume_xml, 0)
        except libvirt.libvirtError as exc:
            logger.error(
                "Failed to create volume %s/%s on %s: %s",
                pool_name,
                volume_name,
                self._host.hostname,
                exc,
            )
            raise StorageError(f"Failed to create volume '{volume_name}': {exc}") from exc

        stream = None
        try:
            if not self._host.conn:
                raise RuntimeError(f"Not connected to {self._host.hostname}")
            stream = self._host.conn.newStream(0)
            volume.upload(stream, 0, size_bytes, 0)

            with open(source_path, "rb") as src:
                while True:
                    chunk = src.read(2 * 1024 * 1024)
                    if not chunk:
                        break
                    stream.send(chunk)
            stream.finish()
        except Exception as exc:
            if stream is not None:
                try:
                    stream.abort()
                except libvirt.libvirtError:
                    pass
            try:
                volume.delete(getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0))
            except libvirt.libvirtError as delete_exc:
                logger.warning(
                    "Failed to clean up partial volume %s/%s on %s after upload error: %s",
                    pool_name,
                    volume_name,
                    self._host.hostname,
                    delete_exc,
                )
            raise StorageError(f"Failed to upload data to volume '{volume_name}': {exc}") from exc

        try:
            pool.refresh(0)
        except libvirt.libvirtError as exc:
            logger.debug(
                "refresh(%s) after upload failed on %s: %s",
                pool_name,
                self._host.hostname,
                exc,
            )

        result = self._summarize_storage_volume(pool_name, volume_name, pool, volume)
        result["upload"] = {
            "bytes": size_bytes,
            "overwrite": overwrite,
            "format": fmt,
        }
        return result

    def delete_pool(self, pool_name: str, *, force: bool = False) -> Dict[str, Any]:
        pool = self._lookup_storage_pool(pool_name)

        state = persistent = autostart = capacity = allocation = available = None
        try:
            info = pool.info()
            if isinstance(info, (list, tuple)) and len(info) >= 4:
                state = _map_pool_state(int(info[0]))
                capacity = int(info[1])
                allocation = int(info[2])
                available = int(info[3])
        except libvirt.libvirtError as exc:
            logger.debug("info() failed for pool %s on %s: %s", pool_name, self._host.hostname, exc)

        try:
            persistent = bool(pool.isPersistent())
        except libvirt.libvirtError:
            persistent = None

        try:
            autostart = bool(pool.autostart())
        except libvirt.libvirtError:
            autostart = None

        pool_type = None
        try:
            pool_type = _detect_pool_type(pool)
        except Exception:
            pool_type = None

        volume_names: List[str] = []
        try:
            volume_names = sorted(name for name in pool.listVolumes() if name)
        except libvirt.libvirtError as exc:
            logger.debug("listVolumes() failed for pool %s on %s: %s", pool_name, self._host.hostname, exc)

        if volume_names and not force:
            raise StoragePoolNotEmptyError(pool_name, volume_names)

        was_active = None
        try:
            was_active = bool(pool.isActive())
        except libvirt.libvirtError:
            was_active = None

        if was_active:
            try:
                pool.destroy()
            except libvirt.libvirtError as exc:
                logger.error(
                    "Failed to destroy storage pool %s on %s: %s",
                    pool_name,
                    self._host.hostname,
                    exc,
                )
                raise StorageError(
                    f"Failed to stop storage pool '{pool_name}': {exc}"
                ) from exc

        if force and volume_names:
            delete_flags = getattr(libvirt, "VIR_STORAGE_POOL_DELETE_NORMAL", 0)
            force_flag = getattr(libvirt, "VIR_STORAGE_POOL_DELETE_FORCE", None)
            if isinstance(force_flag, int):
                delete_flags |= force_flag
            try:
                pool.delete(delete_flags)
            except libvirt.libvirtError as exc:
                logger.debug("delete() failed for pool %s on %s: %s", pool_name, self._host.hostname, exc)

        if persistent:
            try:
                pool.undefine()
            except libvirt.libvirtError as exc:
                logger.error(
                    "Failed to undefine storage pool %s on %s: %s",
                    pool_name,
                    self._host.hostname,
                    exc,
                )
                raise StorageError(
                    f"Failed to undefine storage pool '{pool_name}': {exc}"
                ) from exc

        return {
            "host": self._host.hostname,
            "pool": pool_name,
            "deleted": True,
            "force": force,
            "state": state,
            "persistent": persistent,
            "autostart": autostart,
            "capacity_bytes": capacity,
            "allocation_bytes": allocation,
            "available_bytes": available,
            "type": pool_type,
            "volumes": volume_names,
            "was_active": was_active,
        }

    # ------------------------------------------------------------------
    # Helpers reused by host
    # ------------------------------------------------------------------
    def lookup_volume_by_path(
        self, path: str
    ) -> Tuple["libvirt.virStoragePool", "libvirt.virStorageVol"]:
        if not self._host.conn:
            raise StorageError("Not connected to host")

        try:
            volume = self._host.conn.storageVolLookupByPath(path)
        except libvirt.libvirtError as exc:
            logger.debug(
                "storageVolLookupByPath(%s) failed on %s: %s",
                path,
                self._host.hostname,
                exc,
            )
            volume = None

        pool = None
        if volume is not None:
            lookup_pool = getattr(self._host.conn, "storagePoolLookupByVolume", None)
            if callable(lookup_pool):
                try:
                    pool = lookup_pool(volume)
                except libvirt.libvirtError:
                    pool = None

        if pool is None or volume is None:
            pool_names: List[str] = []
            try:
                pool_names.extend(self._host.conn.listStoragePools() or [])
                pool_names.extend(self._host.conn.listDefinedStoragePools() or [])
            except libvirt.libvirtError as exc:
                logger.debug(
                    "Failed to enumerate storage pools on %s: %s",
                    self._host.hostname,
                    exc,
                )

            for candidate_name in pool_names:
                try:
                    candidate_pool = self._host.conn.storagePoolLookupByName(candidate_name)
                except libvirt.libvirtError:
                    continue

                lookup_by_path = getattr(candidate_pool, "storageVolLookupByPath", None)
                candidate_volume = None
                if callable(lookup_by_path):
                    try:
                        candidate_volume = lookup_by_path(path)
                    except libvirt.libvirtError:
                        candidate_volume = None

                if candidate_volume is None:
                    lookup_by_name = getattr(candidate_pool, "storageVolLookupByName", None)
                    if callable(lookup_by_name):
                        fallback_name = os.path.basename(path)
                        if fallback_name:
                            try:
                                candidate_volume = lookup_by_name(fallback_name)
                            except libvirt.libvirtError:
                                candidate_volume = None

                if candidate_volume is not None:
                    pool = candidate_pool
                    volume = candidate_volume
                    break

        if not pool or not volume:
            raise StorageError(
                f"Unable to resolve storage volume for path '{path}' on {self._host.hostname}"
            )

        return pool, volume

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _lookup_storage_pool(self, pool_name: str):
        if not self._host._ensure_connection():
            raise RuntimeError(f"Not connected to {self._host.hostname}")
        if not self._host.conn:
            raise RuntimeError(f"Not connected to {self._host.hostname}")

        try:
            pool = self._host.conn.storagePoolLookupByName(pool_name)
        except libvirt.libvirtError as exc:
            logger.debug(
                "storagePoolLookupByName(%s) failed on %s: %s",
                pool_name,
                self._host.hostname,
                exc,
            )
            if self._should_retry(exc):
                logger.warning(
                    "storagePoolLookupByName(%s) failed on %s (%s); attempting reconnect",
                    pool_name,
                    self._host.hostname,
                    exc,
                )
                self._host.disconnect()
                if self._host.connect():
                    try:
                        pool = self._host.conn.storagePoolLookupByName(pool_name)
                    except libvirt.libvirtError as retry_exc:
                        logger.error(
                            "storagePoolLookupByName(%s) retry failed on %s: %s",
                            pool_name,
                            self._host.hostname,
                            retry_exc,
                        )
                    else:
                        try:
                            pool.refresh(0)
                        except libvirt.libvirtError as refresh_exc:
                            logger.debug(
                                "refresh(%s) failed on %s after reconnect: %s",
                                pool_name,
                                self._host.hostname,
                                refresh_exc,
                            )
                        return pool
                else:
                    logger.error(
                        "Reconnection attempt failed for %s prior to storage pool lookup",
                        self._host.hostname,
                    )
            raise StoragePoolNotFoundError(pool_name) from exc

        try:
            pool.refresh(0)
        except libvirt.libvirtError as exc:
            logger.debug("refresh(%s) failed on %s: %s", pool_name, self._host.hostname, exc)

        return pool

    def _lookup_storage_volume(
        self, pool_name: str, volume_name: str
    ) -> Tuple["libvirt.virStoragePool", "libvirt.virStorageVol"]:
        pool = self._lookup_storage_pool(pool_name)

        try:
            volume = pool.storageVolLookupByName(volume_name)
        except libvirt.libvirtError as exc:
            logger.debug(
                "storageVolLookupByName(%s) failed in pool %s on %s: %s",
                volume_name,
                pool_name,
                self._host.hostname,
                exc,
            )
            raise StorageVolumeNotFoundError(pool_name, volume_name) from exc

        return pool, volume

    def _collect_running_domain_disk_sources(self) -> Dict[str, Set[str]]:
        references: Dict[str, Set[str]] = {}
        if not self._host.conn:
            return references

        try:
            domain_ids = self._host.conn.listDomainsID()
        except libvirt.libvirtError as exc:
            logger.debug("listDomainsID failed on %s: %s", self._host.hostname, exc)
            return references

        for dom_id in domain_ids or []:
            try:
                domain = self._host.conn.lookupByID(dom_id)
            except libvirt.libvirtError as exc:
                logger.debug("lookupByID(%s) failed on %s: %s", dom_id, self._host.hostname, exc)
                continue

            domain_name = domain.name()
            try:
                xml_desc = domain.XMLDesc(0)
            except libvirt.libvirtError as exc:
                logger.debug(
                    "XMLDesc failed for domain %s on %s: %s",
                    domain_name,
                    self._host.hostname,
                    exc,
                )
                continue

            try:
                root = ET.fromstring(xml_desc)
            except ET.ParseError as exc:
                logger.debug(
                    "Failed to parse XML for domain %s on %s: %s",
                    domain_name,
                    self._host.hostname,
                    exc,
                )
                continue

            values: Set[str] = set()
            for disk in root.findall("./devices/disk"):
                source = disk.find("source")
                if source is None:
                    continue
                for attr_val in source.attrib.values():
                    if attr_val:
                        values.add(attr_val)
                pool = source.attrib.get("pool")
                volume = source.attrib.get("volume") or source.attrib.get("name")
                if pool and volume:
                    values.add(f"{pool}/{volume}")

            if values:
                references[domain_name] = values

        return references

    def _find_volume_consumers(
        self,
        pool_name: str,
        volume_name: str,
        *,
        volume_path: Optional[str] = None,
        volume_key: Optional[str] = None,
    ) -> List[str]:
        usage = self._collect_running_domain_disk_sources()
        identifiers = {volume_name, f"{pool_name}/{volume_name}"}
        if volume_path:
            identifiers.add(volume_path)
        if volume_key:
            identifiers.add(volume_key)

        consumers: List[str] = []
        for domain_name, sources in usage.items():
            if any(identifier and identifier in sources for identifier in identifiers):
                consumers.append(domain_name)

        consumers.sort()
        return consumers

    def _summarize_storage_volume(
        self,
        pool_name: str,
        volume_name: str,
        pool: "libvirt.virStoragePool",
        volume: "libvirt.virStorageVol",
    ) -> Dict[str, Any]:
        capacity = allocation = available = None
        vol_type = None
        vol_format = None
        backing_store = None

        try:
            info = volume.info()
        except libvirt.libvirtError as exc:
            logger.debug(
                "info() failed for volume %s/%s on %s: %s",
                pool_name,
                volume_name,
                self._host.hostname,
                exc,
            )
            info = None

        if isinstance(info, (list, tuple)):
            if len(info) > 1 and info[1] is not None:
                capacity = int(info[1])
            if len(info) > 2 and info[2] is not None:
                allocation = int(info[2])
            if capacity is not None and allocation is not None:
                available = max(capacity - allocation, 0)

        volume_path = None
        try:
            volume_path = volume.path()
        except libvirt.libvirtError as exc:
            logger.debug(
                "path() failed for volume %s/%s on %s: %s",
                pool_name,
                volume_name,
                self._host.hostname,
                exc,
            )

        volume_key = None
        try:
            volume_key = volume.key()
        except libvirt.libvirtError as exc:
            logger.debug(
                "key() failed for volume %s/%s on %s: %s",
                pool_name,
                volume_name,
                self._host.hostname,
                exc,
            )

        xml_desc = None
        try:
            xml_desc = volume.XMLDesc(0)
        except libvirt.libvirtError as exc:
            logger.debug(
                "XMLDesc failed for volume %s/%s on %s: %s",
                pool_name,
                volume_name,
                self._host.hostname,
                exc,
            )

        if xml_desc:
            try:
                root = ET.fromstring(xml_desc)
                vol_type = root.attrib.get("type") or vol_type
                format_el = root.find("./target/format")
                if format_el is not None:
                    vol_format = format_el.attrib.get("type")
                target_path = root.findtext("./target/path")
                if target_path and not volume_path:
                    volume_path = target_path
                backing_store = root.findtext("./backingStore/path") or backing_store
            except ET.ParseError as exc:
                logger.debug(
                    "Failed to parse storage volume XML for %s/%s: %s",
                    pool_name,
                    volume_name,
                    exc,
                )

        consumers = self._find_volume_consumers(
            pool_name,
            volume_name,
            volume_path=volume_path,
            volume_key=volume_key,
        )

        pool_state = None
        pool_capacity = pool_allocation = pool_available = None
        try:
            pstate, pcapacity, pallocation, pavailable = pool.info()
            pool_state = _map_pool_state(pstate)
            pool_capacity = int(pcapacity)
            pool_allocation = int(pallocation)
            pool_available = int(pavailable)
        except libvirt.libvirtError as exc:
            logger.debug("info() failed for pool %s on %s: %s", pool_name, self._host.hostname, exc)

        pool_persistent = None
        pool_autostart = None
        try:
            pool_persistent = bool(pool.isPersistent())
        except libvirt.libvirtError:
            pool_persistent = None
        try:
            pool_autostart = bool(pool.autostart())
        except libvirt.libvirtError:
            pool_autostart = None

        summary: Dict[str, Any] = {
            "host": self._host.hostname,
            "pool": {
                "name": pool_name,
                "state": pool_state,
                "persistent": pool_persistent,
                "autostart": pool_autostart,
                "capacity_bytes": pool_capacity,
                "allocation_bytes": pool_allocation,
                "available_bytes": pool_available,
            },
            "volume": {
                "name": volume_name,
                "path": volume_path,
                "key": volume_key,
                "type": vol_type,
                "format": vol_format,
                "capacity_bytes": capacity,
                "allocation_bytes": allocation,
                "available_bytes": available,
                "backing_store": backing_store,
                "state": _derive_volume_state(
                    allocation,
                    capacity,
                    attached=bool(consumers),
                    context=f"{self._host.hostname}:{pool_name}/{volume_name}",
                ),
            },
            "attached_domains": consumers,
        }

        if xml_desc:
            summary["xml"] = xml_desc

        return summary

    @staticmethod
    def _infer_volume_type(pool_type: Optional[str]) -> str:
        if not pool_type:
            return "file"
        pool_type = pool_type.lower()
        if pool_type in {"iscsi", "scsi", "logical"}:
            return "block"
        return "file"

    @staticmethod
    def _build_volume_xml(
        name: str,
        capacity_bytes: int,
        *,
        volume_type: str = "file",
        volume_format: Optional[str] = None,
        backing_path: Optional[str] = None,
        backing_format: Optional[str] = None,
    ) -> str:
        if capacity_bytes <= 0:
            raise ValueError("Volume capacity must be greater than zero")

        escaped_name = escape(name)
        fmt_fragment = (
            f"<format type=\"{escape(volume_format)}\"/>" if volume_format else ""
        )
        backing_fragment = ""
        if backing_path:
            backing_fmt_fragment = (
                f"<format type=\"{escape(backing_format)}\"/>" if backing_format else ""
            )
            backing_fragment = (
                f"<backingStore><path>{escape(backing_path)}</path>{backing_fmt_fragment}</backingStore>"
            )

        return (
            "<volume type=\"{type}\">"
            "<name>{name}</name>"
            "<capacity unit=\"bytes\">{capacity}</capacity>"
            "<allocation unit=\"bytes\">{capacity}</allocation>"
            "<target>{format}</target>"
            "{backing}"
            "</volume>"
        ).format(
            type=volume_type,
            name=escaped_name,
            capacity=capacity_bytes,
            format=fmt_fragment,
            backing=backing_fragment,
        )

    # Public wrappers for host convenience ---------------------------------

    def build_volume_xml(
        self,
        name: str,
        capacity_bytes: int,
        *,
        volume_type: str = "file",
        volume_format: Optional[str] = None,
        backing_path: Optional[str] = None,
        backing_format: Optional[str] = None,
    ) -> str:
        return self._build_volume_xml(
            name,
            capacity_bytes,
            volume_type=volume_type,
            volume_format=volume_format,
            backing_path=backing_path,
            backing_format=backing_format,
        )

    def infer_volume_type(self, pool_type: Optional[str]) -> str:
        return self._infer_volume_type(pool_type)
