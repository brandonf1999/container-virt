from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

import libvirt
from xml.sax.saxutils import escape

from .common import lookup_domain
from .clone import LibvirtDomainCloneExecutor, LibvirtDomainClonePlanner
from ..errors import (
    DomainActiveError,
    DomainDeviceNotFoundError,
    DomainExistsError,
    DomainNotFoundError,
    DomainNotRunningError,
    StorageError,
)
from ..storage import _detect_pool_type

if TYPE_CHECKING:
    from ..host import LibvirtHost

logger = logging.getLogger(__name__)

_SHARED_STORAGE_POOL_TYPES = {
    "netfs",
    "gluster",
    "rbd",
    "sheepdog",
    "iscsi",
}
_DEFAULT_INTERFACE_MTU = 1500
_MAX_VHOST_QUEUES = 8


class LibvirtDomainLifecycle:
    """Encapsulates domain mutation and lifecycle operations."""

    def __init__(
        self,
        host: "LibvirtHost",
        retry_decider: Callable[[libvirt.libvirtError], bool],
        *,
        detail_resolver: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> None:
        self._host = host
        self._should_retry = retry_decider
        self._detail_resolver = detail_resolver
        self._clone_planner = LibvirtDomainClonePlanner(host)
        self._clone_executor = LibvirtDomainCloneExecutor(host)

    # ------------------------------------------------------------------
    # High-level lifecycle operations
    # ------------------------------------------------------------------

    def clone_guest(
        self,
        source_name: str,
        *,
        new_name: str,
        autostart: Optional[bool] = None,
        start: bool = False,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {self._host.hostname}")

        try:
            source_domain = self._host.conn.lookupByName(source_name)  # type: ignore[union-attr]
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s: %s", source_name, self._host.hostname, exc)
            raise DomainNotFoundError(source_name) from exc

        try:
            existing = self._host.conn.lookupByName(new_name)  # type: ignore[union-attr]
        except libvirt.libvirtError:
            existing = None
        if existing is not None:
            raise DomainExistsError(new_name)

        try:
            is_active = bool(source_domain.isActive())
        except libvirt.libvirtError:
            is_active = False
        if is_active:
            raise DomainActiveError(source_name)

        try:
            source_info = source_domain.info()
        except libvirt.libvirtError as exc:
            logger.error("info() failed for %s on %s: %s", source_name, self._host.hostname, exc)
            raise StorageError(f"Failed to obtain info for '{source_name}': {exc}") from exc

        vcpus = int(source_info[3]) if len(source_info) > 3 else 1
        memory_kib = int(source_info[2]) if len(source_info) > 2 else None
        if not memory_kib and len(source_info) > 1:
            memory_kib = int(source_info[1])
        if not memory_kib:
            raise StorageError("Unable to determine source memory allocation")
        memory_mb = max(int(memory_kib / 1024), 1)

        if autostart is None:
            try:
                autostart = bool(source_domain.autostart())
            except libvirt.libvirtError:
                autostart = False

        try:
            xml_desc = source_domain.XMLDesc(0)
        except libvirt.libvirtError as exc:
            logger.error("XMLDesc failed for %s on %s: %s", source_name, self._host.hostname, exc)
            raise StorageError(f"Failed to read domain XML for '{source_name}': {exc}") from exc

        try:
            root = ET.fromstring(xml_desc)
        except ET.ParseError as exc:
            raise StorageError(f"Failed to parse domain XML for '{source_name}': {exc}") from exc

        if description is None:
            description = root.findtext("description")

        plan = self._clone_planner.build_plan(
            source_domain=source_domain,
            source_name=source_name,
            new_name=new_name,
            xml_root=root,
        )

        artifacts = None
        try:
            artifacts = self._clone_executor.execute(plan)
            result = self.create_guest(
                new_name,
                vcpus=vcpus,
                memory_mb=memory_mb,
                autostart=bool(autostart),
                start=start,
                description=description,
                volumes=artifacts.disk_specs + artifacts.cd_specs,
                networks=artifacts.network_specs,
                enable_vnc=artifacts.vnc_enabled,
                vnc_password=artifacts.vnc_password,
            )
            result["clone"] = {
                "vnc_password": artifacts.vnc_password,
                "mac_addresses": artifacts.mac_addresses,
            }
            return result
        except Exception:
            if artifacts is not None:
                self._clone_executor.cleanup(artifacts)
            raise

    def delete_guest(self, name: str, *, force: bool = False, remove_storage: bool = False) -> Dict[str, Any]:
        try:
            domain = lookup_domain(self._host, self._should_retry, name)
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s during delete: %s", name, self._host.hostname, exc)
            raise DomainNotFoundError(name) from exc

        disk_source_paths: List[str] = []
        if remove_storage:
            try:
                domain_xml = domain.XMLDesc(0)
                xml_root = ET.fromstring(domain_xml)
                for disk_node in xml_root.findall("./devices/disk"):
                    device_type = disk_node.get("device") or ""
                    if device_type not in {"disk", "cdrom"}:
                        continue
                    source = disk_node.find("source")
                    if source is None:
                        continue
                    path = source.get("file") or source.get("dev")
                    if path and path.startswith("/"):
                        disk_source_paths.append(path)
            except libvirt.libvirtError as exc:
                logger.debug("XMLDesc failed for %s on %s: %s", name, self._host.hostname, exc)
            except ET.ParseError as exc:
                logger.debug("Failed to parse domain XML for %s on %s: %s", name, self._host.hostname, exc)

        try:
            is_active = bool(domain.isActive())
        except libvirt.libvirtError:
            is_active = False

        if is_active:
            if not force:
                raise DomainActiveError(name)
            try:
                domain.destroy()
            except libvirt.libvirtError as exc:
                logger.error("Failed to destroy active domain %s on %s: %s", name, self._host.hostname, exc)
                raise StorageError(f"Failed to stop domain '{name}' prior to deletion: {exc}") from exc

        undefine_flags = 0
        for attr in ("VIR_DOMAIN_UNDEFINE_MANAGED_SAVE", "VIR_DOMAIN_UNDEFINE_NVRAM"):
            undefine_flags |= getattr(libvirt, attr, 0)

        try:
            if undefine_flags:
                domain.undefineFlags(undefine_flags)
            else:
                domain.undefine()
        except AttributeError:
            domain.undefine()
        except libvirt.libvirtError as exc:
            logger.error("Failed to undefine domain %s on %s: %s", name, self._host.hostname, exc)
            raise StorageError(f"Failed to remove domain '{name}': {exc}") from exc

        removed_volumes: List[Dict[str, Any]] = []
        if remove_storage and disk_source_paths:
            delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
            for path in disk_source_paths:
                try:
                    volume = self._host.conn.storageVolLookupByPath(path)  # type: ignore[union-attr]
                except libvirt.libvirtError as exc:
                    logger.debug(
                        "Failed to lookup volume by path %s on %s: %s",
                        path,
                        self._host.hostname,
                        exc,
                    )
                    continue

                pool = self._resolve_pool_for_volume(volume, path)
                if pool is None:
                    logger.debug("Unable to resolve pool for volume path %s on %s", path, self._host.hostname)
                    continue

                try:
                    volume_name = volume.name()
                except libvirt.libvirtError:
                    volume_name = path

                try:
                    pool_name = pool.name()
                except libvirt.libvirtError:
                    pool_name = "?"

                try:
                    volume.delete(delete_flags)
                    try:
                        pool.refresh(0)
                    except libvirt.libvirtError as refresh_exc:
                        logger.debug(
                            "refresh() failed for pool %s on %s after volume delete: %s",
                            pool_name,
                            self._host.hostname,
                            refresh_exc,
                        )
                    removed_volumes.append(
                        {
                            "pool": pool_name,
                            "volume": volume_name,
                            "path": path,
                        }
                    )
                except libvirt.libvirtError as exc:
                    logger.warning(
                        "Failed to delete storage volume %s/%s (path=%s) on %s: %s",
                        pool_name,
                        volume_name,
                        path,
                        self._host.hostname,
                        exc,
                    )

        logger.info(
            "Deleted domain %s on %s (force=%s, was_active=%s, removed_volumes=%d)",
            name,
            self._host.hostname,
            force,
            is_active,
            len(removed_volumes),
        )
        return {
            "host": self._host.hostname,
            "domain": name,
            "removed": True,
            "forced": bool(force),
            "was_active": bool(is_active),
            "removed_volumes": removed_volumes,
        }

    def migrate_guest(
        self,
        name: str,
        target_host: "LibvirtHost",
        *,
        live: bool = True,
        shared_storage: bool = True,
        autostart: Optional[bool] = None,
        tunnelled: Optional[bool] = None,
        peer2peer: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if not self._host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {self._host.hostname}")
        if not target_host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {target_host.hostname}")

        try:
            domain = lookup_domain(self._host, self._should_retry, name)
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s during migrate: %s", name, self._host.hostname, exc)
            raise DomainNotFoundError(name) from exc

        try:
            is_active = bool(domain.isActive())
        except libvirt.libvirtError:
            is_active = False

        if live and not is_active:
            raise DomainNotRunningError(name)

        if shared_storage:
            try:
                xml_desc = domain.XMLDesc(0)
            except libvirt.libvirtError as exc:
                logger.error("XMLDesc failed for %s on %s during migrate: %s", name, self._host.hostname, exc)
                raise StorageError(f"Failed to read domain XML for '{name}': {exc}") from exc
            self._assert_shared_storage(xml_desc)

        transport = target_host.migration_transport()
        if tunnelled is None:
            tunnelled = target_host.migration_opts.get("tunnelled")
        if tunnelled is None:
            tunnelled = transport == "ssh"
        if peer2peer is None:
            peer2peer = target_host.migration_opts.get("peer2peer")
        if peer2peer is None:
            peer2peer = True

        flags = 0
        if live:
            flags |= getattr(libvirt, "VIR_MIGRATE_LIVE", 0)
        if shared_storage:
            flags |= getattr(libvirt, "VIR_MIGRATE_SHARED_DISK", 0)
        flags |= getattr(libvirt, "VIR_MIGRATE_PERSIST_DEST", 0)
        flags |= getattr(libvirt, "VIR_MIGRATE_UNDEFINE_SOURCE", 0)
        if peer2peer:
            flags |= getattr(libvirt, "VIR_MIGRATE_PEER2PEER", 0)
        if tunnelled:
            flags |= getattr(libvirt, "VIR_MIGRATE_TUNNELLED", 0)

        dest_uri = target_host.migration_uri()
        logger.info(
            "Live migration settings for %s: transport=%s peer2peer=%s tunnelled=%s dest_uri=%s",
            name,
            transport,
            bool(peer2peer),
            bool(tunnelled),
            dest_uri,
        )
        try:
            if hasattr(domain, "migrateToURI3"):
                params: Dict[str, Any] = {}
                domain.migrateToURI3(dest_uri, params, flags)
            else:
                domain.migrateToURI(dest_uri, flags, None, 0)
        except libvirt.libvirtError as exc:
            logger.error(
                "Failed to migrate domain %s from %s to %s: %s",
                name,
                self._host.hostname,
                target_host.hostname,
                exc,
            )
            raise StorageError(f"Failed to live migrate domain '{name}': {exc}") from exc

        target_domain = None
        try:
            target_domain = target_host.conn.lookupByName(name)  # type: ignore[union-attr]
        except libvirt.libvirtError as exc:
            logger.debug("lookupByName(%s) failed on target %s after migrate: %s", name, target_host.hostname, exc)

        if target_domain is not None and isinstance(autostart, bool):
            try:
                target_domain.setAutostart(autostart)
            except libvirt.libvirtError as exc:
                logger.debug(
                    "setAutostart failed for %s on %s after migrate: %s",
                    name,
                    target_host.hostname,
                    exc,
                )

        started = is_active
        if target_domain is not None:
            try:
                started = bool(target_domain.isActive())
            except libvirt.libvirtError:
                started = is_active

        uuid_text = None
        if target_domain is not None:
            try:
                uuid_text = target_domain.UUIDString()
            except libvirt.libvirtError:
                uuid_text = None

        return {
            "host": target_host.hostname,
            "domain": name,
            "uuid": uuid_text,
            "started": started,
        }

    def detach_guest_block_device(self, name: str, target: str) -> Dict[str, Any]:
        if not target:
            raise DomainDeviceNotFoundError(name, target)

        try:
            domain = lookup_domain(self._host, self._should_retry, name)
        except libvirt.libvirtError as exc:
            raise DomainNotFoundError(name) from exc

        try:
            xml_flags = getattr(libvirt, "VIR_DOMAIN_XML_SECURE", 0) | getattr(libvirt, "VIR_DOMAIN_XML_INACTIVE", 0)
            domain_xml = domain.XMLDesc(xml_flags)
        except libvirt.libvirtError as exc:
            logger.error("XMLDesc failed for %s on %s: %s", name, self._host.hostname, exc)
            raise StorageError(f"Failed to inspect domain '{name}': {exc}") from exc

        try:
            root = ET.fromstring(domain_xml)
        except ET.ParseError as exc:
            raise StorageError(f"Failed to parse domain XML for '{name}': {exc}") from exc

        disk_node = None
        for disk in root.findall("./devices/disk"):
            device_type = (disk.get("device") or "").lower()
            if device_type not in {"disk", "cdrom"}:
                continue
            target_node = disk.find("target")
            if target_node is None:
                continue
            if target_node.get("dev") == target:
                disk_node = disk
                break

        if disk_node is None:
            raise DomainDeviceNotFoundError(name, target)

        disk_xml = ET.tostring(disk_node, encoding="unicode")
        flags = getattr(libvirt, "VIR_DOMAIN_AFFECT_CONFIG", 0)
        try:
            is_active = bool(domain.isActive())
        except libvirt.libvirtError:
            is_active = False
        if is_active:
            flags |= getattr(libvirt, "VIR_DOMAIN_AFFECT_LIVE", 0)

        try:
            domain.detachDeviceFlags(disk_xml, flags)
        except libvirt.libvirtError as exc:
            logger.error(
                "detachDeviceFlags failed for %s (%s) on %s: %s",
                name,
                target,
                self._host.hostname,
                exc,
            )
            raise StorageError(f"Failed to detach device '{target}' from domain '{name}': {exc}") from exc

        details = self._resolve_details(name)
        result: Dict[str, Any] = {
            "host": self._host.hostname,
            "domain": name,
        }
        if details is not None:
            result["details"] = details
        return result

    def generate_vnc_connection_file(self, name: str) -> Dict[str, Any]:
        raise NotImplementedError("Use LibvirtDomainConsole for console helpers")

    def start_domain(self, name: str) -> bool:
        try:
            domain = lookup_domain(self._host, self._should_retry, name)
        except libvirt.libvirtError as exc:
            logger.error(
                "lookupByName(%s) failed on %s during connect: %s",
                name,
                self._host.hostname,
                exc,
            )
            raise DomainNotFoundError(name) from exc
        try:
            domain.create()
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to start domain %s on %s: %s", name, self._host.hostname, exc)
            return False

    def shutdown_domain(self, name: str) -> bool:
        domain = lookup_domain(self._host, self._should_retry, name)
        try:
            domain.shutdown()
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to shutdown domain %s on %s: %s", name, self._host.hostname, exc)
            return False

    def reboot_domain(self, name: str) -> bool:
        domain = lookup_domain(self._host, self._should_retry, name)
        try:
            domain.reboot(libvirt.VIR_DOMAIN_REBOOT_DEFAULT)
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to reboot domain %s on %s: %s", name, self._host.hostname, exc)
            return False

    def destroy_domain(self, name: str) -> bool:
        domain = lookup_domain(self._host, self._should_retry, name)
        try:
            domain.destroy()
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to destroy domain %s on %s: %s", name, self._host.hostname, exc)
            return False

    def create_guest(
        self,
        name: str,
        *,
        vcpus: int,
        memory_mb: int,
        cpu_mode: str = "host-model",
        autostart: bool,
        start: bool,
        description: Optional[str],
        volumes: List[Dict[str, Any]],
        networks: List[Dict[str, Any]],
        enable_vnc: Optional[bool] = None,
        vnc_password: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {self._host.hostname}")

        if not name:
            raise StorageError("Domain name is required")

        try:
            existing = self._host.conn.lookupByName(name)  # type: ignore[union-attr]
            if existing is not None:
                raise DomainExistsError(name)
        except libvirt.libvirtError:
            existing = None

        if vcpus <= 0:
            raise StorageError("vCPUs must be greater than zero")
        if memory_mb <= 0:
            raise StorageError("Memory must be greater than zero")
        if not volumes:
            raise StorageError("At least one volume is required")
        normalized_cpu_mode = (cpu_mode or "host-model").strip().lower()
        if normalized_cpu_mode not in {"host-model", "host-passthrough"}:
            raise StorageError("CPU mode must be host-model or host-passthrough")

        normalized_vnc_password = (vnc_password or "").strip()
        if enable_vnc is True and not normalized_vnc_password:
            raise StorageError("VNC password must be provided when enable_vnc is true")
        if normalized_vnc_password:
            if len(normalized_vnc_password) < 6:
                raise StorageError("VNC password must be at least 6 characters")
            if len(normalized_vnc_password) > 64:
                raise StorageError("VNC password must be 64 characters or fewer")
            if not normalized_vnc_password.isascii():
                raise StorageError("VNC password must contain only ASCII characters")

        vnc_enabled = True if enable_vnc is None else bool(enable_vnc)
        if not vnc_enabled:
            normalized_vnc_password = ""

        disk_specs: List[Dict[str, Any]] = []
        cd_specs: List[Dict[str, Any]] = []
        created_volumes: List[Tuple[libvirt.virStoragePool, libvirt.virStorageVol]] = []

        def _resolve_pool(pool_name: str) -> libvirt.virStoragePool:
            pool = self._host.conn.storagePoolLookupByName(pool_name)  # type: ignore[union-attr]
            pool.refresh(0)
            return pool

        def _volume_path(pool: libvirt.virStoragePool, volume_name: str) -> str:
            volume = pool.storageVolLookupByName(volume_name)
            return volume.path()

        def _volume_format(pool: libvirt.virStoragePool, volume_name: str) -> Optional[str]:
            try:
                volume = pool.storageVolLookupByName(volume_name)
            except libvirt.libvirtError:
                return None
            try:
                xml_desc = volume.XMLDesc(0)
                root = ET.fromstring(xml_desc)
            except (libvirt.libvirtError, ET.ParseError):
                return None
            driver = root.find("./target/format")
            if driver is not None:
                fmt = driver.get("type")
                if fmt:
                    return fmt.lower()
            return None

        try:
            for index, spec in enumerate(volumes):
                vol_type = spec.get("type", "disk")
                pool_name = spec.get("pool")
                vol_name = spec.get("name")
                if not pool_name or not vol_name:
                    raise StorageError("Volume name and pool are required")

                pool = _resolve_pool(pool_name)

                if vol_type == "iso":
                    source_path = spec.get("source_path")
                    source_volume_name = spec.get("source_volume")
                    if not source_path and not source_volume_name:
                        raise StorageError(
                            f"ISO volume '{vol_name}' must specify source_path or source_volume"
                        )
                    if source_volume_name:
                        source_path = _volume_path(pool, source_volume_name)
                    if not source_path:
                        raise StorageError(f"Could not resolve source path for ISO volume '{vol_name}'")
                    cd_specs.append(
                        {
                            "path": source_path,
                            "boot": bool(spec.get("boot", False)),
                            "name": vol_name,
                        }
                    )
                    continue

                existing_path = spec.get("source_path")
                source_volume_name = spec.get("source_volume")
                if existing_path and source_volume_name:
                    raise StorageError(
                        f"Disk volume '{vol_name}' cannot specify both source_path and source_volume"
                    )
                if existing_path:
                    path = existing_path
                    fmt = (spec.get("format") or "qcow2").lower()
                elif source_volume_name:
                    try:
                        path = _volume_path(pool, source_volume_name)
                    except libvirt.libvirtError as exc:
                        raise StorageError(
                            f"Source volume '{source_volume_name}' not found in pool '{pool_name}': {exc}"
                        ) from exc
                    fmt = (spec.get("format") or _volume_format(pool, source_volume_name) or "qcow2").lower()
                else:
                    size_mb = spec.get("size_mb")
                    if size_mb is None or size_mb <= 0:
                        raise StorageError(f"Disk volume '{vol_name}' must include a positive size_mb")
                    fmt = (spec.get("format") or "qcow2").lower()
                    backing_volume_name = spec.get("source_volume")
                    backing_path = None
                    backing_format = None
                    if backing_volume_name:
                        backing_volume = pool.storageVolLookupByName(backing_volume_name)
                        backing_path = backing_volume.path()
                        backing_xml = backing_volume.XMLDesc(0)
                        try:
                            backing_root = ET.fromstring(backing_xml)
                            backing_format = None
                            driver = backing_root.find("./target/format")
                            if driver is not None and driver.get("type"):
                                backing_format = driver.get("type")
                        except ET.ParseError:
                            backing_format = None

                    volume_xml = self._host.storage.build_volume_xml(
                        vol_name,
                        size_mb * 1024 * 1024,
                        volume_type=self._host.storage.infer_volume_type(_detect_pool_type(pool)),
                        volume_format=fmt,
                        backing_path=backing_path,
                        backing_format=backing_format,
                    )

                    new_volume = pool.createXML(volume_xml, 0)
                    created_volumes.append((pool, new_volume))
                    path = new_volume.path()
                disk_specs.append(
                    {
                        "path": path,
                        "format": fmt,
                        "boot": bool(spec.get("boot", False)),
                        "name": vol_name,
                    }
                )

            if not any(d.get("boot") for d in disk_specs + cd_specs):
                if disk_specs:
                    disk_specs[0]["boot"] = True
                elif cd_specs:
                    cd_specs[0]["boot"] = True

            disk_bus_index = 0
            cd_bus_index = 0

            def _next_disk_target() -> str:
                nonlocal disk_bus_index
                target = f"vd{chr(ord('a') + disk_bus_index)}"
                disk_bus_index += 1
                return target

            def _next_cd_target() -> str:
                nonlocal cd_bus_index
                target = f"sd{chr(ord('a') + cd_bus_index)}"
                cd_bus_index += 1
                return target

            memory_kib = memory_mb * 1024

            devices_xml_parts = []
            for disk in disk_specs:
                devices_xml_parts.append(
                    (
                        "<disk type='file' device='disk'>"
                        "<driver name='qemu' type='{fmt}'/>"
                        "<source file='{path}'/>"
                        "<target dev='{target}' bus='virtio'/>"
                        "</disk>"
                    ).format(
                        fmt=disk.get("format", "qcow2"),
                        path=escape(disk["path"]),
                        target=_next_disk_target(),
                    )
                )

            for cd in cd_specs:
                devices_xml_parts.append(
                    (
                        "<disk type='file' device='cdrom'>"
                        "<driver name='qemu' type='raw'/>"
                        "<source file='{path}'/>"
                        "<target dev='{target}' bus='sata'/>"
                        "<readonly/>"
                        "</disk>"
                    ).format(
                        path=escape(cd["path"]),
                        target=_next_cd_target(),
                    )
                )

            for iface in networks:
                network_name = iface.get("network")
                if not network_name:
                    raise StorageError("Network interface requires a network name")
                mac_addr = iface.get("mac")
                model_type = iface.get("model") or "virtio"
                iface_parts = ["<interface type='network'>", f"<source network='{escape(network_name)}'/>"]
                if mac_addr:
                    iface_parts.append(f"<mac address='{escape(mac_addr)}'/>")
                iface_parts.append(f"<model type='{escape(model_type)}'/>")
                if str(model_type).startswith("virtio"):
                    queue_count = max(min(vcpus, _MAX_VHOST_QUEUES), 1)
                    iface_parts.append(f"<driver name='vhost' queues='{queue_count}'/>")
                iface_parts.append("<link state='up'/>")
                if _DEFAULT_INTERFACE_MTU:
                    iface_parts.append(f"<mtu size='{_DEFAULT_INTERFACE_MTU}'/>")
                iface_parts.append("</interface>")
                devices_xml_parts.append("".join(iface_parts))

            if vnc_enabled:
                graphics_attrs = {
                    "type": "vnc",
                    "port": "-1",
                    "autoport": "yes",
                }
                if normalized_vnc_password:
                    graphics_attrs["passwd"] = normalized_vnc_password
                attr_text = " ".join(
                    f"{key}='{escape(str(value))}'" for key, value in graphics_attrs.items()
                )
                devices_xml_parts.append(f"<graphics {attr_text}/>")
            devices_xml_parts.append("<controller type='virtio-serial'/>")
            devices_xml_parts.append(
                "<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>"
            )
            devices_xml_parts.append(
                "<console type='pty'><target type='serial' port='0'/></console>"
            )

            os_boot_entries = []
            disk_boot = any(d.get("boot") for d in disk_specs)
            cd_boot = any(cd.get("boot") for cd in cd_specs)
            if disk_specs and (disk_boot or cd_boot):
                os_boot_entries.append("<boot dev='hd'/>")
            if cd_boot:
                os_boot_entries.append("<boot dev='cdrom'/>")
            if not os_boot_entries:
                if disk_specs:
                    os_boot_entries.append("<boot dev='hd'/>")
                elif cd_specs:
                    os_boot_entries.append("<boot dev='cdrom'/>")
                else:
                    os_boot_entries.append("<boot dev='hd'/>")

            description_fragment = (
                f"<description>{escape(description)}</description>" if description else ""
            )

            if normalized_cpu_mode == "host-passthrough":
                cpu_xml = "<cpu mode='host-passthrough' check='none'/>"
            else:
                cpu_xml = "<cpu mode='host-model'/>"

            domain_xml = (
                "<domain type='kvm'>"
                "<name>{name}</name>"
                "{description}"
                "<memory unit='KiB'>{memory}</memory>"
                "<currentMemory unit='KiB'>{memory}</currentMemory>"
                "<vcpu placement='static'>{vcpus}</vcpu>"
                "<os><type arch='x86_64' machine='q35'>hvm</type>{boot}</os>"
                "{cpu}"
                "<features><acpi/><apic/><pae/></features>"
                "<clock offset='utc'/><on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>restart</on_crash>"
                "<devices>{devices}</devices>"
                "</domain>"
            ).format(
                name=escape(name),
                description=description_fragment,
                memory=memory_kib,
                vcpus=vcpus,
                boot="".join(os_boot_entries),
                cpu=cpu_xml,
                devices="".join(devices_xml_parts),
            )

            domain = self._host.conn.defineXML(domain_xml)  # type: ignore[union-attr]
            if domain is None:
                raise StorageError("Failed to define domain")

            try:
                domain.setAutostart(bool(autostart))
            except libvirt.libvirtError as exc:
                logger.debug("Failed to set autostart for %s: %s", name, exc)

            if start:
                try:
                    domain.create()
                except libvirt.libvirtError as exc:
                    logger.error(
                        "Failed to start domain %s on %s: %s",
                        name,
                        self._host.hostname,
                        exc,
                    )
                    raise StorageError(f"Failed to start domain '{name}': {exc}") from exc

            details = self._resolve_details(name)
            result = {
                "host": self._host.hostname,
                "domain": name,
            }
            if details is not None:
                result["details"] = details
            return result
        except Exception:
            for pool, vol in created_volumes:
                try:
                    vol_name = vol.name()
                except libvirt.libvirtError:
                    vol_name = "?"
                try:
                    vol.delete(getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0))
                    pool.refresh(0)
                except libvirt.libvirtError:
                    logger.warning(
                        "Failed to clean up volume %s in pool %s during guest creation rollback",
                        vol_name,
                        pool.name(),
                    )
            raise

    def define_guest_from_xml(
        self,
        xml: str,
        *,
        start: bool = False,
        autostart: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if not xml or not xml.strip():
            raise StorageError("Domain XML is required to define a guest")
        if not self._host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {self._host.hostname}")

        try:
            domain = self._host.conn.defineXML(xml)  # type: ignore[union-attr]
        except libvirt.libvirtError as exc:
            logger.error("defineXML failed on %s: %s", self._host.hostname, exc)
            raise StorageError(f"Failed to define domain: {exc}") from exc

        if autostart is not None:
            try:
                domain.setAutostart(1 if autostart else 0)
            except libvirt.libvirtError as exc:
                logger.debug("setAutostart failed for %s on %s: %s", domain.name(), self._host.hostname, exc)

        started = False
        if start:
            try:
                domain.create()
                started = True
            except libvirt.libvirtError as exc:
                logger.error("Failed to start domain %s on %s after define: %s", domain.name(), self._host.hostname, exc)
                raise StorageError(f"Domain defined but failed to start: {exc}") from exc

        uuid_text = None
        try:
            uuid_text = domain.UUIDString()
        except libvirt.libvirtError:
            uuid_text = None

        details = None
        if self._detail_resolver:
            try:
                details = self._detail_resolver(domain.name())
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.debug("detail resolver failed for %s on %s: %s", domain.name(), self._host.hostname, exc)

        result: Dict[str, Any] = {
            "host": self._host.hostname,
            "domain": domain.name(),
            "uuid": uuid_text,
            "started": started,
        }
        if details is not None:
            result["details"] = details
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _assert_shared_storage(self, xml_desc: str) -> None:
        try:
            root = ET.fromstring(xml_desc)
        except ET.ParseError as exc:
            raise StorageError(f"Failed to parse domain XML for shared storage check: {exc}") from exc

        non_shared: List[str] = []
        for disk in root.findall("./devices/disk"):
            device_type = (disk.get("device") or "").lower()
            if device_type != "disk":
                continue
            source = disk.find("source")
            if source is None:
                continue
            disk_type = (disk.get("type") or "").lower()
            if disk_type == "network" or source.get("protocol"):
                continue

            pool_name = source.get("pool")
            if pool_name:
                try:
                    pool = self._host.conn.storagePoolLookupByName(pool_name)  # type: ignore[union-attr]
                except libvirt.libvirtError:
                    pool = None
                pool_type = _detect_pool_type(pool) if pool is not None else None
                if pool_type in _SHARED_STORAGE_POOL_TYPES:
                    continue
                non_shared.append(f"{pool_name} (pool type {pool_type or 'unknown'})")
                continue

            path = source.get("file") or source.get("dev")
            if not path:
                non_shared.append("unresolved disk source")
                continue
            pool = self._resolve_pool_for_path(path)
            pool_type = _detect_pool_type(pool) if pool is not None else None
            if pool_type in _SHARED_STORAGE_POOL_TYPES:
                continue
            non_shared.append(f"{path} (pool type {pool_type or 'unknown'})")

        if non_shared:
            allowed = ", ".join(sorted(_SHARED_STORAGE_POOL_TYPES))
            joined = "; ".join(non_shared)
            raise StorageError(
                "Live migration requires shared storage; non-shared disks: "
                f"{joined}. Allowed pool types: {allowed}."
            )

    def _resolve_pool_for_path(self, path: str) -> Optional[libvirt.virStoragePool]:
        try:
            volume = self._host.conn.storageVolLookupByPath(path)  # type: ignore[union-attr]
        except libvirt.libvirtError:
            return None
        return self._resolve_pool_for_volume(volume, path)

    def _resolve_pool_for_volume(
        self,
        volume: libvirt.virStorageVol,
        path: str,
    ) -> Optional[libvirt.virStoragePool]:
        pool = None
        lookup_by_volume = getattr(self._host.conn, "storagePoolLookupByVolume", None)  # type: ignore[union-attr]
        if lookup_by_volume:
            try:
                pool = lookup_by_volume(volume)
            except libvirt.libvirtError:
                pool = None

        if pool is not None:
            return pool

        pool_names: List[str] = []
        try:
            pool_names.extend(self._host.conn.listStoragePools() or [])  # type: ignore[union-attr]
            pool_names.extend(self._host.conn.listDefinedStoragePools() or [])  # type: ignore[union-attr]
        except libvirt.libvirtError as exc:
            logger.debug("Failed to enumerate pools on %s: %s", self._host.hostname, exc)

        for pool_name in pool_names:
            try:
                candidate_pool = self._host.conn.storagePoolLookupByName(pool_name)  # type: ignore[union-attr]
            except libvirt.libvirtError:
                continue

            candidate_volume = None
            pool_lookup_by_path = getattr(candidate_pool, "storageVolLookupByPath", None)
            if callable(pool_lookup_by_path):
                try:
                    candidate_volume = pool_lookup_by_path(path)
                except libvirt.libvirtError:
                    candidate_volume = None

            if candidate_volume is None:
                pool_lookup_by_name = getattr(candidate_pool, "storageVolLookupByName", None)
                if callable(pool_lookup_by_name):
                    fallback_name = os.path.basename(path)
                    if fallback_name:
                        try:
                            candidate_volume = pool_lookup_by_name(fallback_name)
                        except libvirt.libvirtError:
                            candidate_volume = None

            if candidate_volume is not None:
                return candidate_pool

        return None

    def _resolve_details(self, name: str) -> Optional[Dict[str, Any]]:
        if not self._detail_resolver:
            return None
        try:
            return self._detail_resolver(name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Failed to resolve domain details for %s: %s", name, exc)
            return None
