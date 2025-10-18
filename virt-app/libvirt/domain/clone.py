from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

import libvirt

from ..errors import StorageError
from ..storage import _detect_pool_type

if TYPE_CHECKING:
    from ..host import LibvirtHost

logger = logging.getLogger(__name__)


@dataclass
class DiskCloneRequest:
    pool: libvirt.virStoragePool
    source_volume: libvirt.virStorageVol
    pool_name: str
    new_volume_name: str
    capacity_bytes: int
    volume_type: str
    volume_format: str
    boot: bool


@dataclass
class IsoAttachment:
    pool_name: str
    volume_name: str
    source_path: str
    boot: bool


@dataclass
class DomainClonePlan:
    disks: List[DiskCloneRequest]
    isos: List[IsoAttachment]
    networks: List[Dict[str, Any]]
    mac_addresses: List[str]
    vnc_enabled: bool
    vnc_password: Optional[str]


@dataclass
class DomainCloneArtifacts:
    disk_specs: List[Dict[str, Any]]
    cd_specs: List[Dict[str, Any]]
    network_specs: List[Dict[str, Any]]
    mac_addresses: List[str]
    vnc_enabled: bool
    vnc_password: Optional[str]
    cloned_volumes: List[Tuple[libvirt.virStoragePool, libvirt.virStorageVol]]


class LibvirtDomainClonePlanner:
    """Derives disk/network plans for cloning a libvirt domain."""

    def __init__(self, host: "LibvirtHost") -> None:
        self._host = host

    def build_plan(
        self,
        *,
        source_domain: "libvirt.virDomain",
        source_name: str,
        new_name: str,
        xml_root: ET.Element,
    ) -> DomainClonePlan:
        disk_requests: List[DiskCloneRequest] = []
        iso_attachments: List[IsoAttachment] = []
        network_specs: List[Dict[str, Any]] = []
        mac_addresses: List[str] = []

        def _unique_volume_name(pool: libvirt.virStoragePool, base: str, extension: str) -> str:
            candidate = f"{base}{extension}"
            counter = 1
            while True:
                try:
                    pool.storageVolLookupByName(candidate)
                except libvirt.libvirtError:
                    return candidate
                candidate = f"{base}-{counter}{extension}"
                counter += 1

        disk_index = 0
        for disk_node in xml_root.findall("./devices/disk"):
            device_type = (disk_node.get("device") or "").lower()
            source = disk_node.find("source")
            if source is None:
                continue
            path = source.get("file") or source.get("dev")
            if not path:
                continue
            driver = disk_node.find("driver")
            fmt = (driver.get("type") if driver is not None else None) or "qcow2"
            boot_node = disk_node.find("boot")
            boot_flag = False
            if boot_node is not None:
                order = boot_node.get("order")
                boot_flag = order is None or order == "1"

            if device_type == "disk":
                pool, volume = self._host.storage.lookup_volume_by_path(path)
                pool_name = pool.name()
                try:
                    volume_info = volume.info()
                    capacity_bytes = int(volume_info[1]) if len(volume_info) > 1 else None
                except libvirt.libvirtError as exc:
                    raise StorageError(
                        f"Failed to inspect source volume for '{source_name}': {exc}"
                    ) from exc
                if not capacity_bytes or capacity_bytes <= 0:
                    raise StorageError(
                        f"Source volume for '{source_name}' reported invalid capacity"
                    )

                target = disk_node.find("target")
                target_dev = (target.get("dev") if target is not None else None) or f"disk{disk_index}"
                disk_index += 1

                base_name = f"{new_name}-{target_dev}"
                original_basename = os.path.basename(path) or target_dev
                _, extension = os.path.splitext(original_basename)
                volume_type = self._host.storage.infer_volume_type(_detect_pool_type(pool))
                new_volume_name = _unique_volume_name(pool, base_name, extension)

                disk_requests.append(
                    DiskCloneRequest(
                        pool=pool,
                        source_volume=volume,
                        pool_name=pool_name,
                        new_volume_name=new_volume_name,
                        capacity_bytes=capacity_bytes,
                        volume_type=volume_type,
                        volume_format=fmt,
                        boot=boot_flag,
                    )
                )
            elif device_type == "cdrom":
                try:
                    pool, volume = self._host.storage.lookup_volume_by_path(path)
                    pool_name = pool.name()
                    volume_name = volume.name()
                except StorageError:
                    raise StorageError(
                        f"Unable to resolve ISO volume backing '{path}' for '{source_name}'"
                    ) from None

                iso_attachments.append(
                    IsoAttachment(
                        pool_name=pool_name,
                        volume_name=volume_name,
                        source_path=path,
                        boot=boot_flag,
                    )
                )

        if not disk_requests:
            raise StorageError("Cloning requires at least one disk volume")

        for iface in xml_root.findall("./devices/interface"):
            iface_type = (iface.get("type") or "").lower()
            if iface_type != "network":
                continue
            source_node = iface.find("source")
            if source_node is None:
                continue
            network_name = source_node.get("network")
            if not network_name:
                continue
            model_node = iface.find("model")
            model_type = model_node.get("type") if model_node is not None else None
            mac_address = self._host._generate_random_mac()  # pylint: disable=protected-access
            mac_addresses.append(mac_address)
            network_specs.append(
                {
                    "network": network_name,
                    "mac": mac_address,
                    "model": model_type,
                }
            )

        graphics_node = xml_root.find("./devices/graphics[@type='vnc']")
        vnc_enabled = graphics_node is not None
        clone_vnc_password: Optional[str] = None
        if vnc_enabled:
            clone_vnc_password = self._host._generate_vnc_password(8)  # pylint: disable=protected-access

        return DomainClonePlan(
            disks=disk_requests,
            isos=iso_attachments,
            networks=network_specs,
            mac_addresses=mac_addresses,
            vnc_enabled=vnc_enabled,
            vnc_password=clone_vnc_password,
        )


class LibvirtDomainCloneExecutor:
    """Executes a domain clone plan, cloning disks and returning specs."""

    def __init__(self, host: "LibvirtHost") -> None:
        self._host = host

    def execute(self, plan: DomainClonePlan) -> DomainCloneArtifacts:
        cloned_volumes: List[Tuple[libvirt.virStoragePool, libvirt.virStorageVol]] = []
        disk_specs: List[Dict[str, Any]] = []

        try:
            for request in plan.disks:
                volume_xml = self._host.storage.build_volume_xml(
                    request.new_volume_name,
                    request.capacity_bytes,
                    volume_type=request.volume_type,
                    volume_format=request.volume_format,
                )

                try:
                    new_volume = request.pool.createXMLFrom(
                        volume_xml,
                        request.source_volume,
                        0,
                    )
                    request.pool.refresh(0)
                except libvirt.libvirtError as exc:
                    raise StorageError(
                        f"Failed to clone volume '{request.new_volume_name}' in pool '{request.pool_name}': {exc}"
                    ) from exc

                cloned_volumes.append((request.pool, new_volume))

                try:
                    new_path = new_volume.path()
                except libvirt.libvirtError as exc:
                    raise StorageError(
                        f"Failed to determine path for cloned volume '{request.new_volume_name}': {exc}"
                    ) from exc

                disk_specs.append(
                    {
                        "name": request.new_volume_name,
                        "pool": request.pool_name,
                        "type": "disk",
                        "source_path": new_path,
                        "format": request.volume_format,
                        "boot": request.boot,
                    }
                )
        except Exception:
            self._cleanup_volumes(cloned_volumes)
            raise

        cd_specs: List[Dict[str, Any]] = [
            {
                "name": iso.volume_name,
                "pool": iso.pool_name,
                "type": "iso",
                "source_path": iso.source_path,
                "boot": iso.boot,
            }
            for iso in plan.isos
        ]

        return DomainCloneArtifacts(
            disk_specs=disk_specs,
            cd_specs=cd_specs,
            network_specs=plan.networks,
            mac_addresses=plan.mac_addresses,
            vnc_enabled=plan.vnc_enabled,
            vnc_password=plan.vnc_password,
            cloned_volumes=cloned_volumes,
        )

    def cleanup(self, artifacts: DomainCloneArtifacts) -> None:
        self._cleanup_volumes(artifacts.cloned_volumes)

    def _cleanup_volumes(
        self,
        volumes: List[Tuple[libvirt.virStoragePool, libvirt.virStorageVol]],
    ) -> None:
        delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
        for pool, volume in volumes:
            try:
                volume_name = volume.name()
            except libvirt.libvirtError:
                volume_name = "?"
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
            except libvirt.libvirtError as exc:
                logger.warning(
                    "Failed to clean up cloned volume %s in pool %s on %s: %s",
                    volume_name,
                    pool_name,
                    self._host.hostname,
                    exc,
                )
