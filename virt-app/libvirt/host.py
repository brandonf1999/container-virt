import os
import time
import logging
import secrets
import string
import shlex
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode
from xml.sax.saxutils import escape

import libvirt

from .networking import gather_host_network_inventory
from .storage import gather_host_storage_inventory, _derive_volume_state, _detect_pool_type

logger = logging.getLogger(__name__)

# Register default event loop once (prevents keepalive error)
try:
    libvirt.virEventRegisterDefaultImpl()
except Exception:
    pass

# Known CPU time fields returned by libvirt (values in nanoseconds)
_CPU_TIME_FIELDS = {
    "kernel",
    "user",
    "idle",
    "iowait",
    "other",
    "nice",
    "system",
    "steal",
}

_POOL_STATE_LABELS = {
    getattr(libvirt, "VIR_STORAGE_POOL_INACTIVE", None): "inactive",
    getattr(libvirt, "VIR_STORAGE_POOL_BUILDING", None): "building",
    getattr(libvirt, "VIR_STORAGE_POOL_RUNNING", None): "running",
    getattr(libvirt, "VIR_STORAGE_POOL_DEGRADED", None): "degraded",
    getattr(libvirt, "VIR_STORAGE_POOL_INACCESSIBLE", None): "inaccessible",
}


_PASSWORD_ALPHABET = string.ascii_letters + string.digits


_RECOVERABLE_LIBVIRT_ERRORS = {
    "broken pipe",
    "end of file",
    "client socket",
    "transport endpoint",
    "connection closed",
}


def _should_retry_libvirt_error(exc: "libvirt.libvirtError") -> bool:
    try:
        message = str(exc).lower()
    except Exception:
        return False
    return any(token in message for token in _RECOVERABLE_LIBVIRT_ERRORS)


def _kb_to_mb(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1024.0, 2)


def _ns_to_seconds(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1_000_000_000.0, 2)


def _map_pool_state(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return _POOL_STATE_LABELS.get(value, f"state:{value}")


class StorageError(RuntimeError):
    pass


class StoragePoolNotFoundError(StorageError):
    def __init__(self, pool: str):
        super().__init__(f"Storage pool '{pool}' not found")
        self.pool = pool


class StoragePoolNotEmptyError(StorageError):
    def __init__(self, pool: str, volumes: List[str]):
        joined = ", ".join(volumes)
        super().__init__(f"Storage pool '{pool}' still contains volume(s): {joined}")
        self.pool = pool
        self.volumes = volumes


class StorageVolumeNotFoundError(StorageError):
    def __init__(self, pool: str, volume: str):
        super().__init__(f"Volume '{volume}' not found in pool '{pool}'")
        self.pool = pool
        self.volume = volume


class StorageVolumeInUseError(StorageError):
    def __init__(self, pool: str, volume: str, domains: List[str]):
        joined = ", ".join(domains)
        super().__init__(
            f"Volume '{volume}' in pool '{pool}' is attached to running domain(s): {joined}"
        )
        self.pool = pool
        self.volume = volume
        self.domains = domains


class StorageVolumeExistsError(StorageError):
    def __init__(self, pool: str, volume: str):
        super().__init__(f"Volume '{volume}' already exists in pool '{pool}'")
        self.pool = pool
        self.volume = volume


class DomainExistsError(StorageError):
    def __init__(self, name: str):
        super().__init__(f"Domain '{name}' already exists")
        self.name = name


class DomainNotFoundError(StorageError):
    def __init__(self, name: str):
        super().__init__(f"Domain '{name}' not found")
        self.name = name


class DomainActiveError(StorageError):
    def __init__(self, name: str):
        super().__init__(
            f"Domain '{name}' is currently running; stop it first or request a forced deletion"
        )
        self.name = name


class DomainNotRunningError(StorageError):
    def __init__(self, name: str):
        super().__init__(f"Domain '{name}' is not currently running")
        self.name = name


class DomainDeviceNotFoundError(StorageError):
    def __init__(self, name: str, device: str):
        super().__init__(f"Device '{device}' not found on domain '{name}'")
        self.name = name
        self.device = device


class LibvirtHost:
    """Manages a single libvirt host connection over SSH."""

    def __init__(self, hostname: str, user: Optional[str] = None, ssh_opts: Optional[Dict] = None):
        self.hostname = hostname
        self.user = user
        self.ssh_opts = ssh_opts or {}
        self.conn: Optional[libvirt.virConnect] = None
        self._cpu_sample: Optional[Tuple[Dict[str, int], float]] = None

    def _generate_password(self, length: int = 8) -> str:
        return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(max(1, length)))

    @property
    def uri(self) -> str:
        base = f"qemu+ssh://{self.user+'@' if self.user else ''}{self.hostname}/system"
        # Only include supported ssh params; ignore empties
        query = {}
        khv = self.ssh_opts.get("known_hosts_verify")
        if khv in {"normal", "auto", "ignore"}:
            query["known_hosts_verify"] = khv
        # You could optionally support a custom known_hosts file:
        kh_path = self.ssh_opts.get("known_hosts")
        if kh_path:
            query["known_hosts"] = kh_path
        return f"{base}?{urlencode(query)}" if query else base

    def connect(self) -> bool:
        try:
            logger.info("Connecting to %s", self.uri)
            self.conn = libvirt.open(self.uri)
            if self.conn is None:
                logger.error("Failed to connect to %s", self.hostname)
                return False
            logger.info("Connected to %s", self.hostname)
            # Prime the CPU sample so the next metrics call has a baseline
            self._prime_cpu_sample()
            return True
        except libvirt.libvirtError as e:
            logger.error("Connection to %s failed: %s", self.hostname, e)
            return False

    def disconnect(self):
        if self.conn:
            logger.info("Disconnecting from %s", self.hostname)
            self.conn.close()
            self.conn = None
        self._cpu_sample = None

    def _lookup_domain(self, name: str) -> "libvirt.virDomain":
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")
        try:
            return self.conn.lookupByName(name)
        except libvirt.libvirtError as exc:
            if _should_retry_libvirt_error(exc):
                logger.warning(
                    "lookupByName(%s) on %s failed (%s); attempting reconnect",
                    name,
                    self.hostname,
                    exc,
                )
                self.disconnect()
                if self.connect():
                    try:
                        return self.conn.lookupByName(name)
                    except libvirt.libvirtError as retry_exc:
                        logger.error(
                            "lookupByName(%s) retry failed on %s: %s",
                            name,
                            self.hostname,
                            retry_exc,
                        )
                        raise
                else:
                    logger.error(
                        "Reconnection attempt failed for %s prior to retrying domain lookup",
                        self.hostname,
                    )
            logger.error("lookupByName(%s) failed on %s: %s", name, self.hostname, exc)
            raise

    def start_domain(self, name: str) -> bool:
        try:
            domain = self._lookup_domain(name)
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s during connect: %s", name, self.hostname, exc)
            raise DomainNotFoundError(name) from exc
        try:
            domain.create()
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to start domain %s on %s: %s", name, self.hostname, exc)
            return False

    def shutdown_domain(self, name: str) -> bool:
        domain = self._lookup_domain(name)
        try:
            domain.shutdown()
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to shutdown domain %s on %s: %s", name, self.hostname, exc)
            return False

    def reboot_domain(self, name: str) -> bool:
        domain = self._lookup_domain(name)
        try:
            domain.reboot(libvirt.VIR_DOMAIN_REBOOT_DEFAULT)
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to reboot domain %s on %s: %s", name, self.hostname, exc)
            return False

    def destroy_domain(self, name: str) -> bool:
        domain = self._lookup_domain(name)
        try:
            domain.destroy()
            return True
        except libvirt.libvirtError as exc:
            logger.error("Failed to force stop domain %s on %s: %s", name, self.hostname, exc)
            return False

    def _ensure_connection(self) -> bool:
        """Ensure the libvirt connection is alive, reconnecting if needed."""
        if self.conn is not None:
            try:
                if hasattr(self.conn, "isAlive") and self.conn.isAlive():
                    return True
            except libvirt.libvirtError as exc:
                logger.debug("Connection liveness check failed for %s: %s", self.hostname, exc)

        # Stale or missing connection; attempt reconnect.
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            finally:
                self.conn = None

        return self.connect()

    def list_vms(self):
        if not self.conn:
            raise RuntimeError(f"Not connected to {self.hostname}")
        domains = []
        for dom_id in self.conn.listDomainsID():
            dom = self.conn.lookupByID(dom_id)
            domains.append(dom.name())
        for name in self.conn.listDefinedDomains():
            domains.append(name)
        return domains

    def get_host_info(self):
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")
        info = self.conn.getInfo()
        metrics = self.get_resource_utilization()
        return {
            "hostname": self.hostname,
            "memory_MB": info[1],
            "cpus": info[2],
            "arch": info[0],
            "uri": self.uri,
            "metrics": metrics,
        }

    # ------------------------------------------------------------------
    # Resource utilisation helpers
    # ------------------------------------------------------------------
    def get_resource_utilization(self) -> Dict:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")

        cpu_metrics = self._compute_cpu_metrics()
        memory_metrics = self._compute_memory_metrics()
        return {
            "cpu": cpu_metrics,
            "memory": memory_metrics,
        }

    def get_network_inventory(self) -> Dict:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")
        return gather_host_network_inventory(self.conn)

    def get_storage_inventory(self) -> Dict:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")
        return gather_host_storage_inventory(self.conn)

    def _lookup_storage_pool(self, pool_name: str):
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")
        if not self.conn:
            raise RuntimeError(f"Not connected to {self.hostname}")

        try:
            pool = self.conn.storagePoolLookupByName(pool_name)
        except libvirt.libvirtError as exc:
            logger.debug("storagePoolLookupByName(%s) failed on %s: %s", pool_name, self.hostname, exc)
            if _should_retry_libvirt_error(exc):
                logger.warning(
                    "storagePoolLookupByName(%s) failed on %s (%s); attempting reconnect",
                    pool_name,
                    self.hostname,
                    exc,
                )
                self.disconnect()
                if self.connect():
                    try:
                        pool = self.conn.storagePoolLookupByName(pool_name)
                    except libvirt.libvirtError as retry_exc:
                        logger.error(
                            "storagePoolLookupByName(%s) retry failed on %s: %s",
                            pool_name,
                            self.hostname,
                            retry_exc,
                        )
                    else:
                        try:
                            pool.refresh(0)
                        except libvirt.libvirtError as refresh_exc:
                            logger.debug(
                                "refresh(%s) failed on %s after reconnect: %s",
                                pool_name,
                                self.hostname,
                                refresh_exc,
                            )
                        return pool
                else:
                    logger.error(
                        "Reconnection attempt failed for %s prior to storage pool lookup",
                        self.hostname,
                    )
            raise StoragePoolNotFoundError(pool_name) from exc

        try:
            pool.refresh(0)
        except libvirt.libvirtError as exc:
            logger.debug("refresh(%s) failed on %s: %s", pool_name, self.hostname, exc)

        return pool

    def _lookup_storage_volume(self, pool_name: str, volume_name: str):
        pool = self._lookup_storage_pool(pool_name)

        try:
            volume = pool.storageVolLookupByName(volume_name)
        except libvirt.libvirtError as exc:
            logger.debug(
                "storageVolLookupByName(%s) failed in pool %s on %s: %s",
                volume_name,
                pool_name,
                self.hostname,
                exc,
            )
            raise StorageVolumeNotFoundError(pool_name, volume_name) from exc

        return pool, volume

    def _collect_running_domain_disk_sources(self) -> Dict[str, Set[str]]:
        references: Dict[str, Set[str]] = {}
        if not self.conn:
            return references

        try:
            domain_ids = self.conn.listDomainsID()
        except libvirt.libvirtError as exc:
            logger.debug("listDomainsID failed on %s: %s", self.hostname, exc)
            return references

        for dom_id in domain_ids or []:
            try:
                domain = self.conn.lookupByID(dom_id)
            except libvirt.libvirtError as exc:
                logger.debug("lookupByID(%s) failed on %s: %s", dom_id, self.hostname, exc)
                continue

            domain_name = domain.name()
            try:
                xml_desc = domain.XMLDesc(0)
            except libvirt.libvirtError as exc:
                logger.debug("XMLDesc failed for domain %s on %s: %s", domain_name, self.hostname, exc)
                continue

            try:
                root = ET.fromstring(xml_desc)
            except ET.ParseError as exc:
                logger.debug("Failed to parse XML for domain %s on %s: %s", domain_name, self.hostname, exc)
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
            logger.debug("info() failed for volume %s/%s on %s: %s", pool_name, volume_name, self.hostname, exc)
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
            logger.debug("path() failed for volume %s/%s on %s: %s", pool_name, volume_name, self.hostname, exc)

        volume_key = None
        try:
            volume_key = volume.key()
        except libvirt.libvirtError as exc:
            logger.debug("key() failed for volume %s/%s on %s: %s", pool_name, volume_name, self.hostname, exc)

        xml_desc = None
        try:
            xml_desc = volume.XMLDesc(0)
        except libvirt.libvirtError as exc:
            logger.debug("XMLDesc failed for volume %s/%s on %s: %s", pool_name, volume_name, self.hostname, exc)

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
                logger.debug("Failed to parse storage volume XML for %s/%s: %s", pool_name, volume_name, exc)

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
            logger.debug("info() failed for pool %s on %s: %s", pool_name, self.hostname, exc)

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
            "host": self.hostname,
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
                    context=f"{self.hostname}:{pool_name}/{volume_name}",
                ),
            },
            "attached_domains": consumers,
        }

        if xml_desc:
            summary["xml"] = xml_desc

        return summary

    def describe_storage_volume(self, pool_name: str, volume_name: str) -> Dict[str, Any]:
        pool, volume = self._lookup_storage_volume(pool_name, volume_name)
        return self._summarize_storage_volume(pool_name, volume_name, pool, volume)

    def delete_storage_volume(self, pool_name: str, volume_name: str, *, force: bool = False) -> Dict[str, Any]:
        pool, volume = self._lookup_storage_volume(pool_name, volume_name)
        details = self._summarize_storage_volume(pool_name, volume_name, pool, volume)

        conflicts = details.get("attached_domains") or []
        if conflicts and not force:
            raise StorageVolumeInUseError(pool_name, volume_name, conflicts)

        delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
        try:
            volume.delete(delete_flags)
        except libvirt.libvirtError as exc:
            logger.error("Failed to delete volume %s/%s on %s: %s", pool_name, volume_name, self.hostname, exc)
            raise StorageError(
                f"Failed to delete volume '{volume_name}' in pool '{pool_name}': {exc}"
            ) from exc

        try:
            pool.refresh(0)
        except libvirt.libvirtError as exc:
            logger.debug("refresh(%s) after delete failed on %s: %s", pool_name, self.hostname, exc)

        return {
            "host": self.hostname,
            "pool": pool_name,
            "volume": volume_name,
            "path": details.get("volume", {}).get("path"),
            "capacity_bytes": details.get("volume", {}).get("capacity_bytes"),
            "allocation_bytes": details.get("volume", {}).get("allocation_bytes"),
            "deleted": True,
            "force": force,
            "attached_domains": conflicts,
        }

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

    @staticmethod
    def _generate_vnc_password(length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(max(length, 8)))

    @staticmethod
    def _generate_random_mac() -> str:
        # Locally administered unicast MAC (x2:xx:xx:xx:xx:xx)
        first_octet = 0x02
        octets = [first_octet] + [secrets.randbits(8) for _ in range(5)]
        return ":".join(f"{value:02x}" for value in octets)

    def _lookup_volume_by_path(
        self,
        path: str,
    ) -> Tuple["libvirt.virStoragePool", "libvirt.virStorageVol"]:
        if not self.conn:
            raise StorageError("Not connected to host")

        try:
            volume = self.conn.storageVolLookupByPath(path)
        except libvirt.libvirtError as exc:
            logger.debug("storageVolLookupByPath(%s) failed on %s: %s", path, self.hostname, exc)
            volume = None

        pool = None
        if volume is not None:
            lookup_pool = getattr(self.conn, "storagePoolLookupByVolume", None)
            if callable(lookup_pool):
                try:
                    pool = lookup_pool(volume)
                except libvirt.libvirtError:
                    pool = None

        if pool is None or volume is None:
            pool_names: List[str] = []
            try:
                pool_names.extend(self.conn.listStoragePools() or [])
                pool_names.extend(self.conn.listDefinedStoragePools() or [])
            except libvirt.libvirtError as exc:
                logger.debug("Failed to enumerate storage pools on %s: %s", self.hostname, exc)

            for pool_name in pool_names:
                try:
                    candidate_pool = self.conn.storagePoolLookupByName(pool_name)
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
                f"Unable to resolve storage volume for path '{path}' on {self.hostname}"
            )

        return pool, volume

    def upload_storage_volume(
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
                    self.hostname,
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
                self.hostname,
                exc,
            )
            raise StorageError(f"Failed to create volume '{volume_name}': {exc}") from exc

        stream = None
        try:
            if not self.conn:
                raise RuntimeError(f"Not connected to {self.hostname}")
            stream = self.conn.newStream(0)
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
                    self.hostname,
                    delete_exc,
                )
            raise StorageError(f"Failed to upload data to volume '{volume_name}': {exc}") from exc

        try:
            pool.refresh(0)
        except libvirt.libvirtError as exc:
            logger.debug(
                "refresh(%s) after upload failed on %s: %s",
                pool_name,
                self.hostname,
                exc,
            )

        result = self._summarize_storage_volume(pool_name, volume_name, pool, volume)
        result["upload"] = {
            "bytes": size_bytes,
            "overwrite": overwrite,
            "format": fmt,
        }
        return result

    def create_guest(
        self,
        name: str,
        *,
        vcpus: int,
        memory_mb: int,
        autostart: bool,
        start: bool,
        description: Optional[str],
        volumes: List[Dict[str, Any]],
        networks: List[Dict[str, Any]],
        enable_vnc: Optional[bool] = None,
        vnc_password: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")

        if not name:
            raise StorageError("Domain name is required")

        try:
            existing = self.conn.lookupByName(name)
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

        disk_specs = []
        cd_specs = []
        created_volumes: List[Tuple[libvirt.virStoragePool, libvirt.virStorageVol]] = []

        def _resolve_pool(pool_name: str) -> libvirt.virStoragePool:
            pool = self.conn.storagePoolLookupByName(pool_name)
            pool.refresh(0)
            return pool

        def _volume_path(pool: libvirt.virStoragePool, volume_name: str) -> str:
            volume = pool.storageVolLookupByName(volume_name)
            return volume.path()

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
                if existing_path:
                    path = existing_path
                    fmt = (spec.get("format") or "qcow2").lower()
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

                    volume_xml = self._build_volume_xml(
                        vol_name,
                        size_mb * 1024 * 1024,
                        volume_type=self._infer_volume_type(_detect_pool_type(pool)),
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
            devices_xml_parts.append(
                "<console type='pty'><target type='serial' port='0'/></console>"
            )

            os_boot_entries = []
            if any(d.get("boot") for d in disk_specs):
                os_boot_entries.append("<boot dev='hd'/>")
            if any(cd.get("boot") for cd in cd_specs):
                os_boot_entries.append("<boot dev='cdrom'/>")
            if not os_boot_entries:
                os_boot_entries.append("<boot dev='hd'/>")

            description_fragment = (
                f"<description>{escape(description)}</description>" if description else ""
            )

            domain_xml = (
                "<domain type='kvm'>"
                "<name>{name}</name>"
                "{description}"
                "<memory unit='KiB'>{memory}</memory>"
                "<currentMemory unit='KiB'>{memory}</currentMemory>"
                "<vcpu placement='static'>{vcpus}</vcpu>"
                "<os><type arch='x86_64' machine='q35'>hvm</type>{boot}</os>"
                "<cpu mode='host-passthrough' check='none'/>"
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
                devices="".join(devices_xml_parts),
            )

            domain = self.conn.defineXML(domain_xml)
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
                    logger.error("Failed to start domain %s on %s: %s", name, self.hostname, exc)
                    raise StorageError(f"Failed to start domain '{name}': {exc}") from exc

            details = self.get_domain_details(name)
            return {
                "host": self.hostname,
                "domain": name,
                "details": details,
            }
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

    def clone_guest(
        self,
        source_name: str,
        *,
        new_name: str,
        autostart: Optional[bool] = None,
        start: bool = False,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")

        try:
            source_domain = self.conn.lookupByName(source_name)
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s: %s", source_name, self.hostname, exc)
            raise DomainNotFoundError(source_name) from exc

        try:
            existing = self.conn.lookupByName(new_name)
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
            logger.error("info() failed for %s on %s: %s", source_name, self.hostname, exc)
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
            logger.error("XMLDesc failed for %s on %s: %s", source_name, self.hostname, exc)
            raise StorageError(f"Failed to read domain XML for '{source_name}': {exc}") from exc

        try:
            root = ET.fromstring(xml_desc)
        except ET.ParseError as exc:
            raise StorageError(f"Failed to parse domain XML for '{source_name}': {exc}") from exc

        if description is None:
            description = root.findtext("description")

        disk_specs: List[Dict[str, Any]] = []
        cd_specs: List[Dict[str, Any]] = []
        network_specs: List[Dict[str, Any]] = []
        cloned_volumes: List[Tuple[libvirt.virStoragePool, libvirt.virStorageVol]] = []
        new_mac_addresses: List[str] = []

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
        cd_index = 0

        for disk_node in root.findall("./devices/disk"):
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
                pool, volume = self._lookup_volume_by_path(path)
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
                volume_type = self._infer_volume_type(_detect_pool_type(pool))
                new_volume_name = _unique_volume_name(pool, base_name, extension)

                volume_xml = self._build_volume_xml(
                    new_volume_name,
                    capacity_bytes,
                    volume_type=volume_type,
                    volume_format=fmt,
                )

                try:
                    new_volume = pool.createXMLFrom(volume_xml, volume, 0)
                    pool.refresh(0)
                except libvirt.libvirtError as exc:
                    raise StorageError(
                        f"Failed to clone volume '{new_volume_name}' in pool '{pool_name}': {exc}"
                    ) from exc

                cloned_volumes.append((pool, new_volume))
                try:
                    new_path = new_volume.path()
                except libvirt.libvirtError as exc:
                    raise StorageError(
                        f"Failed to determine path for cloned volume '{new_volume_name}': {exc}"
                    ) from exc

                disk_specs.append(
                    {
                        "name": new_volume_name,
                        "pool": pool_name,
                        "type": "disk",
                        "source_path": new_path,
                        "format": fmt,
                        "boot": boot_flag,
                    }
                )
            elif device_type == "cdrom":
                try:
                    pool, volume = self._lookup_volume_by_path(path)
                    pool_name = pool.name()
                    volume_name = volume.name()
                except StorageError:
                    raise StorageError(
                        f"Unable to resolve ISO volume backing '{path}' for '{source_name}'"
                    )

                cd_index += 1
                cd_specs.append(
                    {
                        "name": volume_name,
                        "pool": pool_name,
                        "type": "iso",
                        "source_path": path,
                        "boot": boot_flag,
                    }
                )

        if not disk_specs:
            raise StorageError("Cloning requires at least one disk volume")

        for iface in root.findall("./devices/interface"):
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
            mac_address = self._generate_random_mac()
            new_mac_addresses.append(mac_address)
            network_specs.append(
                {
                    "network": network_name,
                    "mac": mac_address,
                    "model": model_type,
                }
            )

        graphics_node = root.find("./devices/graphics[@type='vnc']")
        vnc_enabled = graphics_node is not None
        clone_vnc_password: Optional[str] = None
        if vnc_enabled:
            clone_vnc_password = self._generate_vnc_password(16)

        volume_payload = disk_specs + cd_specs

        try:
            result = self.create_guest(
                new_name,
                vcpus=vcpus,
                memory_mb=memory_mb,
                autostart=bool(autostart),
                start=start,
                description=description,
                volumes=volume_payload,
                networks=network_specs,
                enable_vnc=vnc_enabled,
                vnc_password=clone_vnc_password,
            )
            result["clone"] = {
                "vnc_password": clone_vnc_password,
                "mac_addresses": new_mac_addresses,
            }
            return result
        except Exception:
            delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
            for pool, volume in cloned_volumes:
                try:
                    volume.delete(delete_flags)
                    pool.refresh(0)
                except libvirt.libvirtError as exc:
                    try:
                        vol_name = volume.name()
                    except libvirt.libvirtError:
                        vol_name = "?"
                    logger.warning(
                        "Failed to clean up cloned volume %s in pool %s on %s: %s",
                        vol_name,
                        pool.name(),
                        self.hostname,
                        exc,
                    )
            raise

    def delete_guest(self, name: str, *, force: bool = False, remove_storage: bool = False) -> Dict[str, Any]:
        try:
            domain = self._lookup_domain(name)
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s during delete: %s", name, self.hostname, exc)
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
                logger.debug("XMLDesc failed for %s on %s: %s", name, self.hostname, exc)
            except ET.ParseError as exc:
                logger.debug("Failed to parse domain XML for %s on %s: %s", name, self.hostname, exc)

        try:
            is_active = bool(domain.isActive())
        except libvirt.libvirtError:
            # Assume inactive if status cannot be retrieved
            is_active = False

        if is_active:
            if not force:
                raise DomainActiveError(name)
            try:
                domain.destroy()
            except libvirt.libvirtError as exc:
                logger.error("Failed to destroy active domain %s on %s: %s", name, self.hostname, exc)
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
            logger.error("Failed to undefine domain %s on %s: %s", name, self.hostname, exc)
            raise StorageError(f"Failed to remove domain '{name}': {exc}") from exc

        removed_volumes: List[Dict[str, Any]] = []
        if remove_storage and disk_source_paths:
            delete_flags = getattr(libvirt, "VIR_STORAGE_VOL_DELETE_NORMAL", 0)
            for path in disk_source_paths:
                try:
                    volume = self.conn.storageVolLookupByPath(path)
                except libvirt.libvirtError as exc:
                    logger.debug("Failed to lookup volume by path %s on %s: %s", path, self.hostname, exc)
                    continue

                pool = None
                lookup_by_volume = getattr(self.conn, "storagePoolLookupByVolume", None)
                if lookup_by_volume:
                    try:
                        pool = lookup_by_volume(volume)
                    except libvirt.libvirtError:
                        pool = None

                if pool is None:
                    pool_names: List[str] = []
                    try:
                        pool_names.extend(self.conn.listStoragePools() or [])
                        pool_names.extend(self.conn.listDefinedStoragePools() or [])
                    except libvirt.libvirtError as exc:
                        logger.debug("Failed to enumerate pools on %s: %s", self.hostname, exc)

                    for pool_name in pool_names:
                        try:
                            candidate_pool = self.conn.storagePoolLookupByName(pool_name)
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
                            pool = candidate_pool
                            volume = candidate_volume
                            break

                if pool is None:
                    logger.debug("Unable to resolve pool for volume path %s on %s", path, self.hostname)
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
                        logger.debug("refresh() failed for pool %s on %s after volume delete: %s", pool_name, self.hostname, refresh_exc)
                    removed_volumes.append({
                        "pool": pool_name,
                        "volume": volume_name,
                        "path": path,
                    })
                except libvirt.libvirtError as exc:
                    logger.warning(
                        "Failed to delete storage volume %s/%s (path=%s) on %s: %s",
                        pool_name,
                        volume_name,
                        path,
                        self.hostname,
                        exc,
                    )

        logger.info(
            "Deleted domain %s on %s (force=%s, was_active=%s, removed_volumes=%d)",
            name,
            self.hostname,
            force,
            is_active,
            len(removed_volumes),
        )
        return {
            "host": self.hostname,
            "domain": name,
            "removed": True,
            "forced": bool(force),
            "was_active": bool(is_active),
            "removed_volumes": removed_volumes,
        }

    def detach_guest_block_device(self, name: str, target: str) -> Dict[str, Any]:
        if not target:
            raise DomainDeviceNotFoundError(name, target)

        try:
            domain = self._lookup_domain(name)
        except libvirt.libvirtError as exc:
            raise DomainNotFoundError(name) from exc

        try:
            xml_flags = getattr(libvirt, "VIR_DOMAIN_XML_SECURE", 0) | getattr(libvirt, "VIR_DOMAIN_XML_INACTIVE", 0)
            domain_xml = domain.XMLDesc(xml_flags)
        except libvirt.libvirtError as exc:
            logger.error("XMLDesc failed for %s on %s: %s", name, self.hostname, exc)
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
            logger.error("detachDeviceFlags failed for %s (%s) on %s: %s", name, target, self.hostname, exc)
            raise StorageError(f"Failed to detach device '{target}' from domain '{name}': {exc}") from exc

        details = self.get_domain_details(name)
        return {
            "host": self.hostname,
            "domain": name,
            "details": details,
        }

    def delete_storage_pool(self, pool_name: str, *, force: bool = False) -> Dict[str, Any]:
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
            logger.debug("info() failed for pool %s on %s: %s", pool_name, self.hostname, exc)

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
            logger.debug("listVolumes() failed for pool %s on %s: %s", pool_name, self.hostname, exc)

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
                logger.error("Failed to destroy storage pool %s on %s: %s", pool_name, self.hostname, exc)
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
                logger.debug("delete() failed for pool %s on %s: %s", pool_name, self.hostname, exc)

        if persistent:
            try:
                pool.undefine()
            except libvirt.libvirtError as exc:
                logger.error("Failed to undefine storage pool %s on %s: %s", pool_name, self.hostname, exc)
                raise StorageError(
                    f"Failed to undefine storage pool '{pool_name}': {exc}"
                ) from exc

        return {
            "host": self.hostname,
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

    def generate_vnc_connection_file(self, name: str) -> Dict[str, Any]:
        domain = self._lookup_domain(name)

        try:
            info = domain.info()
        except libvirt.libvirtError as exc:
            logger.error("info() failed for %s on %s: %s", name, self.hostname, exc)
            raise StorageError(f"Failed to inspect domain '{name}': {exc}") from exc

        state_code = info[0] if isinstance(info, (list, tuple)) and info else None
        running_states: Set[int] = set()
        for attr in ("VIR_DOMAIN_RUNNING", "VIR_DOMAIN_BLOCKED"):
            value = getattr(libvirt, attr, None)
            if isinstance(value, int):
                running_states.add(value)
        if state_code not in running_states:
            raise DomainNotRunningError(name)

        xml_flags = 0
        for attr in ("VIR_DOMAIN_XML_SECURE", "VIR_DOMAIN_XML_ACTIVE"):
            xml_flags |= getattr(libvirt, attr, 0)

        try:
            xml_desc = domain.XMLDesc(xml_flags)
        except libvirt.libvirtError as exc:
            logger.error("XMLDesc() failed for %s on %s: %s", name, self.hostname, exc)
            raise StorageError(f"Failed to inspect graphics configuration for '{name}': {exc}") from exc

        try:
            root = ET.fromstring(xml_desc)
        except ET.ParseError as exc:
            logger.error("Failed to parse domain XML for %s on %s: %s", name, self.hostname, exc)
            raise StorageError(f"Unable to parse graphics configuration for '{name}'") from exc

        graphics = root.find("./devices/graphics[@type='vnc']")
        if graphics is None:
            raise StorageError(f"Domain '{name}' does not expose a VNC console")

        port_attr = graphics.get("port")
        port: Optional[int]
        try:
            port = int(port_attr) if port_attr is not None else None
        except ValueError:
            port = None
        if not port or port <= 0:
            raise StorageError(f"Domain '{name}' does not have an active VNC port")

        listen_address = graphics.get("listen") or graphics.get("address")
        listen = graphics.find("listen")
        if listen is not None:
            listen_address = listen.get("address") or listen_address
        if not listen_address or listen_address in {"0.0.0.0", "::"}:
            listen_address = self.hostname

        existing_password = (graphics.get("passwd") or "").strip() or None
        password: Optional[str] = None
        password_error: Optional[str] = None

        if existing_password:
            password = existing_password
        else:
            minted_password = self._generate_password()
            password_flags = 0
            for attr in ("VIR_DOMAIN_PASSWORD_SET_AFFECT_LIVE", "VIR_DOMAIN_PASSWORD_SET_AFFECT_CURRENT"):
                flag_value = getattr(libvirt, attr, 0)
                if isinstance(flag_value, int):
                    password_flags |= flag_value

            set_password = getattr(domain, "setPassword", None)
            if callable(set_password):
                try:
                    set_password("vnc", minted_password, password_flags)
                    password = minted_password
                except libvirt.libvirtError as exc:
                    logger.warning(
                        "setPassword failed for %s on %s; attempting XML graphics update: %s",
                        name,
                        self.hostname,
                        exc,
                    )
                    password_error = str(exc)
            else:
                logger.debug(
                    "setPassword unavailable for %s on %s; attempting XML graphics update",
                    name,
                    self.hostname,
                )

            if password is None:
                modify_flags = 0
                for attr in ("VIR_DOMAIN_DEVICE_MODIFY_LIVE", "VIR_DOMAIN_DEVICE_MODIFY_CURRENT"):
                    flag_value = getattr(libvirt, attr, 0)
                    if isinstance(flag_value, int):
                        modify_flags |= flag_value

                updated_graphics = ET.Element("graphics", graphics.attrib)
                updated_graphics.set("passwd", minted_password)
                try:
                    # libvirt expects a naive timestamp (YYYY-MM-DDTHH:MM:SS) in the host's timezone.
                    valid_until = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 300))
                    updated_graphics.set("passwdValidTo", valid_until)
                except Exception:
                    # Fallback silently if strftime fails for any reason
                    pass
                for child in list(graphics):
                    updated_graphics.append(child)

                update_device = getattr(domain, "updateDeviceFlags", None)
                if callable(update_device):
                    try:
                        update_device(ET.tostring(updated_graphics, encoding="unicode", method="xml"), modify_flags)
                        password = minted_password
                    except libvirt.libvirtError as exc:
                        logger.warning(
                            "updateDeviceFlags failed to set VNC password for %s on %s: %s",
                            name,
                            self.hostname,
                            exc,
                        )
                        password_error = str(exc)
                else:
                    logger.debug("updateDeviceFlags unavailable for %s on %s", name, self.hostname)

            if password is None:
                hint = (
                    "Configure a static VNC password in the domain XML or upgrade libvirt to enable runtime password updates."
                )
                detail = (
                    f"Unable to set VNC password for '{name}' on {self.hostname}: "
                    f"{password_error or 'runtime password updates are not supported.'} {hint}"
                )
                raise StorageError(detail)

        issued_at = int(time.time())

        default_ssh_target = self.hostname
        if self.user:
            default_ssh_target = f"{self.user}@{self.hostname}"

        script_lines = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            "# Generated by VirtLab: forward VNC over SSH and launch virt-viewer.",
            "",
            "required_commands=(ssh virt-viewer mktemp)",
            "for cmd in \"${required_commands[@]}\"; do",
            "  if ! command -v \"$cmd\" >/dev/null 2>&1; then",
            "    echo \"Missing required command: $cmd\" >&2",
            "    exit 1",
            "  fi",
            "done",
            "",
            f"HOST={shlex.quote(listen_address)}",
            f"HOST_PORT={port}",
            f"PASSWORD={shlex.quote(password)}",
            f"TITLE={shlex.quote(f'Console - {name}')}",
            f"DEFAULT_SSH_TARGET={shlex.quote(default_ssh_target)}",
            'SSH_TARGET="${SSH_TARGET:-$DEFAULT_SSH_TARGET}"',
            'if [[ -z "$SSH_TARGET" ]]; then',
            '  echo "Set SSH_TARGET to your libvirt host (e.g. user@host)" >&2',
            '  exit 1',
            'fi',
            'LOCAL_PORT="${LOCAL_PORT:-$HOST_PORT}"',
            'if ! [[ "$LOCAL_PORT" =~ ^[0-9]+$ ]] || (( LOCAL_PORT < 1 || LOCAL_PORT > 65535 )); then',
            '  echo "LOCAL_PORT must be an integer between 1 and 65535" >&2',
            '  exit 1',
            'fi',
            '',
            'cleanup() {',
            '  if [[ -n "${SSH_PID:-}" ]]; then',
            '    kill "$SSH_PID" >/dev/null 2>&1 || true',
            '    wait "$SSH_PID" 2>/dev/null || true',
            '  fi',
            '  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then',
            '    rm -rf "$TMP_DIR"',
            '  fi',
            '}',
            'trap cleanup EXIT',
            'TMP_DIR=$(mktemp -d)',
            'VV_FILE="$TMP_DIR/console.vv"',
            'cat >"$VV_FILE" <<EOF',
            '[virt-viewer]',
            'type=vnc',
            'host=127.0.0.1',
            'port=${LOCAL_PORT}',
            'password=${PASSWORD}',
            'title=${TITLE}',
            'delete-this-file=1',
            'EOF',
            'echo "Starting SSH tunnel to $SSH_TARGET (local $LOCAL_PORT -> $HOST:$HOST_PORT)..."',
            'ssh -o ExitOnForwardFailure=yes -L "${LOCAL_PORT}:${HOST}:${HOST_PORT}" "$SSH_TARGET" -N &',
            'SSH_PID=$!',
            'sleep 1',
            'if ! kill -0 "$SSH_PID" >/dev/null 2>&1; then',
            '  set +e',
            '  wait "$SSH_PID"',
            '  status=$?',
            '  set -e',
            '  exit "$status"',
            'fi',
            'echo "Launching virt-viewer..."',
            'virt-viewer "$VV_FILE" "$@"',
        ]

        return {
            "host": listen_address,
            "port": port,
            "password": password,
            "issued_at": issued_at,
            "filename": f"{name}-console.sh",
            "content": "\n".join(script_lines) + "\n",
            "ssh_target": default_ssh_target,
        }

    def get_domain_details(self, name: str) -> Dict[str, Any]:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")

        domain = None
        try:
            domain = self.conn.lookupByName(name)
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s: %s", name, self.hostname, exc)
            raise

        info: Dict[str, Any] = {}

        def safe_call(label: str, func, *args, **kwargs):
            try:
                return func(*args, **kwargs)
            except libvirt.libvirtError as exc:
                logger.debug("%s failed for %s on %s: %s", label, name, self.hostname, exc)
                info.setdefault("errors", []).append(f"{label}: {exc}")
                return None

        base_info = safe_call("dominfo", domain.info)
        if isinstance(base_info, (list, tuple)):
            state_code = base_info[0]
            info["dominfo"] = {
                "state": state_code,
                "maxMem": base_info[1],
                "memory": base_info[2],
                "nrVirtCpu": base_info[3],
                "cpuTime": base_info[4],
            }
            info["state_code"] = state_code
            info["state"] = _map_domain_state(state_code)

        info["uuid"] = safe_call("UUIDString", domain.UUIDString)
        info["id"] = safe_call("ID", domain.ID)
        info["name"] = name
        info["persistent"] = safe_call("isPersistent", domain.isPersistent)
        info["autostart"] = safe_call("autostart", domain.autostart)
        xml_desc = safe_call("XMLDesc", domain.XMLDesc, 0)
        info["metadata"] = xml_desc

        disks: List[Dict[str, Any]] = []
        interfaces: List[Dict[str, Any]] = []

        if isinstance(xml_desc, str):
            try:
                root = ET.fromstring(xml_desc)
                for disk in root.findall("./devices/disk"):
                    target = disk.find("target")
                    dev = target.get("dev") if target is not None else None
                    if not dev:
                        continue
                    entry: Dict[str, Any] = {
                        "target": dev,
                        "bus": target.get("bus") if target is not None else None,
                        "device": (disk.get("device") if isinstance(disk.get("device"), str) else None),
                        "type": disk.get("type"),
                    }
                    source = disk.find("source")
                    if source is not None:
                        entry["source"] = source.attrib
                    stats = safe_call(f"blockStats:{dev}", domain.blockStats, dev)
                    if isinstance(stats, (list, tuple)) and len(stats) >= 5:
                        entry["stats"] = {
                            "read_requests": stats[0],
                            "read_bytes": stats[1],
                            "write_requests": stats[2],
                            "write_bytes": stats[3],
                            "errors": stats[4],
                        }
                    disks.append(entry)

                for iface in root.findall("./devices/interface"):
                    target = iface.find("target")
                    dev = target.get("dev") if target is not None else None
                    mac_el = iface.find("mac")
                    entry: Dict[str, Any] = {
                        "target": dev,
                        "mac": mac_el.get("address") if mac_el is not None else None,
                        "model": (iface.find("model").get("type") if iface.find("model") is not None else None),
                    }
                    source = iface.find("source")
                    if source is not None:
                        entry["source"] = source.attrib
                    if dev:
                        net_stats = safe_call(f"interfaceStats:{dev}", domain.interfaceStats, dev)
                        if isinstance(net_stats, (list, tuple)) and len(net_stats) >= 8:
                            entry["stats"] = {
                                "rx_bytes": net_stats[0],
                                "rx_packets": net_stats[1],
                                "rx_errors": net_stats[2],
                                "rx_drops": net_stats[3],
                                "tx_bytes": net_stats[4],
                                "tx_packets": net_stats[5],
                                "tx_errors": net_stats[6],
                                "tx_drops": net_stats[7],
                            }
                    interfaces.append(entry)
            except ET.ParseError as exc:
                info.setdefault("errors", []).append(f"domxml parse: {exc}")

        info["block_devices"] = disks

        # Interface addresses via guest agent (fallback to DHCP leases)
        addresses = safe_call(
            "interfaceAddresses-agent",
            domain.interfaceAddresses,
            getattr(libvirt, "VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT", 0),
        )
        if addresses is None:
            addresses = safe_call(
                "interfaceAddresses-lease",
                domain.interfaceAddresses,
                getattr(libvirt, "VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE", 0),
            )
        if isinstance(addresses, dict):
            for entry in interfaces:
                addrs = addresses.get(entry.get("target"))
                if isinstance(addrs, dict):
                    entry["addresses"] = addrs.get("addrs")

        info["interfaces"] = interfaces

        memory_stats = safe_call("dommemstat", domain.memoryStats)
        if isinstance(memory_stats, dict):
            info["memory_stats"] = memory_stats

        fs_info = safe_call("domfsinfo", domain.fsInfo)
        if isinstance(fs_info, list):
            info["filesystems"] = fs_info

        perf = safe_call("domstats", self.conn.domainListGetStats, [domain], 0)
        if isinstance(perf, list) and perf:
            entry = perf[0]
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                stats_payload = entry[1]
                if isinstance(stats_payload, dict):
                    info["stats"] = stats_payload

        return info

    def get_vm_inventory(self) -> Dict:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")

        inventory: Dict[str, Any] = {"vms": []}
        errors: List[str] = []
        domains: Dict[str, libvirt.virDomain] = {}

        list_all = getattr(self.conn, "listAllDomains", None)
        if callable(list_all):
            try:
                for domain in list_all(0):
                    domains[domain.name()] = domain
            except libvirt.libvirtError as exc:
                logger.debug("listAllDomains failed for %s: %s", self.hostname, exc)

        if not domains:
            # Fallback to manual enumeration
            try:
                for dom_id in self.conn.listDomainsID():
                    try:
                        domain = self.conn.lookupByID(dom_id)
                        domains[domain.name()] = domain
                    except libvirt.libvirtError as exc:
                        logger.debug("lookupByID(%s) failed on %s: %s", dom_id, self.hostname, exc)
                        errors.append(f"id {dom_id}: {exc}")
            except libvirt.libvirtError as exc:
                logger.debug("listDomainsID failed on %s: %s", self.hostname, exc)
                errors.append(str(exc))

            try:
                for name in self.conn.listDefinedDomains():
                    if name in domains:
                        continue
                    try:
                        domains[name] = self.conn.lookupByName(name)
                    except libvirt.libvirtError as exc:
                        logger.debug("lookupByName(%s) failed on %s: %s", name, self.hostname, exc)
                        errors.append(f"{name}: {exc}")
            except libvirt.libvirtError as exc:
                logger.debug("listDefinedDomains failed on %s: %s", self.hostname, exc)
                errors.append(str(exc))

        vm_entries: List[Dict[str, Any]] = []
        for name, domain in domains.items():
            try:
                info = domain.info()
                state_code = int(info[0]) if isinstance(info, (list, tuple)) and info else None
                max_mem_kib = int(info[1]) if len(info) > 1 else None
                mem_kib = int(info[2]) if len(info) > 2 else None
                vcpus = int(info[3]) if len(info) > 3 else None
                cpu_time_ns = int(info[4]) if len(info) > 4 else None
                entry: Dict[str, Any] = {
                    "name": name,
                    "state": _map_domain_state(state_code),
                    "state_code": state_code,
                }
                try:
                    entry["persistent"] = bool(domain.isPersistent())
                except libvirt.libvirtError:
                    entry["persistent"] = None

                metrics: Dict[str, Any] = {}
                if vcpus is not None:
                    metrics["vcpu_count"] = vcpus
                memory_mb = _kb_to_mb(mem_kib)
                max_memory_mb = _kb_to_mb(max_mem_kib)
                if memory_mb is not None:
                    metrics["memory_mb"] = memory_mb
                if max_memory_mb is not None:
                    metrics["max_memory_mb"] = max_memory_mb
                cpu_time_seconds = _ns_to_seconds(cpu_time_ns)
                if cpu_time_seconds is not None:
                    metrics["cpu_time_seconds"] = cpu_time_seconds
                    if vcpus:
                        metrics["uptime_seconds"] = round(cpu_time_seconds / max(vcpus, 1), 2)
                if metrics:
                    entry["metrics"] = metrics
                vm_entries.append(entry)
            except libvirt.libvirtError as exc:
                logger.debug("Failed to inspect VM %s on %s: %s", name, self.hostname, exc)
                errors.append(f"{name}: {exc}")

        vm_entries.sort(key=lambda entry: entry.get("name") or "")
        inventory["vms"] = vm_entries
        if errors:
            inventory["errors"] = errors
        return inventory

    def _prime_cpu_sample(self):
        sample = self._collect_cpu_stats()
        if sample:
            self._cpu_sample = (sample, time.perf_counter())
        else:
            self._cpu_sample = None

    def _collect_cpu_stats(self) -> Optional[Dict[str, int]]:
        if not self.conn:
            return None
        try:
            stats = self.conn.getCPUStats(-1, 0)
        except (libvirt.libvirtError, AttributeError) as exc:
            logger.debug("Unable to collect CPU stats for %s: %s", self.hostname, exc)
            return None

        if isinstance(stats, list):
            stats = stats[0] if stats else {}

        cleaned: Dict[str, int] = {}
        for key, value in stats.items():
            if isinstance(value, (int, float)):
                cleaned[key] = int(value)
        return cleaned or None

    def _compute_cpu_metrics(self) -> Dict[str, object]:
        metrics: Dict[str, object] = {
            "cores": None,
            "usage_percent": None,
            "sample_period_seconds": None,
            "times_ns": None,
        }

        if not self.conn:
            return metrics

        try:
            info = self.conn.getInfo()
            metrics["cores"] = info[2]
        except libvirt.libvirtError as exc:
            logger.debug("Failed to read CPU core count for %s: %s", self.hostname, exc)

        current_stats = self._collect_cpu_stats()
        now = time.perf_counter()
        prev_sample = self._cpu_sample
        if current_stats:
            metrics["times_ns"] = current_stats
            if prev_sample:
                prev_stats, prev_time = prev_sample
                tracked = [field for field in _CPU_TIME_FIELDS if field in current_stats and field in prev_stats]
                if tracked:
                    delta_total = sum(max(current_stats[field] - prev_stats[field], 0) for field in tracked)
                    delta_idle = max(current_stats.get("idle", 0) - prev_stats.get("idle", 0), 0)
                    if delta_total > 0:
                        usage = (delta_total - delta_idle) / delta_total * 100.0
                        metrics["usage_percent"] = round(min(max(usage, 0.0), 100.0), 1)
                metrics["sample_period_seconds"] = round(max(now - prev_time, 0.0), 3)
            self._cpu_sample = (current_stats, now)
        else:
            self._cpu_sample = None

        return metrics

    def _compute_memory_metrics(self) -> Dict[str, object]:
        metrics: Dict[str, object] = {
            "total_mb": None,
            "used_mb": None,
            "free_mb": None,
            "available_mb": None,
            "usage_percent": None,
            "raw": None,
        }

        if not self.conn:
            return metrics

        raw_stats = None
        try:
            raw_stats = self.conn.getMemoryStats(-1, 0)
        except (libvirt.libvirtError, AttributeError) as exc:
            logger.debug("Unable to collect memory stats for %s: %s", self.hostname, exc)

        if isinstance(raw_stats, list):
            raw_stats = raw_stats[0] if raw_stats else None

        cleaned_stats: Dict[str, int] = {}
        if isinstance(raw_stats, dict):
            for key, value in raw_stats.items():
                if isinstance(value, (int, float)):
                    cleaned_stats[key] = int(value)
            metrics["raw"] = cleaned_stats

        total_kib = cleaned_stats.get("total") if cleaned_stats else None
        free_kib = cleaned_stats.get("free") if cleaned_stats else None
        buffers_kib = cleaned_stats.get("buffers", 0) if cleaned_stats else 0
        cached_kib = cleaned_stats.get("cached", 0) if cleaned_stats else 0

        try:
            info = self.conn.getInfo()
            metrics["total_mb"] = info[1]
            if total_kib is None:
                total_kib = info[1] * 1024
        except libvirt.libvirtError as exc:
            logger.debug("Unable to read base memory info for %s: %s", self.hostname, exc)

        if free_kib is None:
            try:
                free_bytes = self.conn.getFreeMemory()
                free_kib = int(free_bytes / 1024)
            except libvirt.libvirtError as exc:
                logger.debug("Unable to read free memory for %s: %s", self.hostname, exc)

        available_kib = None
        if free_kib is not None:
            available_kib = free_kib + buffers_kib + cached_kib

        used_kib = None
        if total_kib is not None:
            if available_kib is not None:
                used_kib = max(total_kib - available_kib, 0)
            elif free_kib is not None:
                used_kib = max(total_kib - free_kib, 0)

        def _to_mb(value_kib: Optional[int]) -> Optional[float]:
            if value_kib is None:
                return None
            return round(value_kib / 1024.0, 2)

        if free_kib is not None:
            metrics["free_mb"] = _to_mb(free_kib)
        if available_kib is not None:
            metrics["available_mb"] = _to_mb(available_kib)
        if used_kib is not None:
            metrics["used_mb"] = _to_mb(used_kib)
            if total_kib:
                metrics["usage_percent"] = round((used_kib / total_kib) * 100.0, 1)

        return metrics
_DOMAIN_STATE_LABELS = {
    getattr(libvirt, "VIR_DOMAIN_NOSTATE", None): "unknown",
    getattr(libvirt, "VIR_DOMAIN_RUNNING", None): "running",
    getattr(libvirt, "VIR_DOMAIN_BLOCKED", None): "blocked",
    getattr(libvirt, "VIR_DOMAIN_PAUSED", None): "paused",
    getattr(libvirt, "VIR_DOMAIN_SHUTDOWN", None): "shutdown",
    getattr(libvirt, "VIR_DOMAIN_SHUTOFF", None): "shutoff",
    getattr(libvirt, "VIR_DOMAIN_CRASHED", None): "crashed",
    getattr(libvirt, "VIR_DOMAIN_PMSUSPENDED", None): "suspended",
    getattr(libvirt, "VIR_DOMAIN_LAST", None): "unknown",
}


def _map_domain_state(code: Optional[int]) -> str:
    if code is None:
        return "unknown"
    return _DOMAIN_STATE_LABELS.get(code, f"state:{code}")
