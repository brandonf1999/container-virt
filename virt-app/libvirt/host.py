import logging
import secrets
import string
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import libvirt

from .networking import gather_host_network_inventory
from .domain import LibvirtDomainManager
from .host_metrics import LibvirtHostMetrics
from .storage_manager import LibvirtStorageManager

logger = logging.getLogger(__name__)

# Register default event loop once (prevents keepalive error)
try:
    libvirt.virEventRegisterDefaultImpl()
except Exception:
    pass

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

class LibvirtHost:
    """Manages a single libvirt host connection over SSH."""

    def __init__(self, hostname: str, user: Optional[str] = None, ssh_opts: Optional[Dict] = None):
        self.hostname = hostname
        self.user = user
        self.ssh_opts = ssh_opts or {}
        self.conn: Optional[libvirt.virConnect] = None
        self.storage = LibvirtStorageManager(self, _should_retry_libvirt_error)
        self.domains = LibvirtDomainManager(self, _should_retry_libvirt_error)
        self.metrics = LibvirtHostMetrics(self)

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
            self.metrics.prime_cpu_sample()
            return True
        except libvirt.libvirtError as e:
            logger.error("Connection to %s failed: %s", self.hostname, e)
            return False

    def disconnect(self):
        if self.conn:
            logger.info("Disconnecting from %s", self.hostname)
            self.conn.close()
            self.conn = None
        self.metrics.reset()

    def start_domain(self, name: str) -> bool:
        return self.domains.start_domain(name)

    def shutdown_domain(self, name: str) -> bool:
        return self.domains.shutdown_domain(name)

    def reboot_domain(self, name: str) -> bool:
        return self.domains.reboot_domain(name)

    def destroy_domain(self, name: str) -> bool:
        return self.domains.destroy_domain(name)

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
        return self.domains.list_vms()

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

        return self.metrics.gather()

    def get_network_inventory(self) -> Dict:
        if not self._ensure_connection():
            raise RuntimeError(f"Not connected to {self.hostname}")
        return gather_host_network_inventory(self.conn)

    def get_storage_inventory(self) -> Dict:
        return self.storage.get_inventory()

    def describe_storage_volume(self, pool_name: str, volume_name: str) -> Dict[str, Any]:
        return self.storage.describe_volume(pool_name, volume_name)

    def delete_storage_volume(self, pool_name: str, volume_name: str, *, force: bool = False) -> Dict[str, Any]:
        return self.storage.delete_volume(pool_name, volume_name, force=force)

    @staticmethod
    def _generate_vnc_password(length: int = 8) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(max(length, 8)))

    @staticmethod
    def _generate_random_mac() -> str:
        # Locally administered unicast MAC (x2:xx:xx:xx:xx:xx)
        first_octet = 0x02
        octets = [first_octet] + [secrets.randbits(8) for _ in range(5)]
        return ":".join(f"{value:02x}" for value in octets)

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
        return self.storage.upload_volume(
            pool_name,
            volume_name,
            source_path,
            size_bytes=size_bytes,
            overwrite=overwrite,
            volume_format=volume_format,
        )

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
        return self.domains.create_guest(
            name,
            vcpus=vcpus,
            memory_mb=memory_mb,
            autostart=autostart,
            start=start,
            description=description,
            volumes=volumes,
            networks=networks,
            enable_vnc=enable_vnc,
            vnc_password=vnc_password,
        )

    def clone_guest(
        self,
        source_name: str,
        *,
        new_name: str,
        autostart: Optional[bool] = None,
        start: bool = False,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.domains.clone_guest(
            source_name,
            new_name=new_name,
            autostart=autostart,
            start=start,
            description=description,
        )

    def delete_guest(
        self,
        name: str,
        *,
        force: bool = False,
        remove_storage: bool = False,
    ) -> Dict[str, Any]:
        return self.domains.delete_guest(name, force=force, remove_storage=remove_storage)

    def detach_guest_block_device(
        self,
        name: str,
        target: str,
    ) -> Dict[str, Any]:
        return self.domains.detach_guest_block_device(name, target)

    def delete_storage_pool(self, pool_name: str, *, force: bool = False) -> Dict[str, Any]:
        return self.storage.delete_pool(pool_name, force=force)

    def generate_vnc_connection_file(self, name: str) -> Dict[str, Any]:
        return self.domains.generate_vnc_connection_file(name)

    def get_domain_details(self, name: str) -> Dict[str, Any]:
        return self.domains.get_domain_details(name)

    def get_vm_inventory(self) -> Dict:
        return self.domains.get_vm_inventory()
