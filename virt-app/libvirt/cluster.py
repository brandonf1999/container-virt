import yaml
import logging
from typing import Any, Dict, List, Optional
from .host import LibvirtHost

logger = logging.getLogger(__name__)

class LibvirtCluster:
    """Manages multiple libvirt hosts and connections."""

    def __init__(self):
        self.hosts: Dict[str, LibvirtHost] = {}

    def _require_host(self, hostname: str) -> LibvirtHost:
        host = self.hosts.get(hostname)
        if not host:
            raise KeyError(f"Host {hostname} not found")
        return host

    def _require_connected_host(self, hostname: str) -> LibvirtHost:
        host = self._require_host(hostname)
        if host.conn or host.connect():
            return host
        raise ConnectionError(f"Unable to connect to host {hostname}")

    # --------------------------------------------------------------
    # Host management
    # --------------------------------------------------------------
    def add_host(self, hostname: str, user: Optional[str] = None, ssh_opts: Optional[dict] = None):
        """
        Add a host to the cluster.
        :param hostname: Hostname or IP address
        :param user: SSH user for the connection
        :param ssh_opts: SSH configuration options (e.g., {'known_hosts_verify': 'ignore'})
        """
        if hostname not in self.hosts:
            self.hosts[hostname] = LibvirtHost(hostname, user, ssh_opts)
            logger.info("Added host %s (ssh_opts=%s)", hostname, ssh_opts)
        else:
            logger.warning("Host %s already added, skipping.", hostname)

    # --------------------------------------------------------------
    # YAML loader
    # --------------------------------------------------------------
    def load_from_yaml(self, config_path: str):
        """
        Load cluster configuration from a YAML file.
        Expected structure:
          hosts:
            - hostname: virt0001.foos.net
              user: brandon
              ssh:
                known_hosts_verify: ignore
        """
        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}
            logger.info("Loaded libvirt cluster configuration from %s", config_path)
        except FileNotFoundError:
            logger.error("Configuration file not found: %s", config_path)
            return
        except yaml.YAMLError as e:
            logger.error("YAML parsing error in %s: %s", config_path, e)
            return

        for entry in data.get("hosts", []):
            hostname = entry.get("hostname")
            user = entry.get("user")
            ssh_opts = entry.get("ssh", {}) or {}
            if not hostname:
                logger.warning("Invalid host entry (missing hostname): %s", entry)
                continue
            self.add_host(hostname, user, ssh_opts)

    # --------------------------------------------------------------
    # Connection management
    # --------------------------------------------------------------
    def connect_all(self) -> Dict[str, bool]:
        """Attempt to connect to any hosts that are not already connected."""
        results: Dict[str, bool] = {}
        for hostname, host in self.hosts.items():
            if host.conn:
                results[hostname] = True
                continue
            connected = host.connect()
            results[hostname] = connected
        return results

    def disconnect_all(self):
        """Disconnect from all hosts."""
        for host in self.hosts.values():
            host.disconnect()

    # --------------------------------------------------------------
    # Cluster-level queries
    # --------------------------------------------------------------
    def list_all_vms(self):
        """
        Return a dict of all VMs across all hosts.
        Example:
        {
            "virt0001.foos.net": ["vm1", "vm2"],
            "virt0002.foos.net": ["vm3"]
        }
        """
        cluster_vms = {}
        for hostname, host in self.hosts.items():
            try:
                cluster_vms[hostname] = host.list_vms()
            except Exception as e:
                logger.exception("Failed to list VMs on %s: %s", hostname, e)
                cluster_vms[hostname] = f"Error: {e}"
        return cluster_vms

    def get_cluster_info(self):
        """
        Return a dict summarizing each connected host's info.
        Example:
        {
            "virt0001.foos.net": {"memory_MB": ..., "cpus": ..., "arch": ...},
            "virt0002.foos.net": {...}
        }
        """
        cluster_info = {}
        for hostname, host in self.hosts.items():
            try:
                cluster_info[hostname] = host.get_host_info()
            except Exception as e:
                logger.exception("Failed to get host info for %s: %s", hostname, e)
        return cluster_info

    def get_host_details(self, hostname: str) -> dict:
        host = self._require_connected_host(hostname)
        details = host.get_host_info()
        details["guests"] = host.get_vm_inventory().get("vms", [])
        return details

    def get_network_inventory(self):
        """Return per-host network inventory (interfaces + libvirt networks)."""
        inventory: Dict[str, dict] = {}
        errors: Dict[str, str] = {}

        for hostname, host in self.hosts.items():
            try:
                inventory[hostname] = host.get_network_inventory()
            except Exception as e:
                logger.exception("Failed to gather network inventory for %s: %s", hostname, e)
                errors[hostname] = str(e)

        return inventory, errors

    def get_storage_inventory(self):
        """Return per-host storage pool inventory."""
        inventory: Dict[str, dict] = {}
        errors: Dict[str, str] = {}

        for hostname, host in self.hosts.items():
            try:
                inventory[hostname] = host.get_storage_inventory()
            except Exception as e:
                logger.exception("Failed to gather storage inventory for %s: %s", hostname, e)
                errors[hostname] = str(e)

        return inventory, errors

    def delete_storage_volume(self, hostname: str, pool: str, volume: str, *, force: bool = False) -> dict:
        host = self._require_connected_host(hostname)
        return host.delete_storage_volume(pool, volume, force=force)

    def delete_storage_pool(self, hostname: str, pool: str, *, force: bool = False) -> dict:
        host = self._require_connected_host(hostname)
        return host.delete_storage_pool(pool, force=force)

    def upload_storage_volume(
        self,
        hostname: str,
        pool: str,
        volume: str,
        source_path: str,
        *,
        size_bytes: int,
        overwrite: bool = False,
        volume_format: Optional[str] = None,
    ) -> dict:
        host = self._require_connected_host(hostname)
        return host.upload_storage_volume(
            pool,
            volume,
            source_path,
            size_bytes=size_bytes,
            overwrite=overwrite,
            volume_format=volume_format,
        )

    def create_guest(
        self,
        hostname: str,
        *,
        name: str,
        vcpus: int,
        memory_mb: int,
        autostart: bool,
        start: bool,
        description: Optional[str],
        volumes: List[Dict[str, Any]],
        networks: List[Dict[str, Any]],
        enable_vnc: Optional[bool] = None,
        vnc_password: Optional[str] = None,
    ) -> dict:
        host = self._require_connected_host(hostname)
        return host.create_guest(
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
        hostname: str,
        source: str,
        *,
        new_name: str,
        autostart: Optional[bool] = None,
        start: bool = False,
        description: Optional[str] = None,
    ) -> dict:
        host = self._require_connected_host(hostname)
        return host.clone_guest(
            source,
            new_name=new_name,
            autostart=autostart,
            start=start,
            description=description,
        )

    def delete_guest(self, hostname: str, name: str, *, force: bool = False, remove_storage: bool = False) -> dict:
        host = self._require_connected_host(hostname)
        return host.delete_guest(name, force=force, remove_storage=remove_storage)

    def detach_guest_block_device(self, hostname: str, name: str, target: str) -> dict:
        host = self._require_connected_host(hostname)
        return host.detach_guest_block_device(name, target)

    def describe_storage_volume(self, hostname: str, pool: str, volume: str) -> dict:
        host = self._require_connected_host(hostname)
        return host.describe_storage_volume(pool, volume)

    def get_vm_inventory(self):
        """Return per-host virtual machine inventory."""
        inventory: Dict[str, dict] = {}
        errors: Dict[str, str] = {}

        for hostname, host in self.hosts.items():
            try:
                inventory[hostname] = host.get_vm_inventory()
            except Exception as e:
                logger.exception("Failed to gather VM inventory for %s: %s", hostname, e)
                errors[hostname] = str(e)

        return inventory, errors

    def generate_guest_console_file(self, hostname: str, domain: str) -> dict:
        host = self._require_connected_host(hostname)
        return host.generate_vnc_connection_file(domain)

    def get_domain_details(self, hostname: str, domain: str) -> dict:
        host = self._require_connected_host(hostname)
        return host.get_domain_details(domain)

    def control_domain(self, hostname: str, domain: str, action: str) -> bool:
        host = self._require_connected_host(hostname)

        action_map = {
            "start": host.start_domain,
            "shutdown": host.shutdown_domain,
            "reboot": host.reboot_domain,
            "force-off": host.destroy_domain,
        }
        handler = action_map.get(action)
        if not handler:
            raise ValueError(f"Unsupported action: {action}")
        return handler(domain)

    # --------------------------------------------------------------
    # Diagnostics
    # --------------------------------------------------------------
    def summary(self) -> dict:
        """Return a brief summary of the cluster state."""
        total_hosts = len(self.hosts)
        connected = sum(1 for h in self.hosts.values() if h.conn)
        return {
            "total_hosts": total_hosts,
            "connected_hosts": connected,
            "disconnected_hosts": total_hosts - connected,
        }
