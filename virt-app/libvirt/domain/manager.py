from __future__ import annotations

from typing import Any, Dict, List, Optional

from .console import LibvirtDomainConsole
from .inventory import LibvirtDomainInventory
from .lifecycle import LibvirtDomainLifecycle


class LibvirtDomainManager:
    """Facade aggregating domain lifecycle, console, and inventory helpers."""

    def __init__(self, host, retry_decider) -> None:
        self.inventory = LibvirtDomainInventory(host, retry_decider)
        self.lifecycle = LibvirtDomainLifecycle(
            host,
            retry_decider,
            detail_resolver=self.inventory.get_domain_details,
        )
        self.console = LibvirtDomainConsole(host, retry_decider)

    # ------------------------------------------------------------------
    # Lifecycle wrappers
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
        return self.lifecycle.clone_guest(
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
        return self.lifecycle.delete_guest(name, force=force, remove_storage=remove_storage)

    def detach_guest_block_device(self, name: str, target: str) -> Dict[str, Any]:
        return self.lifecycle.detach_guest_block_device(name, target)

    def start_domain(self, name: str) -> bool:
        return self.lifecycle.start_domain(name)

    def shutdown_domain(self, name: str) -> bool:
        return self.lifecycle.shutdown_domain(name)

    def reboot_domain(self, name: str) -> bool:
        return self.lifecycle.reboot_domain(name)

    def destroy_domain(self, name: str) -> bool:
        return self.lifecycle.destroy_domain(name)

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
        return self.lifecycle.create_guest(
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

    # ------------------------------------------------------------------
    # Console wrappers
    # ------------------------------------------------------------------

    def generate_vnc_connection_file(self, name: str) -> Dict[str, Any]:
        return self.console.generate_vnc_connection_file(name)

    # ------------------------------------------------------------------
    # Inventory wrappers
    # ------------------------------------------------------------------

    def get_domain_details(self, name: str) -> Dict[str, Any]:
        return self.inventory.get_domain_details(name)

    def get_vm_inventory(self) -> Dict[str, Any]:
        return self.inventory.get_vm_inventory()

    def list_vms(self):
        return self.inventory.list_vms()
