from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import libvirt

if TYPE_CHECKING:
    from ..host import LibvirtHost

logger = logging.getLogger(__name__)


def _kb_to_mb(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1024.0, 2)


def _ns_to_seconds(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1_000_000_000.0, 2)


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


class LibvirtDomainInventory:
    """Aggregates read-only inspection helpers for libvirt domains."""

    def __init__(
        self,
        host: "LibvirtHost",
        retry_decider,
    ) -> None:
        self._host = host
        self._should_retry = retry_decider

    def get_domain_details(self, name: str) -> Dict[str, Any]:
        if not self._host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {self._host.hostname}")

        domain = None
        try:
            domain = self._host.conn.lookupByName(name)  # type: ignore[union-attr]
        except libvirt.libvirtError as exc:
            logger.error("lookupByName(%s) failed on %s: %s", name, self._host.hostname, exc)
            raise

        info: Dict[str, Any] = {}

        def safe_call(label: str, func, *args, **kwargs):
            try:
                return func(*args, **kwargs)
            except libvirt.libvirtError as exc:  # pragma: no cover - defensive logging
                logger.debug("%s failed for %s on %s: %s", label, name, self._host.hostname, exc)
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
                disks.extend(self._extract_disk_details(root, domain, safe_call))
                interfaces.extend(self._extract_interface_details(root, domain, safe_call))
            except ET.ParseError as exc:
                info.setdefault("errors", []).append(f"domxml parse: {exc}")

        info["block_devices"] = disks

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

        perf = safe_call("domstats", self._host.conn.domainListGetStats, [domain], 0)  # type: ignore[union-attr]
        if isinstance(perf, list) and perf:
            entry = perf[0]
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                stats_payload = entry[1]
                if isinstance(stats_payload, dict):
                    info["stats"] = stats_payload

        return info

    def get_vm_inventory(self) -> Dict[str, Any]:
        if not self._host._ensure_connection():  # pylint: disable=protected-access
            raise RuntimeError(f"Not connected to {self._host.hostname}")

        inventory: Dict[str, Any] = {"vms": []}
        errors: List[str] = []
        domains: Dict[str, libvirt.virDomain] = {}

        list_all = getattr(self._host.conn, "listAllDomains", None)  # type: ignore[union-attr]
        if callable(list_all):
            try:
                for domain in list_all(0):
                    domains[domain.name()] = domain
            except libvirt.libvirtError as exc:
                logger.debug("listAllDomains failed for %s: %s", self._host.hostname, exc)

        if not domains:
            try:
                for dom_id in self._host.conn.listDomainsID():  # type: ignore[union-attr]
                    try:
                        domain = self._host.conn.lookupByID(dom_id)  # type: ignore[union-attr]
                        domains[domain.name()] = domain
                    except libvirt.libvirtError as exc:
                        logger.debug("lookupByID(%s) failed on %s: %s", dom_id, self._host.hostname, exc)
                        errors.append(f"id {dom_id}: {exc}")
            except libvirt.libvirtError as exc:
                logger.debug("listDomainsID failed on %s: %s", self._host.hostname, exc)
                errors.append(str(exc))

            try:
                for name in self._host.conn.listDefinedDomains():  # type: ignore[union-attr]
                    if name in domains:
                        continue
                    try:
                        domains[name] = self._host.conn.lookupByName(name)  # type: ignore[union-attr]
                    except libvirt.libvirtError as exc:
                        logger.debug("lookupByName(%s) failed on %s: %s", name, self._host.hostname, exc)
                        errors.append(f"{name}: {exc}")
            except libvirt.libvirtError as exc:
                logger.debug("listDefinedDomains failed on %s: %s", self._host.hostname, exc)
                errors.append(str(exc))

        vm_entries: List[Dict[str, Any]] = []
        for name, domain in domains.items():
            try:
                entry = self._build_inventory_entry(name, domain)
                vm_entries.append(entry)
            except libvirt.libvirtError as exc:
                logger.debug("Failed to inspect VM %s on %s: %s", name, self._host.hostname, exc)
                errors.append(f"{name}: {exc}")

        vm_entries.sort(key=lambda entry: entry.get("name") or "")
        inventory["vms"] = vm_entries
        if errors:
            inventory["errors"] = errors
        return inventory

    def list_vms(self) -> List[str]:
        if not self._host.conn:
            raise RuntimeError(f"Not connected to {self._host.hostname}")
        domains: List[str] = []
        for dom_id in self._host.conn.listDomainsID():  # type: ignore[union-attr]
            dom = self._host.conn.lookupByID(dom_id)  # type: ignore[union-attr]
            domains.append(dom.name())
        for name in self._host.conn.listDefinedDomains():  # type: ignore[union-attr]
            domains.append(name)
        return domains

    def _extract_disk_details(self, root: ET.Element, domain: "libvirt.virDomain", safe_call) -> List[Dict[str, Any]]:
        disks: List[Dict[str, Any]] = []
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
        return disks

    def _extract_interface_details(self, root: ET.Element, domain: "libvirt.virDomain", safe_call) -> List[Dict[str, Any]]:
        interfaces: List[Dict[str, Any]] = []
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
        return interfaces

    def _build_inventory_entry(self, name: str, domain: "libvirt.virDomain") -> Dict[str, Any]:
        info = domain.info()
        state_code = int(info[0]) if isinstance(info, (list, tuple)) and info else None
        max_mem_kib = int(info[1]) if len(info) > 1 else None
        mem_kib = int(info[2]) if len(info) > 2 else None
        vcpus = int(info[3]) if len(info) > 3 else None
        cpu_time_ns = int(info[4]) if len(info) > 4 else None
        try:
            uuid = domain.UUIDString()
        except libvirt.libvirtError:
            uuid = None
        entry: Dict[str, Any] = {
            "name": name,
            "state": _map_domain_state(state_code),
            "state_code": state_code,
        }
        if isinstance(uuid, str) and uuid:
            entry["uuid"] = uuid
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

        guest_agent_ips: List[str] = []
        addresses = None
        try:
            is_active = bool(domain.isActive())
        except libvirt.libvirtError:
            is_active = False
        if is_active:
            addresses = self._collect_interface_addresses(domain)
        if isinstance(addresses, dict):
            for iface in addresses.values():
                addrs = iface.get("addrs") if isinstance(iface, dict) else None
                if isinstance(addrs, list):
                    for addr in addrs:
                        if not isinstance(addr, dict):
                            continue
                        ip_addr = addr.get("addr")
                        if isinstance(ip_addr, str) and ip_addr:
                            guest_agent_ips.append(ip_addr)
        if guest_agent_ips:
            entry["guest_agent_ips"] = guest_agent_ips
        return entry

    def _collect_interface_addresses(self, domain: "libvirt.virDomain") -> Optional[Dict[str, Any]]:
        try:
            return domain.interfaceAddresses(
                getattr(libvirt, "VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT", 0),
                0,
            )
        except libvirt.libvirtError:
            try:
                return domain.interfaceAddresses(
                    getattr(libvirt, "VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE", 0),
                    0,
                )
            except libvirt.libvirtError:
                return None
