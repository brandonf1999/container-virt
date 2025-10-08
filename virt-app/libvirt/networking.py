import logging
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

import libvirt

logger = logging.getLogger(__name__)

def _parse_interface_xml(xml: str) -> Dict[str, Any]:
    root = ET.fromstring(xml)
    iface_data: Dict[str, Any] = {
        "type": root.attrib.get("type"),
        "start_mode": None,
        "mtu": None,
        "mac": None,
        "addresses": [],
        "routes": [],
        "link": None,
        "bond": None,
        "bridge": None,
        "vlan": None,
        "raw_xml": xml,
    }

    start_elem = root.find("start")
    if start_elem is not None:
        iface_data["start_mode"] = start_elem.attrib.get("mode")

    mtu_elem = root.find("mtu")
    if mtu_elem is not None:
        size = mtu_elem.attrib.get("size")
        iface_data["mtu"] = int(size) if size and size.isdigit() else size

    mac_elem = root.find("mac")
    if mac_elem is not None:
        iface_data["mac"] = mac_elem.attrib.get("address")

    for protocol_elem in root.findall("protocol"):
        family = protocol_elem.attrib.get("family")
        for ip_elem in protocol_elem.findall("ip"):
            iface_data["addresses"].append(
                {
                    "family": family,
                    "address": ip_elem.attrib.get("address"),
                    "prefix": ip_elem.attrib.get("prefix"),
                }
            )
        for route_elem in protocol_elem.findall("route"):
            iface_data["routes"].append(
                {
                    "family": family,
                    "gateway": route_elem.attrib.get("gateway"),
                }
            )

    link_elem = root.find("link")
    if link_elem is not None:
        link_info: Dict[str, Any] = {
            "state": link_elem.attrib.get("state"),
        }
        speed = link_elem.attrib.get("speed")
        if speed is not None:
            try:
                link_info["speed_mbps"] = int(speed)
            except ValueError:
                link_info["speed"] = speed
        iface_data["link"] = link_info

    bond_elem = root.find("bond")
    if bond_elem is not None:
        iface_data["bond"] = {
            "mode": bond_elem.attrib.get("mode"),
            "miimon": bond_elem.attrib.get("miimon"),
        }
        iface_data["bond"]["slaves"] = [
            {
                "name": slave.attrib.get("name"),
                "mac": slave.attrib.get("mac"),
            }
            for slave in bond_elem.findall("interface")
        ]

    bridge_elem = root.find("bridge")
    if bridge_elem is not None:
        iface_data["bridge"] = {
            "name": bridge_elem.attrib.get("name"),
            "stp": bridge_elem.attrib.get("stp"),
            "delay": bridge_elem.attrib.get("delay"),
        }

    vlan_elem = root.find("vlan")
    if vlan_elem is not None:
        tag_elem = vlan_elem.find("tag")
        iface_data["vlan"] = {
            "trunk": vlan_elem.attrib.get("trunk") == "yes",
            "tags": [
                {
                    "id": tag.attrib.get("id"),
                    "nativeMode": tag.attrib.get("nativeMode"),
                }
                for tag in vlan_elem.findall("tag")
            ],
        }
        if tag_elem is not None:
            iface_data["vlan"]["id"] = tag_elem.attrib.get("id")

    return iface_data


def _collect_interface_objects(conn: libvirt.virConnect) -> Dict[str, "libvirt.virInterface"]:
    interfaces: Dict[str, libvirt.virInterface] = {}

    list_flags = 0
    for attr in ("VIR_CONNECT_LIST_INTERFACES_ACTIVE", "VIR_CONNECT_LIST_INTERFACES_INACTIVE"):
        flag = getattr(libvirt, attr, None)
        if flag is not None:
            list_flags |= flag

    try:
        if hasattr(conn, "listAllInterfaces"):
            for iface in conn.listAllInterfaces(list_flags):
                interfaces[iface.name()] = iface
    except libvirt.libvirtError as exc:
        logger.debug("listAllInterfaces failed: %s", exc)

    try:
        for name in conn.listInterfaces():
            if name not in interfaces and hasattr(conn, "interfaceLookupByName"):
                try:
                    interfaces[name] = conn.interfaceLookupByName(name)
                except libvirt.libvirtError as exc:
                    logger.debug("interfaceLookupByName(%s) failed: %s", name, exc)
    except libvirt.libvirtError as exc:
        logger.debug("listInterfaces failed: %s", exc)

    try:
        for name in conn.listDefinedInterfaces():
            if name not in interfaces and hasattr(conn, "interfaceLookupByName"):
                try:
                    interfaces[name] = conn.interfaceLookupByName(name)
                except libvirt.libvirtError as exc:
                    logger.debug("interfaceLookupByName(%s) failed: %s", name, exc)
    except libvirt.libvirtError:
        # Optional capability
        pass

    return interfaces


def _fetch_interface_stats(conn: libvirt.virConnect, name: str) -> Optional[Dict[str, Any]]:
    stats_fn = getattr(conn, "interfaceStats", None)
    if not callable(stats_fn):
        return None

    try:
        stats = stats_fn(name)
    except libvirt.libvirtError as exc:
        logger.debug("interfaceStats(%s) failed: %s", name, exc)
        return None

    if not isinstance(stats, (list, tuple)) or len(stats) < 8:
        return None

    rx_bytes, rx_packets, rx_errs, rx_drop, tx_bytes, tx_packets, tx_errs, tx_drop = stats[:8]
    return {
        "rx_bytes": int(rx_bytes),
        "rx_packets": int(rx_packets),
        "rx_errors": int(rx_errs),
        "rx_drops": int(rx_drop),
        "tx_bytes": int(tx_bytes),
        "tx_packets": int(tx_packets),
        "tx_errors": int(tx_errs),
        "tx_drops": int(tx_drop),
        "collected_at": time.time(),
    }


def collect_host_interfaces(conn: libvirt.virConnect) -> Tuple[List[Dict[str, Any]], List[str]]:
    interfaces: List[Dict[str, Any]] = []
    errors: List[str] = []

    for name, iface in _collect_interface_objects(conn).items():
        try:
            xml_desc = iface.XMLDesc(0)
            parsed = _parse_interface_xml(xml_desc)
            parsed.update(
                {
                    "name": name,
                    "active": bool(iface.isActive()),
                }
            )
            stats = _fetch_interface_stats(conn, name)
            if stats is not None:
                parsed["stats"] = stats
            interfaces.append(parsed)
        except libvirt.libvirtError as exc:
            logger.debug("Failed to inspect interface %s: %s", name, exc)
            errors.append(f"{name}: {exc}")
        except ET.ParseError as exc:
            logger.warning("Failed to parse iface XML for %s: %s", name, exc)
            errors.append(f"{name}: XML parse error {exc}")

    interfaces.sort(key=lambda entry: entry.get("name") or "")
    return interfaces, errors


def _parse_network_xml(xml: str) -> Dict[str, Any]:
    root = ET.fromstring(xml)
    net: Dict[str, Any] = {
        "forward_mode": None,
        "bridge": None,
        "ips": [],
        "dhcp": [],
        "dns": None,
        "mtu": None,
        "raw_xml": xml,
    }

    forward_elem = root.find("forward")
    if forward_elem is not None:
        net["forward_mode"] = forward_elem.attrib.get("mode")
        net["forward_dev"] = forward_elem.attrib.get("dev")

    bridge_elem = root.find("bridge")
    if bridge_elem is not None:
        net["bridge"] = {
            "name": bridge_elem.attrib.get("name"),
            "stp": bridge_elem.attrib.get("stp"),
            "delay": bridge_elem.attrib.get("delay"),
        }

    mtu_elem = root.find("mtu")
    if mtu_elem is not None:
        size = mtu_elem.attrib.get("size")
        net["mtu"] = int(size) if size and size.isdigit() else size

    for ip_elem in root.findall("ip"):
        ip_data = {
            "family": ip_elem.attrib.get("family", "ipv4"),
            "address": ip_elem.attrib.get("address"),
            "prefix": ip_elem.attrib.get("prefix"),
            "netmask": ip_elem.attrib.get("netmask"),
        }
        dhcp_elem = ip_elem.find("dhcp")
        if dhcp_elem is not None:
            net["dhcp"].extend(
                {
                    "family": ip_data["family"],
                    "start": rng.attrib.get("start"),
                    "end": rng.attrib.get("end"),
                }
                for rng in dhcp_elem.findall("range")
            )
        net["ips"].append(ip_data)

    dns_elem = root.find("dns")
    if dns_elem is not None:
        net["dns"] = {
            "forwarder": [f.attrib for f in dns_elem.findall("forwarder")],
            "hosts": [
                {
                    "ip": host.attrib.get("ip"),
                    "hostnames": [name.text for name in host.findall("hostname") if name.text],
                }
                for host in dns_elem.findall("host")
            ],
        }

    portgroup_elems = root.findall("portgroup")
    if portgroup_elems:
        net["portgroups"] = [
            {
                "name": pg.attrib.get("name"),
                "default": pg.attrib.get("default") == "yes",
                "vlan": pg.find("vlan").attrib if pg.find("vlan") is not None else None,
            }
            for pg in portgroup_elems
        ]

    return net


def collect_host_networks(conn: libvirt.virConnect) -> Tuple[List[Dict[str, Any]], List[str]]:
    networks: List[Dict[str, Any]] = []
    errors: List[str] = []

    list_flags = 0
    for attr in ("VIR_CONNECT_LIST_NETWORKS_ACTIVE", "VIR_CONNECT_LIST_NETWORKS_INACTIVE"):
        flag = getattr(libvirt, attr, None)
        if flag is not None:
            list_flags |= flag

    network_map: Dict[str, libvirt.virNetwork] = {}
    try:
        for network in conn.listAllNetworks(list_flags):
            network_map[network.name()] = network
    except libvirt.libvirtError as exc:
        logger.debug("listAllNetworks failed: %s", exc)

    try:
        for name in conn.listNetworks():
            if name not in network_map:
                network_map[name] = conn.networkLookupByName(name)
    except libvirt.libvirtError as exc:
        logger.debug("listNetworks failed: %s", exc)

    try:
        for name in conn.listDefinedNetworks():
            if name not in network_map:
                network_map[name] = conn.networkLookupByName(name)
    except libvirt.libvirtError:
        pass

    for name, network in network_map.items():
        try:
            xml_desc = network.XMLDesc(0)
            parsed = _parse_network_xml(xml_desc)
            parsed.update(
                {
                    "name": name,
                    "uuid": network.UUIDString() if hasattr(network, "UUIDString") else None,
                    "active": bool(network.isActive()),
                    "autostart": bool(network.autostart()),
                }
            )
            networks.append(parsed)
        except libvirt.libvirtError as exc:
            logger.debug("Failed to inspect network %s: %s", name, exc)
            errors.append(f"{name}: {exc}")
        except ET.ParseError as exc:
            logger.warning("Failed to parse network XML for %s: %s", name, exc)
            errors.append(f"{name}: XML parse error {exc}")

    networks.sort(key=lambda entry: entry.get("name") or "")
    return networks, errors


def gather_host_network_inventory(conn: libvirt.virConnect) -> Dict[str, Any]:
    interfaces, iface_errors = collect_host_interfaces(conn)
    networks, net_errors = collect_host_networks(conn)

    inventory: Dict[str, Any] = {
        "interfaces": interfaces,
        "networks": networks,
    }

    errors: List[str] = []
    if iface_errors:
        errors.extend(iface_errors)
    if net_errors:
        errors.extend(net_errors)
    if errors:
        inventory["errors"] = errors

    return inventory
