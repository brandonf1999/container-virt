from __future__ import annotations

import base64
import datetime
import json
import logging
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

import libvirt
try:  # libvirt-qemu is optional and not always present.
    import libvirt_qemu
except ImportError:  # pragma: no cover - optional dependency
    libvirt_qemu = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from ..host import LibvirtHost

logger = logging.getLogger(__name__)

_GUEST_EXEC_DISABLED_WARNING = (
    "Guest agent command 'guest-exec' is disabled; enable it to report guest uptime."
)
_GUEST_EXEC_PARSE_WARNING = "Guest agent uptime output could not be parsed; guest uptime unavailable."
_GUEST_UPTIME_UNAVAILABLE_WARNING = "Guest uptime unavailable; guest-exec did not return data."

def _kb_to_mb(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1024.0, 2)


def _ns_to_seconds(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1_000_000_000.0, 2)


def _get_int(value: Optional[object]) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


def _parse_int_token(value: Optional[object]) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _decode_base64_text(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        decoded = base64.b64decode(value)
    except (ValueError, TypeError):
        return ""
    try:
        return decoded.decode("utf-8", errors="replace")
    except (AttributeError, UnicodeDecodeError):
        return ""


def _pick_stat(stats: Optional[Dict[str, Any]], keys: Tuple[str, ...]) -> Tuple[Optional[int], Optional[str]]:
    if not stats:
        return None, None
    for key in keys:
        value = _get_int(stats.get(key))
        if value is not None:
            return value, f"memory_stats.{key}"
    return None, None


def _normalize_mac(value: Optional[str]) -> Optional[str]:
    if not value or not isinstance(value, str):
        return None
    stripped = value.strip().lower()
    if not stripped:
        return None
    return stripped.replace(":", "").replace("-", "")


def _append_warning(errors: Optional[List[str]], message: str) -> None:
    if errors is None:
        return
    if message not in errors:
        errors.append(message)


def _is_guest_exec_disabled(message: str, error_class: Optional[str] = None) -> bool:
    if error_class:
        normalized = "".join(char for char in error_class.lower() if char.isalnum())
        if normalized in {"commanddisabled", "commandnotallowed", "commandnotpermitted", "commanddenied"}:
            return True
    lowered = message.lower()
    if "guest-exec" not in lowered:
        return "command" in lowered and "disabled" in lowered
    return any(
        token in lowered
        for token in (
            "disabled",
            "not enabled",
            "not permitted",
            "permission denied",
            "not allowed",
            "denied",
        )
    )


def _build_memory_summary(
    dominfo: Optional[Dict[str, Any]],
    memory_stats: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not dominfo and not memory_stats:
        return None

    max_kib = _get_int(dominfo.get("maxMem") if dominfo else None)
    max_source = "dominfo.maxMem" if max_kib is not None else None

    total_kib, total_source = _pick_stat(memory_stats, ("actual", "balloon"))
    if total_kib is None:
        total_kib = _get_int(dominfo.get("memory") if dominfo else None)
        total_source = "dominfo.memory" if total_kib is not None else None

    free_kib, free_source = _pick_stat(memory_stats, ("unused", "free"))
    available_kib, available_source = _pick_stat(memory_stats, ("available", "usable"))

    used_kib = None
    used_source = None
    if total_kib is not None and free_kib is not None:
        used_kib = max(total_kib - free_kib, 0)
        used_source = f"{total_source} - {free_source}"
    elif total_kib is not None and available_kib is not None:
        used_kib = max(total_kib - available_kib, 0)
        used_source = f"{total_source} - {available_source}"

    return {
        "unit": "MiB",
        "max_mb": _kb_to_mb(max_kib),
        "max_source": max_source,
        "total_mb": _kb_to_mb(total_kib),
        "total_source": total_source,
        "used_mb": _kb_to_mb(used_kib),
        "used_source": used_source,
        "free_mb": _kb_to_mb(free_kib),
        "free_source": free_source,
        "available_mb": _kb_to_mb(available_kib),
        "available_source": available_source,
    }

def _parse_uptime_output(output: str) -> Optional[float]:
    if not output:
        return None
    normalized = " ".join(output.strip().split())
    if not normalized:
        return None
    if " up " in normalized:
        normalized = normalized.split(" up ", 1)[1]
    elif normalized.startswith("up "):
        normalized = normalized[3:]
    for marker in (" users", " user", " load average"):
        if marker in normalized:
            normalized = normalized.split(marker, 1)[0]
            break
    normalized = normalized.strip().strip(",")
    if not normalized:
        return None
    parts = [part.strip() for part in normalized.split(",") if part.strip()]
    total_seconds = 0
    matched = False
    for part in parts:
        if ":" in part:
            hours, minutes = part.split(":", 1)
            if hours.isdigit() and minutes.isdigit():
                total_seconds += int(hours) * 3600 + int(minutes) * 60
                matched = True
                continue
        tokens = part.split()
        if len(tokens) < 2:
            continue
        value = _parse_int_token(tokens[0])
        if value is None:
            continue
        unit = tokens[1].lower()
        if unit.startswith("day"):
            total_seconds += value * 86400
            matched = True
        elif unit.startswith("hour") or unit.startswith("hr"):
            total_seconds += value * 3600
            matched = True
        elif unit.startswith("min"):
            total_seconds += value * 60
            matched = True
        elif unit.startswith("sec"):
            total_seconds += value
            matched = True
        elif unit.startswith("week"):
            total_seconds += value * 7 * 86400
            matched = True
    if not matched:
        return None
    return float(total_seconds)


def _parse_uptime_start(output: str) -> Optional[float]:
    if not output:
        return None
    normalized = " ".join(output.strip().split())
    if not normalized:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            boot_time = datetime.datetime.strptime(normalized, fmt)
        except ValueError:
            continue
        uptime = time.time() - boot_time.timestamp()
        if uptime < 0:
            return None
        return float(round(uptime, 2))
    return None


def _parse_proc_uptime(output: str) -> Optional[float]:
    if not output:
        return None
    trimmed = output.strip().split()
    if not trimmed:
        return None
    try:
        value = float(trimmed[0])
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return float(round(value, 2))


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

    def _read_guest_agent_command(
        self,
        domain: "libvirt.virDomain",
        name: str,
        command: str,
        arguments: Optional[Dict[str, Any]] = None,
        timeout: int = 2,
        errors: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        qemu_agent_command = None
        use_libvirt_qemu = False
        try:
            qemu_agent_command = domain.qemuAgentCommand
        except AttributeError:
            qemu_agent_command = None
        if not callable(qemu_agent_command):
            qemu_agent_command = getattr(libvirt_qemu, "qemuAgentCommand", None) if libvirt_qemu else None
            use_libvirt_qemu = callable(qemu_agent_command)
        if not callable(qemu_agent_command):
            logger.debug(
                "qemuAgentCommand unavailable for %s on %s; skipping guest agent query",
                name,
                self._host.hostname,
            )
            return None
        payload: Dict[str, Any] = {"execute": command}
        if arguments:
            payload["arguments"] = arguments
        try:
            if use_libvirt_qemu:
                response = qemu_agent_command(domain, json.dumps(payload), timeout, 0)
            else:
                response = qemu_agent_command(json.dumps(payload), timeout, 0)
        except AttributeError:
            logger.debug(
                "qemuAgentCommand unavailable for %s on %s; skipping guest agent query",
                name,
                self._host.hostname,
            )
            return None
        except libvirt.libvirtError as exc:
            message = str(exc)
            if command == "guest-exec" and _is_guest_exec_disabled(message):
                _append_warning(errors, _GUEST_EXEC_DISABLED_WARNING)
            logger.debug(
                "qemuAgentCommand(%s) failed for %s on %s: %s",
                command,
                name,
                self._host.hostname,
                exc,
            )
            return None
        if not isinstance(response, str):
            return None
        try:
            payload = json.loads(response)
        except json.JSONDecodeError as exc:
            logger.debug(
                "qemuAgentCommand(%s) returned invalid JSON for %s on %s: %s",
                command,
                name,
                self._host.hostname,
                exc,
            )
            return None
        if not isinstance(payload, dict):
            return None
        if command == "guest-exec":
            error_payload = payload.get("error")
            if isinstance(error_payload, dict):
                error_message = error_payload.get("desc") or ""
                error_class = error_payload.get("class") or ""
                if isinstance(error_message, str) or isinstance(error_class, str):
                    message_text = error_message if isinstance(error_message, str) else ""
                    class_text = error_class if isinstance(error_class, str) else None
                    if _is_guest_exec_disabled(message_text or "", class_text):
                        _append_warning(errors, _GUEST_EXEC_DISABLED_WARNING)
        return payload

    def _run_guest_exec(
        self,
        domain: "libvirt.virDomain",
        name: str,
        path: str,
        args: Optional[List[str]] = None,
        timeout: int = 3,
        poll_interval: float = 0.2,
        errors: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        exec_args = {
            "path": path,
            "arg": args or [],
            "capture-output": True,
        }
        start_payload = self._read_guest_agent_command(
            domain,
            name,
            "guest-exec",
            exec_args,
            timeout=timeout,
            errors=errors,
        )
        if not start_payload:
            return None
        start_return = start_payload.get("return")
        if not isinstance(start_return, dict):
            return None
        pid = _get_int(start_return.get("pid"))
        if pid is None:
            return None
        deadline = time.monotonic() + max(timeout, poll_interval)
        while time.monotonic() < deadline:
            status_payload = self._read_guest_agent_command(
                domain,
                name,
                "guest-exec-status",
                {"pid": pid},
                timeout=timeout,
                errors=errors,
            )
            status_return = status_payload.get("return") if status_payload else None
            if isinstance(status_return, dict) and status_return.get("exited") is True:
                stdout = _decode_base64_text(status_return.get("out-data"))
                stderr = _decode_base64_text(status_return.get("err-data"))
                return {
                    "exitcode": _get_int(status_return.get("exitcode")),
                    "signal": status_return.get("signal"),
                    "stdout": stdout,
                    "stderr": stderr,
                }
            time.sleep(poll_interval)
        logger.debug(
            "guest-exec-status timed out for %s on %s (pid=%s)",
            name,
            self._host.hostname,
            pid,
        )
        return None

    def _read_guest_uptime_seconds(
        self,
        domain: "libvirt.virDomain",
        name: str,
        errors: Optional[List[str]] = None,
    ) -> Optional[float]:
        cat_paths = ("/bin/cat", "/usr/bin/cat")
        for cat_path in cat_paths:
            exec_result = self._run_guest_exec(domain, name, cat_path, args=["/proc/uptime"], errors=errors)
            if not exec_result:
                continue
            exit_code = exec_result.get("exitcode")
            stderr = exec_result.get("stderr") or ""
            if isinstance(exit_code, int) and exit_code != 0:
                stderr_lower = stderr.lower()
                if exit_code == 127 or "not found" in stderr_lower or "no such file" in stderr_lower:
                    continue
                logger.debug(
                    "guest-exec /proc/uptime failed for %s on %s (exitcode=%s, stderr=%s)",
                    name,
                    self._host.hostname,
                    exit_code,
                    stderr,
                )
                return None
            stdout = exec_result.get("stdout") or ""
            uptime = _parse_proc_uptime(stdout)
            if uptime is not None:
                return uptime

        paths = ("/usr/bin/uptime", "/bin/uptime")
        for path in paths:
            exec_result = self._run_guest_exec(domain, name, path, args=["-s"], errors=errors)
            if exec_result:
                exit_code = exec_result.get("exitcode")
                stderr = exec_result.get("stderr") or ""
                if isinstance(exit_code, int) and exit_code != 0:
                    stderr_lower = stderr.lower()
                    if "invalid option" in stderr_lower or "unrecognized option" in stderr_lower:
                        exec_result = None
                    elif exit_code == 127 or "not found" in stderr_lower or "no such file" in stderr_lower:
                        exec_result = None
                    else:
                        logger.debug(
                            "guest-exec uptime -s failed for %s on %s (exitcode=%s, stderr=%s)",
                            name,
                            self._host.hostname,
                            exit_code,
                            stderr,
                        )
                        exec_result = None
                if exec_result:
                    stdout = exec_result.get("stdout") or ""
                    uptime = _parse_uptime_start(stdout)
                    if uptime is not None:
                        return uptime
            if not exec_result:
                exec_result = self._run_guest_exec(domain, name, path, errors=errors)
            if not exec_result:
                continue
            exit_code = exec_result.get("exitcode")
            stderr = exec_result.get("stderr") or ""
            if isinstance(exit_code, int) and exit_code != 0:
                if exit_code == 127 or "not found" in stderr.lower() or "no such file" in stderr.lower():
                    continue
                logger.debug(
                    "guest-exec uptime failed for %s on %s (exitcode=%s, stderr=%s)",
                    name,
                    self._host.hostname,
                    exit_code,
                    stderr,
                )
                return None
            stdout = exec_result.get("stdout") or ""
            uptime = _parse_uptime_output(stdout)
            if uptime is not None:
                return uptime
            _append_warning(errors, _GUEST_EXEC_PARSE_WARNING)
        return None

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
            addresses_by_mac: Dict[str, Dict[str, Any]] = {}
            for addr_entry in addresses.values():
                if not isinstance(addr_entry, dict):
                    continue
                mac = addr_entry.get("hwaddr") or addr_entry.get("mac") or addr_entry.get("addr")
                normalized = _normalize_mac(mac if isinstance(mac, str) else None)
                if normalized:
                    addresses_by_mac[normalized] = addr_entry
            for entry in interfaces:
                addrs = addresses.get(entry.get("target"))
                if isinstance(addrs, dict):
                    entry["addresses"] = addrs.get("addrs")
                    continue
                mac = entry.get("mac")
                normalized = _normalize_mac(mac if isinstance(mac, str) else None)
                if normalized and normalized in addresses_by_mac:
                    mac_entry = addresses_by_mac[normalized]
                    addrs = mac_entry.get("addrs") if isinstance(mac_entry, dict) else None
                    if isinstance(addrs, list):
                        entry["addresses"] = addrs

        info["interfaces"] = interfaces

        memory_stats = safe_call("dommemstat", domain.memoryStats)
        if isinstance(memory_stats, dict):
            info["memory_stats"] = memory_stats
        memory_summary = _build_memory_summary(info.get("dominfo"), memory_stats if isinstance(memory_stats, dict) else None)
        if memory_summary:
            info["memory_summary"] = memory_summary
            missing = [
                key
                for key in ("max_mb", "total_mb", "used_mb", "free_mb", "available_mb")
                if memory_summary.get(key) is None
            ]
            if missing:
                logger.debug(
                    "Memory summary incomplete for %s on %s (missing=%s)",
                    name,
                    self._host.hostname,
                    ", ".join(missing),
                )

        is_active = safe_call("isActive", domain.isActive)
        if is_active:
            error_sink = info.setdefault("errors", [])
            guest_uptime_seconds = self._read_guest_uptime_seconds(domain, name, errors=error_sink)
            if guest_uptime_seconds is not None:
                info["guest_uptime_seconds"] = guest_uptime_seconds
            elif not error_sink:
                _append_warning(error_sink, _GUEST_UPTIME_UNAVAILABLE_WARNING)
            if not error_sink:
                info.pop("errors", None)

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
            metrics["total_memory_mb"] = memory_mb
        if max_memory_mb is not None:
            metrics["max_memory_mb"] = max_memory_mb
        cpu_time_seconds = _ns_to_seconds(cpu_time_ns)
        if cpu_time_seconds is not None:
            metrics["cpu_time_seconds"] = cpu_time_seconds
        try:
            is_active = bool(domain.isActive())
        except libvirt.libvirtError:
            is_active = False

        if is_active:
            try:
                memory_stats = domain.memoryStats()
            except libvirt.libvirtError:
                memory_stats = None
            if isinstance(memory_stats, dict):
                memory_summary = _build_memory_summary(
                    {
                        "maxMem": max_mem_kib,
                        "memory": mem_kib,
                    },
                    memory_stats,
                )
                if memory_summary:
                    total_mb = memory_summary.get("total_mb")
                    used_mb = memory_summary.get("used_mb")
                    if isinstance(total_mb, (int, float)):
                        metrics["total_memory_mb"] = total_mb
                    if isinstance(used_mb, (int, float)):
                        metrics["used_memory_mb"] = used_mb
            guest_uptime_seconds = self._read_guest_uptime_seconds(domain, name)
            if guest_uptime_seconds is not None:
                metrics["uptime_seconds"] = round(guest_uptime_seconds, 2)

        if metrics:
            entry["metrics"] = metrics

        guest_agent_ips: List[str] = []
        addresses = None
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
