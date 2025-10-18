from __future__ import annotations

import logging
import shlex
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

import libvirt

from .common import lookup_domain
from ..errors import DomainNotRunningError, StorageError

if TYPE_CHECKING:
    from ..host import LibvirtHost

logger = logging.getLogger(__name__)


class LibvirtDomainConsole:
    """Handles runtime console/VNC helpers for a libvirt host."""

    def __init__(
        self,
        host: "LibvirtHost",
        retry_decider,
    ) -> None:
        self._host = host
        self._should_retry = retry_decider

    def generate_vnc_connection_file(self, name: str) -> Dict[str, Any]:
        domain = lookup_domain(self._host, self._should_retry, name)

        try:
            info = domain.info()
        except libvirt.libvirtError as exc:
            logger.error("info() failed for %s on %s: %s", name, self._host.hostname, exc)
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
            logger.error("XMLDesc() failed for %s on %s: %s", name, self._host.hostname, exc)
            raise StorageError(f"Failed to inspect graphics configuration for '{name}': {exc}") from exc

        try:
            root = ET.fromstring(xml_desc)
        except ET.ParseError as exc:
            logger.error("Failed to parse domain XML for %s on %s: %s", name, self._host.hostname, exc)
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
            listen_address = self._host.hostname

        existing_password = (graphics.get("passwd") or "").strip() or None
        password: Optional[str] = None
        password_error: Optional[str] = None

        if existing_password:
            password = existing_password
        else:
            password, password_error = self._mint_vnc_password(domain, name, graphics)

        if password is None:
            hint = (
                "Configure a static VNC password in the domain XML or upgrade libvirt to enable runtime password updates."
            )
            detail = (
                f"Unable to set VNC password for '{name}' on {self._host.hostname}: "
                f"{password_error or 'runtime password updates are not supported.'} {hint}"
            )
            raise StorageError(detail)

        issued_at = int(time.time())

        default_ssh_target = self._host.hostname
        if self._host.user:
            default_ssh_target = f"{self._host.user}@{self._host.hostname}"

        script_lines = self._build_console_script(name, listen_address, port, password, default_ssh_target)

        return {
            "host": listen_address,
            "port": port,
            "password": password,
            "issued_at": issued_at,
            "filename": f"{name}-console.sh",
            "content": "\n".join(script_lines) + "\n",
            "ssh_target": default_ssh_target,
        }

    def _mint_vnc_password(
        self,
        domain: "libvirt.virDomain",
        name: str,
        graphics: ET.Element,
    ) -> Tuple[Optional[str], Optional[str]]:
        minted_password = self._host._generate_password()  # pylint: disable=protected-access
        password_flags = 0
        for attr in ("VIR_DOMAIN_PASSWORD_SET_AFFECT_LIVE", "VIR_DOMAIN_PASSWORD_SET_AFFECT_CURRENT"):
            flag_value = getattr(libvirt, attr, 0)
            if isinstance(flag_value, int):
                password_flags |= flag_value

        set_password = getattr(domain, "setPassword", None)
        password_error: Optional[str] = None
        if callable(set_password):
            try:
                set_password("vnc", minted_password, password_flags)
                return minted_password, None
            except libvirt.libvirtError as exc:  # pragma: no cover - logging branch
                logger.warning(
                    "setPassword failed for %s on %s; attempting XML graphics update: %s",
                    name,
                    self._host.hostname,
                    exc,
                )
                password_error = str(exc)
        else:
            logger.debug("setPassword unavailable for %s on %s; attempting XML graphics update", name, self._host.hostname)

        modify_flags = 0
        for attr in ("VIR_DOMAIN_DEVICE_MODIFY_LIVE", "VIR_DOMAIN_DEVICE_MODIFY_CURRENT"):
            flag_value = getattr(libvirt, attr, 0)
            if isinstance(flag_value, int):
                modify_flags |= flag_value

        updated_graphics = ET.Element("graphics", graphics.attrib)
        updated_graphics.set("passwd", minted_password)
        try:
            valid_until = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 300))
            updated_graphics.set("passwdValidTo", valid_until)
        except Exception:  # pragma: no cover - defensive
            pass
        for child in list(graphics):
            updated_graphics.append(child)

        update_device = getattr(domain, "updateDeviceFlags", None)
        if callable(update_device):
            try:
                update_device(
                    ET.tostring(updated_graphics, encoding="unicode", method="xml"),
                    modify_flags,
                )
                return minted_password, None
            except libvirt.libvirtError as exc:  # pragma: no cover - logging path
                logger.warning(
                    "updateDeviceFlags failed to set VNC password for %s on %s: %s",
                    name,
                    self._host.hostname,
                    exc,
                )
                password_error = password_error or str(exc)
        else:
            logger.debug("updateDeviceFlags unavailable for %s on %s", name, self._host.hostname)

        return None, password_error

    def _build_console_script(
        self,
        name: str,
        listen_address: str,
        port: int,
        password: str,
        default_ssh_target: str,
    ) -> List[str]:
        return [
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
