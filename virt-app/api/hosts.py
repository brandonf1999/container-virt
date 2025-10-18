import asyncio
import asyncio.subprocess
import contextlib
import logging
import os
import socket
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Literal, Optional, Tuple

from fastapi import APIRouter, HTTPException, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, model_validator

from app.core.console_sessions import console_session_manager
from app.deps import get_cluster
from app.libvirt.host import (
    StorageError,
    StoragePoolNotFoundError,
    StoragePoolNotEmptyError,
    StorageVolumeInUseError,
    StorageVolumeExistsError,
    StorageVolumeNotFoundError,
    DomainExistsError,
    DomainNotFoundError,
    DomainActiveError,
    DomainNotRunningError,
    DomainDeviceNotFoundError,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/hosts", tags=["Hosts"])


def _get_required_host(cluster, hostname: str):
    host = cluster.hosts.get(hostname)
    if not host:
        raise HTTPException(status_code=404, detail=f"Host {hostname} not found")
    return host


def _ensure_host_connection(host, hostname: str, *, error_status: int = 500) -> None:
    if host.conn:
        return
    if not host.connect():
        raise HTTPException(status_code=error_status, detail=f"Failed to connect to {hostname}")


def _call_cluster_operation(operation: Callable[[], object], *, hostname: str):
    try:
        return operation()
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Host {hostname} not found")
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


def _parse_ssh_target(target: str) -> Tuple[Optional[str], str, Optional[int]]:
    target = (target or "").strip()
    username: Optional[str] = None
    hostname = target
    port: Optional[int] = None

    if "@" in hostname:
        username, hostname = hostname.split("@", 1)
        username = username or None

    if ":" in hostname:
        host_part, port_part = hostname.rsplit(":", 1)
        hostname = host_part or hostname
        try:
            port = int(port_part)
        except ValueError:
            port = None

    return username, hostname, port


class DomainActionRequest(BaseModel):
  action: str


class StorageVolumeDeleteResponse(BaseModel):
    host: str
    pool: str
    volume: str
    deleted: bool
    force: bool = False
    path: Optional[str]
    capacity_bytes: Optional[int]
    allocation_bytes: Optional[int]


class StoragePoolSummary(BaseModel):
    name: str
    state: Optional[str] = None
    persistent: Optional[bool] = None
    autostart: Optional[bool] = None
    capacity_bytes: Optional[int] = None
    allocation_bytes: Optional[int] = None
    available_bytes: Optional[int] = None


class StorageVolumeSummary(BaseModel):
    name: str
    path: Optional[str] = None
    key: Optional[str] = None
    type: Optional[str] = None
    format: Optional[str] = None
    capacity_bytes: Optional[int] = None
    allocation_bytes: Optional[int] = None
    available_bytes: Optional[int] = None
    backing_store: Optional[str] = None
    state: Optional[str] = None


class StorageVolumeUploadSummary(BaseModel):
    bytes: int
    overwrite: bool = False
    format: Optional[str] = None


class StorageVolumeDetailsResponse(BaseModel):
    host: str
    pool: StoragePoolSummary
    volume: StorageVolumeSummary
    attached_domains: List[str]
    xml: Optional[str] = None
    upload: Optional[StorageVolumeUploadSummary] = None


class StoragePoolDeleteResponse(BaseModel):
    host: str
    pool: str
    deleted: bool
    force: bool = False
    state: Optional[str] = None
    persistent: Optional[bool] = None
    autostart: Optional[bool] = None
    capacity_bytes: Optional[int] = None
    allocation_bytes: Optional[int] = None
    available_bytes: Optional[int] = None
    type: Optional[str] = None
    volumes: Optional[List[str]] = None
    was_active: Optional[bool] = None


class GuestVolumeSpec(BaseModel):
    name: str
    pool: str
    type: Literal["disk", "iso"] = "disk"
    size_mb: Optional[int] = None
    format: Optional[str] = "qcow2"
    source_volume: Optional[str] = None
    source_path: Optional[str] = None
    boot: bool = False

    @model_validator(mode="after")
    def _check_volume(self) -> "GuestVolumeSpec":
        if self.type == "disk":
            has_external_source = bool(self.source_path or self.source_volume)
            if self.size_mb is not None and self.size_mb <= 0:
                raise ValueError("Disk volume size_mb must be positive when provided")
            if not has_external_source and (self.size_mb is None or self.size_mb <= 0):
                raise ValueError(
                    "Disk volumes must include size_mb when source_path or source_volume is not provided"
                )
        if self.type == "iso":
            if not self.source_path and not self.source_volume:
                raise ValueError("ISO volumes must specify source_path or source_volume")
        return self


class GuestNetworkSpec(BaseModel):
    network: str
    mac: Optional[str] = None
    model: Optional[str] = None


class GuestCreateRequest(BaseModel):
    name: str
    vcpus: int
    memory_mb: int
    autostart: bool = False
    start: bool = True
    description: Optional[str] = None
    volumes: List[GuestVolumeSpec]
    networks: List[GuestNetworkSpec] = []
    enable_vnc: Optional[bool] = None
    vnc_password: Optional[str] = None

    @model_validator(mode="after")
    def _check_guest(self) -> "GuestCreateRequest":
        if not self.volumes:
            raise ValueError("At least one storage volume must be defined")
        if self.vcpus <= 0:
            raise ValueError("vcpus must be greater than zero")
        if self.memory_mb <= 0:
            raise ValueError("memory_mb must be greater than zero")
        if self.enable_vnc is True:
            password = (self.vnc_password or "").strip()
            if not password:
                raise ValueError("vnc_password is required when enable_vnc is true")
            if len(password) < 6:
                raise ValueError("vnc_password must be at least 6 characters")
            if len(password) > 64:
                raise ValueError("vnc_password must be 64 characters or fewer")
            if not password.isascii():
                raise ValueError("vnc_password must contain only ASCII characters")
            self.vnc_password = password
        return self


class DomainDetailsResponse(BaseModel):
    host: str
    domain: str
    details: dict


class GuestCloneMetadata(BaseModel):
    vnc_password: Optional[str] = None
    mac_addresses: List[str] = Field(default_factory=list)


class GuestCloneResponse(DomainDetailsResponse):
    clone: Optional[GuestCloneMetadata] = None


class GuestCloneRequest(BaseModel):
    name: str
    autostart: Optional[bool] = None
    start: bool = False
    description: Optional[str] = None
    target_host: Optional[str] = None

    @model_validator(mode="after")
    def _validate(self) -> "GuestCloneRequest":
        if not self.name or not self.name.strip():
            raise ValueError("name is required")
        self.name = self.name.strip()
        return self


class ConsoleSessionResponse(BaseModel):
    token: str
    expires_at: int
    websocket_path: str
    password: str


class GuestDeleteResponse(BaseModel):
    host: str
    domain: str
    removed: bool
    forced: bool = False
    was_active: bool = False

@router.get("/")
def list_hosts():
    cluster = get_cluster()
    return {"hosts": list(cluster.hosts.keys())}

@router.get("/{hostname}/vms")
def list_vms_for_host(hostname: str):
    cluster = get_cluster()
    host = _get_required_host(cluster, hostname)
    _ensure_host_connection(host, hostname)
    try:
        vms = host.list_vms()
        logger.info("Listed %d VMs for host %s", len(vms), hostname)
        return {"host": hostname, "vms": vms}
    except Exception as e:
        logger.exception("Error listing VMs for %s: %s", hostname, e)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{hostname}/connect")
def connect_host(hostname: str):
    cluster = get_cluster()
    host = _get_required_host(cluster, hostname)
    ok = host.connect()
    return {"host": hostname, "connected": bool(ok)}

@router.post("/{hostname}/disconnect")
def disconnect_host(hostname: str):
    cluster = get_cluster()
    host = _get_required_host(cluster, hostname)
    host.disconnect()
    return {"host": hostname, "disconnected": True}


@router.get("/{hostname}/vms/{name}")
def get_domain_details(hostname: str, name: str):
    cluster = get_cluster()
    try:
        details = _call_cluster_operation(
            lambda: cluster.get_domain_details(hostname, name),
            hostname=hostname,
        )
        return {
            "host": hostname,
            "domain": name,
            "details": details,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to gather domain details for %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{hostname}/info")
def get_host_details(hostname: str):
    cluster = get_cluster()
    try:
        details = _call_cluster_operation(
            lambda: cluster.get_host_details(hostname),
            hostname=hostname,
        )
        return {"host": hostname, "details": details}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to gather host details for %s: %s", hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{hostname}/vms/{name}/actions")
def control_domain(hostname: str, name: str, body: DomainActionRequest):
    cluster = get_cluster()
    try:
        ok = _call_cluster_operation(
            lambda: cluster.control_domain(hostname, name, body.action),
            hostname=hostname,
        )
        if not ok:
            raise HTTPException(status_code=500, detail=f"Failed to execute {body.action} on {name}")
        return {
            "host": hostname,
            "domain": name,
            "action": body.action,
            "status": "ok",
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to execute %s for %s on %s: %s", body.action, name, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{hostname}/vms/{name}/connect")
def generate_domain_console_file(hostname: str, name: str):
    cluster = get_cluster()
    try:
        result = _call_cluster_operation(
            lambda: cluster.generate_guest_console_file(hostname, name),
            hostname=hostname,
        )
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainNotRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to prepare console file for %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail="Failed to generate console connection") from exc

    content = result.get("content")
    if not content:
        raise HTTPException(status_code=500, detail="Console file rendering failed")

    filename = result.get("filename") or f"{name}-console.sh"
    safe_filename = str(filename).replace('"', "")
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
    }

    host = result.get("host")
    port = result.get("port")
    if host:
        headers["X-Console-Host"] = str(host)
    if port:
        headers["X-Console-Port"] = str(port)

    return Response(content=content, media_type="text/x-shellscript", headers=headers)


@router.post("/{hostname}/vms/{name}/console-session", response_model=ConsoleSessionResponse)
async def create_console_session(hostname: str, name: str):
    cluster = get_cluster()
    try:
        result = _call_cluster_operation(
            lambda: cluster.generate_guest_console_file(hostname, name),
            hostname=hostname,
        )
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainNotRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to prepare console session for %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail="Failed to create console session") from exc

    host = result.get("host")
    port = result.get("port")
    password = result.get("password")

    if not host or not port or not password:
        raise HTTPException(status_code=500, detail="Console session metadata incomplete")

    try:
        port_value = int(port)
    except (TypeError, ValueError):
        raise HTTPException(status_code=500, detail="Invalid console port reported")

    ssh_target = result.get("ssh_target")
    session_payload = await console_session_manager.create(
        hostname,
        name,
        host=str(host),
        port=port_value,
        password=str(password),
        ssh_target=str(ssh_target) if ssh_target else None,
    )

    websocket_path = f"/api/hosts/{hostname}/vms/{name}/console/{session_payload['token']}"

    return ConsoleSessionResponse(
        token=session_payload["token"],
        expires_at=int(session_payload["expires_at"]),
        websocket_path=websocket_path,
        password=str(password),
    )


@router.get("/{hostname}/storage/pools/{pool}/volumes/{volume}", response_model=StorageVolumeDetailsResponse)
def get_storage_volume(hostname: str, pool: str, volume: str):
    cluster = get_cluster()
    try:
        result = _call_cluster_operation(
            lambda: cluster.describe_storage_volume(hostname, pool, volume),
            hostname=hostname,
        )
        return result
    except HTTPException:
        raise
    except StoragePoolNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageVolumeNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception(
            "Failed to inspect volume %s/%s on %s: %s", pool, volume, hostname, exc
        )
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/{hostname}/storage/pools/{pool}/volumes/{volume}", response_model=StorageVolumeDeleteResponse)
def delete_storage_volume(hostname: str, pool: str, volume: str, force: bool = False):
    cluster = get_cluster()
    try:
        result = _call_cluster_operation(
            lambda: cluster.delete_storage_volume(hostname, pool, volume, force=force),
            hostname=hostname,
        )
        return result
    except HTTPException:
        raise
    except StoragePoolNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageVolumeNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageVolumeInUseError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": str(exc),
                "domains": exc.domains,
            },
        )
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception(
            "Failed to delete volume %s/%s on %s: %s", pool, volume, hostname, exc
        )
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/{hostname}/storage/pools/{pool}/upload",
    response_model=StorageVolumeDetailsResponse,
)
async def upload_storage_volume(
    hostname: str,
    pool: str,
    file: UploadFile = File(...),
    volume: Optional[str] = Form(None),
    overwrite: bool = Form(False),
    volume_format: Optional[str] = Form("raw"),
):
    cluster = get_cluster()

    filename = file.filename or ""
    volume_name = (volume or Path(filename).name or "").strip()
    if not volume_name:
        raise HTTPException(status_code=400, detail="Volume name is required")
    if any(sep in volume_name for sep in ("/", "\\")) or volume_name in {".", ".."}:
        raise HTTPException(status_code=400, detail="Volume name contains invalid characters")

    normalized_format = (volume_format or "").strip().lower() or None

    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    total_bytes = 0
    try:
        chunk_size = 4 * 1024 * 1024
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            tmp_file.write(chunk)
            total_bytes += len(chunk)
        tmp_file.flush()
    finally:
        tmp_file.close()

    await file.close()

    if total_bytes <= 0:
        try:
            os.unlink(tmp_file.name)
        except FileNotFoundError:
            pass
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        result = await run_in_threadpool(
            lambda: _call_cluster_operation(
                lambda: cluster.upload_storage_volume(
                    hostname,
                    pool,
                    volume_name,
                    tmp_file.name,
                    size_bytes=total_bytes,
                    overwrite=overwrite,
                    volume_format=normalized_format,
                ),
                hostname=hostname,
            )
        )
        return result
    except HTTPException:
        raise
    except StoragePoolNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageVolumeExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageVolumeInUseError as exc:
        raise HTTPException(
            status_code=409,
            detail={"message": str(exc), "domains": exc.domains},
        )
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception(
            "Failed to upload volume %s to pool %s on %s: %s",
            volume_name,
            pool,
            hostname,
            exc,
        )
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        try:
            os.unlink(tmp_file.name)
        except FileNotFoundError:
            pass


@router.post("/{hostname}/vms", response_model=DomainDetailsResponse)
async def create_guest_host(hostname: str, request: GuestCreateRequest):
    cluster = get_cluster()

    volume_payload = [volume.model_dump() for volume in request.volumes]
    network_payload = [network.model_dump() for network in request.networks]

    try:
        result = await run_in_threadpool(
            lambda: _call_cluster_operation(
                lambda: cluster.create_guest(
                    hostname,
                    name=request.name,
                    vcpus=request.vcpus,
                    memory_mb=request.memory_mb,
                    autostart=request.autostart,
                    start=request.start,
                    description=request.description,
                    volumes=volume_payload,
                    networks=network_payload,
                    enable_vnc=request.enable_vnc,
                    vnc_password=request.vnc_password,
                ),
                hostname=hostname,
            )
        )
        return result
    except HTTPException:
        raise
    except DomainExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StoragePoolNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageVolumeExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageVolumeNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to create guest %s on %s: %s", request.name, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))




@router.delete("/{hostname}/vms/{name}/devices/block/{target}", response_model=DomainDetailsResponse)
async def detach_guest_block_device(hostname: str, name: str, target: str):
    cluster = get_cluster()
    try:
        result = await run_in_threadpool(
            lambda: _call_cluster_operation(
                lambda: cluster.detach_guest_block_device(hostname, name, target),
                hostname=hostname,
            )
        )
        return result
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainDeviceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to detach device %s from %s on %s: %s", target, name, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))

@router.post("/{hostname}/vms/{name}/clone", response_model=GuestCloneResponse)
async def clone_guest_host(hostname: str, name: str, request: GuestCloneRequest):
    if request.target_host and request.target_host != hostname:
        raise HTTPException(status_code=400, detail="Cross-host cloning is not supported")
    if request.name == name:
        raise HTTPException(status_code=400, detail="Clone name must differ from source")

    cluster = get_cluster()
    try:
        result = await run_in_threadpool(
            lambda: _call_cluster_operation(
                lambda: cluster.clone_guest(
                    hostname,
                    name,
                    new_name=request.name,
                    autostart=request.autostart,
                    start=request.start,
                    description=request.description,
                ),
                hostname=hostname,
            )
        )
        return GuestCloneResponse(**result)
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except DomainActiveError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to clone guest %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/{hostname}/vms/{name}", response_model=GuestDeleteResponse)
async def delete_guest_host(hostname: str, name: str, force: bool = False, remove_storage: bool = False):
    cluster = get_cluster()

    try:
        result = await run_in_threadpool(
            lambda: _call_cluster_operation(
                lambda: cluster.delete_guest(hostname, name, force=force, remove_storage=remove_storage),
                hostname=hostname,
            )
        )
        return result
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainActiveError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to delete guest %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.websocket("/{hostname}/vms/{name}/console/{token}")
async def console_websocket(websocket: WebSocket, hostname: str, name: str, token: str):
    session = await console_session_manager.consume(token, hostname, name)
    if not session:
        await websocket.close(code=4401, reason="Invalid or expired console token")
        return

    await websocket.accept()

    host = str(session.get("host"))
    port_value = session.get("port")
    try:
        port = int(port_value) if port_value is not None else None
    except (TypeError, ValueError):
        port = None

    if not host or not isinstance(port, int):
        await websocket.close(code=1011, reason="Console session missing host metadata")
        return

    ssh_target = session.get("ssh_target") or None
    tunnel_proc: Optional[asyncio.subprocess.Process] = None

    async def _open_vnc_via_ssh(target: str) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, asyncio.subprocess.Process]:
        username, ssh_host, ssh_port = _parse_ssh_target(target)
        if not ssh_host:
            raise RuntimeError("SSH target missing hostname")

        destination = ssh_host if username is None else f"{username}@{ssh_host}"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            local_port = probe.getsockname()[1]

        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=2",
            "-N",
        ]
        if ssh_port:
            cmd.extend(["-p", str(ssh_port)])
        cmd.extend(["-L", f"{local_port}:{host}:{port}", destination])

        logger.debug(
            "Launching SSH tunnel for %s@%s via %s (localhost:%s -> %s:%s)",
            name,
            hostname,
            destination,
            local_port,
            host,
            port,
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Wait for local forward to come up
        for _ in range(50):
            try:
                test_reader, test_writer = await asyncio.open_connection("127.0.0.1", local_port)
                test_writer.close()
                await test_writer.wait_closed()
                break
            except (ConnectionRefusedError, OSError):
                await asyncio.sleep(0.1)
        else:
            stderr_output = b""
            if proc.stderr is not None:
                try:
                    stderr_output = await asyncio.wait_for(proc.stderr.read(), timeout=0.5)
                except Exception:
                    pass
            proc.terminate()
            with contextlib.suppress(Exception):
                await proc.wait()
            detail = stderr_output.decode().strip() or "no details"
            raise RuntimeError(f"SSH tunnel setup failed via {destination}: {detail}")

        reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
        logger.info(
            "SSH tunnel established for %s@%s (%s:%s via %s)",
            name,
            hostname,
            host,
            port,
            destination,
        )
        return reader, writer, proc

    prefer_tunnel = bool(ssh_target) and host in {"127.0.0.1", "::1", "localhost"}

    try:
        if prefer_tunnel and ssh_target:
            reader, writer, tunnel_proc = await _open_vnc_via_ssh(str(ssh_target))
        else:
            reader, writer = await asyncio.open_connection(host, port)
            logger.debug(
                "Direct VNC connection established for %s@%s (%s:%s)",
                name,
                hostname,
                host,
                port,
            )
            logger.debug(
                "Direct VNC connection established for %s@%s (%s:%s)",
                name,
                hostname,
                host,
                port,
            )
    except (OSError, socket.gaierror) as exc:
        if not ssh_target:
            logger.error(
                "Failed to connect to VNC endpoint %s:%s for %s on %s: %s",
                host,
                port,
                name,
                hostname,
                exc,
            )
            await websocket.close(code=1011, reason="Unable to reach VNC endpoint")
            return
        try:
            logger.info(
                "Direct VNC connection failed for %s@%s (%s:%s); attempting SSH tunnel via %s",
                name,
                hostname,
                host,
                port,
                ssh_target,
            )
            reader, writer, tunnel_proc = await _open_vnc_via_ssh(str(ssh_target))
        except Exception as ssh_exc:
            logger.error(
                "SSH tunnel establishment failed for %s on %s (%s -> %s:%s): %s",
                name,
                hostname,
                ssh_target,
                host,
                port,
                ssh_exc,
            )
            await websocket.close(code=1011, reason="Unable to reach VNC endpoint via SSH")
            return

    async def ws_to_tcp() -> None:
        try:
            while True:
                message = await websocket.receive()
                message_type = message.get("type")
                if message_type == "websocket.disconnect":
                    break
                data = message.get("bytes")
                if data is None:
                    text = message.get("text")
                    if text is None:
                        continue
                    data = text.encode("utf-8")
                writer.write(data)
                await writer.drain()
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.debug("WebSocket -> TCP relay ended for %s on %s: %s", name, hostname, exc)

    async def tcp_to_ws() -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                await websocket.send_bytes(chunk)
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.debug("TCP -> WebSocket relay ended for %s on %s: %s", name, hostname, exc)

    ws_task = asyncio.create_task(ws_to_tcp())
    tcp_task = asyncio.create_task(tcp_to_ws())

    try:
        await asyncio.wait({ws_task, tcp_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        ws_task.cancel()
        tcp_task.cancel()
        for task in (ws_task, tcp_task):
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        try:
            writer.close()
            wait_closed = getattr(writer, "wait_closed", None)
            if callable(wait_closed):
                await wait_closed()
        except Exception:
            pass
        if tunnel_proc is not None:
            try:
                tunnel_proc.terminate()
                await asyncio.wait_for(tunnel_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                tunnel_proc.kill()
                await tunnel_proc.wait()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass


@router.delete("/{hostname}/storage/pools/{pool}", response_model=StoragePoolDeleteResponse)
def delete_storage_pool(hostname: str, pool: str, force: bool = False):
    cluster = get_cluster()
    try:
        result = _call_cluster_operation(
            lambda: cluster.delete_storage_pool(hostname, pool, force=force),
            hostname=hostname,
        )
        return result
    except HTTPException:
        raise
    except StoragePoolNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except StoragePoolNotEmptyError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": str(exc),
                "volumes": exc.volumes,
            },
        )
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to delete pool %s on %s: %s", pool, hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))
