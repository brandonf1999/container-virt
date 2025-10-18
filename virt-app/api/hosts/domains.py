from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator

from app.deps import get_cluster
from app.libvirt.errors import (
    DomainActiveError,
    DomainDeviceNotFoundError,
    DomainExistsError,
    DomainNotFoundError,
    DomainNotRunningError,
    StorageError,
    StoragePoolNotFoundError,
    StorageVolumeExistsError,
    StorageVolumeNotFoundError,
)

from .common import (
    call_cluster_operation,
    execute_cluster_task,
    get_required_host,
    ensure_host_connection,
    logger,
)

router = APIRouter()


class DomainActionRequest(BaseModel):
    action: str


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
    details: Dict[str, Any]


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


class GuestDeleteResponse(BaseModel):
    host: str
    domain: str
    removed: bool
    forced: bool = False
    was_active: bool = False


@router.get("/{hostname}/vms")
def list_vms_for_host(hostname: str):
    cluster = get_cluster()
    host = get_required_host(cluster, hostname)
    ensure_host_connection(host, hostname)
    try:
        vms = host.list_vms()
        logger.info("Listed %d VMs for host %s", len(vms), hostname)
        return {"host": hostname, "vms": vms}
    except Exception as exc:
        logger.exception("Error listing VMs for %s: %s", hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{hostname}/vms/{name}")
def get_domain_details(hostname: str, name: str):
    cluster = get_cluster()
    try:
        details = call_cluster_operation(
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


@router.post("/{hostname}/vms/{name}/actions")
def control_domain(hostname: str, name: str, body: DomainActionRequest):
    cluster = get_cluster()
    try:
        ok = call_cluster_operation(
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


@router.post("/{hostname}/vms", response_model=DomainDetailsResponse)
async def create_guest_host(hostname: str, request: GuestCreateRequest):
    cluster = get_cluster()

    volume_payload = [volume.model_dump() for volume in request.volumes]
    network_payload = [network.model_dump() for network in request.networks]

    try:
        result = await execute_cluster_task(
            cluster.create_guest,
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
        result = await execute_cluster_task(
            cluster.detach_guest_block_device,
            hostname,
            name,
            target,
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
        result = await execute_cluster_task(
            cluster.clone_guest,
            hostname,
            name,
            new_name=request.name,
            autostart=request.autostart,
            start=request.start,
            description=request.description,
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
        result = await execute_cluster_task(
            cluster.delete_guest,
            hostname,
            name,
            force=force,
            remove_storage=remove_storage,
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


__all__ = [
    "router",
    "DomainActionRequest",
    "GuestCreateRequest",
    "GuestCloneRequest",
    "GuestCloneResponse",
    "GuestDeleteResponse",
]
