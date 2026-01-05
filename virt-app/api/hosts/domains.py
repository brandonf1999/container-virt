import asyncio
import time
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, model_validator

from app.deps import get_cluster
from app.db import async_session_dependency
from app.db.repositories.domains import (
    adopt_domain_from_inventory,
    list_domain_uuids_for_host,
    sync_domain_inventory,
)
from app.db.repositories.hosts import get_host_by_libvirt_id
from app.core.auto_eject import schedule_iso_auto_eject
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
    cpu_mode: Literal["host-model", "host-passthrough"] = "host-model"
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


class AdoptableGuest(BaseModel):
    name: str
    uuid: str
    state: Optional[str] = None
    persistent: Optional[bool] = None


class AdoptableGuestsResponse(BaseModel):
    host: str
    guests: List[AdoptableGuest]


class GuestAdoptRequest(BaseModel):
    uuid: str


class GuestAdoptResponse(BaseModel):
    host: str
    domain: str
    uuid: str
    status: Literal["adopted", "exists"]


class GuestMoveRequest(BaseModel):
    target_host: str
    mode: Literal["live", "cold"] = "live"
    start: bool = False
    shutdown_timeout: int = Field(default=60, ge=5, le=600)
    force: bool = False


class GuestMoveResponse(BaseModel):
    source_host: str
    target_host: str
    domain: str
    uuid: Optional[str] = None
    started: bool
    status: Literal["migrated"]


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


@router.get("/{hostname}/vms/adoptable", response_model=AdoptableGuestsResponse)
async def list_adoptable_guests(hostname: str, db_session=Depends(async_session_dependency())):
    cluster = get_cluster()
    host = get_required_host(cluster, hostname)
    ensure_host_connection(host, hostname)

    try:
        inventory = await run_in_threadpool(host.get_vm_inventory)
    except Exception as exc:
        logger.exception("Failed to gather VM inventory for adoption on %s: %s", hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))

    host_record = await get_host_by_libvirt_id(db_session, hostname=hostname)
    if host_record is None:
        raise HTTPException(status_code=404, detail=f"Host {hostname} is not managed in the database")

    known = await list_domain_uuids_for_host(db_session, host=host_record)
    adoptable: List[AdoptableGuest] = []
    vm_entries = inventory.get("vms") if isinstance(inventory, dict) else []
    for entry in vm_entries or []:
        if not isinstance(entry, dict):
            continue
        uuid_text = entry.get("uuid")
        if not uuid_text or uuid_text in known:
            continue
        persistent = entry.get("persistent")
        adoptable.append(
            AdoptableGuest(
                name=str(entry.get("name") or uuid_text),
                uuid=uuid_text,
                state=entry.get("state"),
                persistent=persistent if isinstance(persistent, bool) else None,
            )
        )

    return {"host": hostname, "guests": adoptable}


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


@router.post("/{hostname}/vms/{name}/adopt", response_model=GuestAdoptResponse)
async def adopt_guest(
    hostname: str,
    name: str,
    request: GuestAdoptRequest,
    db_session=Depends(async_session_dependency()),
):
    cluster = get_cluster()
    host = get_required_host(cluster, hostname)
    ensure_host_connection(host, hostname)

    host_record = await get_host_by_libvirt_id(db_session, hostname=hostname)
    if host_record is None:
        raise HTTPException(status_code=404, detail=f"Host {hostname} is not managed in the database")

    try:
        inventory = await run_in_threadpool(host.get_vm_inventory)
    except Exception as exc:
        logger.exception("Failed to gather VM inventory for adoption on %s: %s", hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))

    vm_entries = inventory.get("vms") if isinstance(inventory, dict) else []
    target_entry: Optional[Dict[str, Any]] = None
    for entry in vm_entries or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("uuid") == request.uuid:
            target_entry = entry
            break

    if target_entry is None:
        raise HTTPException(status_code=404, detail=f"VM {name} with UUID {request.uuid} was not found on {hostname}")

    existing = await list_domain_uuids_for_host(db_session, host=host_record)
    already_tracked = request.uuid in existing

    try:
        domain = await adopt_domain_from_inventory(
            db_session,
            host=host_record,
            payload=target_entry,
        )
        await db_session.commit()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    status = "exists" if already_tracked else "adopted"
    return {
        "host": hostname,
        "domain": domain.name,
        "uuid": str(domain.uuid),
        "status": status,
    }


@router.post("/{hostname}/vms/{name}/move", response_model=GuestMoveResponse)
async def move_guest_host(
    hostname: str,
    name: str,
    request: GuestMoveRequest,
    db_session=Depends(async_session_dependency()),
):
    cluster = get_cluster()
    target_host_name = request.target_host.strip()
    if not target_host_name:
        raise HTTPException(status_code=400, detail="target_host is required")
    if target_host_name == hostname:
        raise HTTPException(status_code=400, detail="Target host must differ from source host")

    source_host = get_required_host(cluster, hostname)
    target_host = get_required_host(cluster, target_host_name)
    ensure_host_connection(source_host, hostname)
    ensure_host_connection(target_host, target_host_name)

    source_host_record = await get_host_by_libvirt_id(db_session, hostname=hostname)
    target_host_record = await get_host_by_libvirt_id(db_session, hostname=target_host_name)
    if source_host_record is None:
        raise HTTPException(status_code=404, detail=f"Host {hostname} is not managed in the database")
    if target_host_record is None:
        raise HTTPException(status_code=404, detail=f"Host {target_host_name} is not managed in the database")

    async def _fetch_domain_details() -> Dict[str, Any]:
        return await run_in_threadpool(
            lambda: call_cluster_operation(
                lambda: cluster.get_domain_details(hostname, name),
                hostname=hostname,
            )
        )

    details_envelope = await _fetch_domain_details()
    domain_details = details_envelope.get("details") or {}
    state = (domain_details.get("state") or "").strip().lower()
    autostart_flag = domain_details.get("autostart")
    domain_xml = domain_details.get("metadata")
    def _apply_snapshot(snapshot: Dict[str, Any]) -> None:
        nonlocal domain_details, domain_xml, autostart_flag, state
        new_details = snapshot.get("details")
        if isinstance(new_details, dict) and new_details:
            domain_details = new_details
        snapshot_state = (domain_details.get("state") or "").strip().lower()
        if snapshot_state:
            state = snapshot_state
        if "autostart" in domain_details:
            autostart_flag = domain_details.get("autostart", autostart_flag)
        metadata = domain_details.get("metadata")
        if metadata:
            domain_xml = metadata
    _apply_snapshot(details_envelope)
    running_states = {"running", "blocked"}
    if request.mode == "live":
        logger.info("Starting live migration for %s from %s to %s", name, hostname, target_host_name)
        try:
            migrate_result = await execute_cluster_task(
                cluster.migrate_guest,
                hostname,
                name,
                target_host_name,
                live=True,
                shared_storage=True,
                autostart=autostart_flag if isinstance(autostart_flag, bool) else None,
            )
        except DomainNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except DomainNotRunningError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"{exc}. Use cold migration to move a stopped guest.",
            )
        except StorageError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception(
                "Failed to live migrate domain %s from %s to %s: %s",
                name,
                hostname,
                target_host_name,
                exc,
            )
            raise HTTPException(status_code=500, detail=f"Failed to live migrate domain on {target_host_name}: {exc}")

        try:
            source_inventory = await run_in_threadpool(source_host.get_vm_inventory)
            target_inventory = await run_in_threadpool(target_host.get_vm_inventory)
            await sync_domain_inventory(db_session, host=source_host_record, inventory=source_inventory)
            await sync_domain_inventory(db_session, host=target_host_record, inventory=target_inventory)
            await db_session.commit()
        except Exception as exc:
            logger.error("Failed to sync domain inventory after moving %s: %s", name, exc)

        return {
            "source_host": hostname,
            "target_host": target_host_name,
            "domain": name,
            "uuid": migrate_result.get("uuid"),
            "started": bool(migrate_result.get("started")),
            "status": "migrated",
        }

    if not domain_xml:
        try:
            domain_xml = await execute_cluster_task(cluster.get_domain_xml, hostname, name)
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to fetch XML for %s on %s: %s", name, hostname, exc)
            raise HTTPException(status_code=500, detail="Domain metadata is unavailable; cannot migrate") from exc
    if not domain_xml:
        raise HTTPException(status_code=500, detail="Domain metadata is unavailable; cannot migrate")

    shutdown_timeout = max(5, min(request.shutdown_timeout, 600))

    async def _wait_for_shutdown(timeout_seconds: int) -> Dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        latest = details_envelope
        while time.monotonic() < deadline:
            latest = await _fetch_domain_details()
            latest_state = (latest.get("details") or {}).get("state")
            if isinstance(latest_state, str) and latest_state.strip().lower() not in running_states:
                return latest
            await asyncio.sleep(2)
        return latest

    if state in running_states:
        action = "force-off" if request.force else "shutdown"
        await execute_cluster_task(cluster.control_domain, hostname, name, action)
        latest = await _wait_for_shutdown(shutdown_timeout)
        latest_state = (latest.get("details") or {}).get("state")
        if not isinstance(latest_state, str) or latest_state.strip().lower() in running_states:
            error_message = "Guest failed to stop before timeout"
            if not request.force:
                error_message += "; retry with force=true to destroy power"
            raise HTTPException(status_code=409, detail=error_message)
        _apply_snapshot(latest)

    try:
        await execute_cluster_task(
            cluster.delete_guest,
            hostname,
            name,
            force=request.force or state in running_states,
            remove_storage=False,
        )
    except DomainActiveError:
        logger.warning("Domain %s still active on %s during delete; forcing shutdown", name, hostname)
        await execute_cluster_task(cluster.control_domain, hostname, name, "force-off")
        forced_snapshot = await _wait_for_shutdown(30)
        _apply_snapshot(forced_snapshot)
        try:
            await execute_cluster_task(
                cluster.delete_guest,
                hostname,
                name,
                force=True,
                remove_storage=False,
            )
        except Exception as exc:
            logger.exception("Forced delete still failed for domain %s on %s: %s", name, hostname, exc)
            raise HTTPException(status_code=500, detail=f"Failed to delete domain on {hostname}: {exc}")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to remove domain %s from %s during migration: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail=f"Failed to delete domain on {hostname}: {exc}")

    try:
        define_result = await execute_cluster_task(
            cluster.define_guest_from_xml,
            target_host_name,
            domain_xml,
            start=request.start,
            autostart=autostart_flag if isinstance(autostart_flag, bool) else None,
        )
    except Exception as exc:
        logger.exception("Failed to define domain %s on %s after migration: %s", name, target_host_name, exc)
        # Best-effort restore on source host
        try:
            await execute_cluster_task(
                cluster.define_guest_from_xml,
                hostname,
                domain_xml,
                start=False,
                autostart=autostart_flag if isinstance(autostart_flag, bool) else None,
            )
        except Exception as restore_exc:
            logger.error(
                "Failed to restore domain %s on %s after migration failure: %s",
                name,
                hostname,
                restore_exc,
            )
        raise HTTPException(status_code=500, detail=f"Failed to start domain on {target_host_name}: {exc}")

    try:
        source_inventory = await run_in_threadpool(source_host.get_vm_inventory)
        target_inventory = await run_in_threadpool(target_host.get_vm_inventory)
        await sync_domain_inventory(db_session, host=source_host_record, inventory=source_inventory)
        await sync_domain_inventory(db_session, host=target_host_record, inventory=target_inventory)
        await db_session.commit()
    except Exception as exc:
        logger.error("Failed to sync domain inventory after moving %s: %s", name, exc)

    return {
        "source_host": hostname,
        "target_host": target_host_name,
        "domain": name,
        "uuid": define_result.get("uuid"),
        "started": bool(define_result.get("started")),
        "status": "migrated",
    }


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
    iso_volume_count = sum(1 for volume in request.volumes if volume.type == "iso")

    try:
        result = await execute_cluster_task(
            cluster.create_guest,
            hostname,
            name=request.name,
            vcpus=request.vcpus,
            memory_mb=request.memory_mb,
            cpu_mode=request.cpu_mode,
            autostart=request.autostart,
            start=request.start,
            description=request.description,
            volumes=volume_payload,
            networks=network_payload,
            enable_vnc=request.enable_vnc,
            vnc_password=request.vnc_password,
        )
        if iso_volume_count and request.start:
            schedule_iso_auto_eject(
                cluster,
                hostname,
                request.name,
                max_targets=iso_volume_count,
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
