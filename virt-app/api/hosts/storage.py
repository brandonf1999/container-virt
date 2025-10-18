import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from app.deps import get_cluster
from app.libvirt.errors import (
    StorageError,
    StoragePoolNotEmptyError,
    StoragePoolNotFoundError,
    StorageVolumeExistsError,
    StorageVolumeInUseError,
    StorageVolumeNotFoundError,
)

from .common import call_cluster_operation, execute_cluster_task, logger

router = APIRouter()


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


class StorageVolumeDeleteResponse(BaseModel):
    host: str
    pool: str
    volume: str
    deleted: bool
    force: bool = False
    path: Optional[str]
    capacity_bytes: Optional[int]
    allocation_bytes: Optional[int]


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


@router.get("/{hostname}/storage/pools/{pool}/volumes/{volume}", response_model=StorageVolumeDetailsResponse)
def get_storage_volume(hostname: str, pool: str, volume: str):
    cluster = get_cluster()
    try:
        result = call_cluster_operation(
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
        result = call_cluster_operation(
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
        result = await execute_cluster_task(
            cluster.upload_storage_volume,
            hostname,
            pool,
            volume_name,
            tmp_file.name,
            size_bytes=total_bytes,
            overwrite=overwrite,
            volume_format=normalized_format,
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


@router.delete("/{hostname}/storage/pools/{pool}", response_model=StoragePoolDeleteResponse)
def delete_storage_pool(hostname: str, pool: str, force: bool = False):
    cluster = get_cluster()
    try:
        result = call_cluster_operation(
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


__all__ = [
    "router",
    "StorageVolumeDetailsResponse",
    "StorageVolumeDeleteResponse",
    "StoragePoolDeleteResponse",
]
