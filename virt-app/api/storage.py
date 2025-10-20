"""Storage domain detailed endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.db import async_session_dependency
from app.db.services.storage import get_storage_domain

router = APIRouter(prefix="/storage", tags=["Storage"])


@router.get("/{storage_id}")
async def get_storage_detail(storage_id: str, db_session=Depends(async_session_dependency())):
    """Return detailed information for a single storage domain."""

    try:
        storage_uuid = UUID(storage_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="storage_id must be a UUID") from exc

    record = await get_storage_domain(db_session, storage_uuid)
    if record is None:
        raise HTTPException(status_code=404, detail="Storage domain not found")
    return record


__all__ = ["router"]
