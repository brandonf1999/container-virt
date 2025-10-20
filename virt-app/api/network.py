"""Network-related API endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.db import async_session_dependency
from app.db.services.network import get_network

router = APIRouter(prefix="/network", tags=["Networks"])


@router.get("/{network_id}")
async def get_network_detail(network_id: str, db_session=Depends(async_session_dependency())):
    try:
        network_uuid = UUID(network_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="network_id must be a UUID") from exc

    record = await get_network(db_session, network_uuid)
    if record is None:
        raise HTTPException(status_code=404, detail="Network not found")
    return record


__all__ = ["router"]
