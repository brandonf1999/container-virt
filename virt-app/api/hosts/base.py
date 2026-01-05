from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.deps import get_cluster
from app.db import async_session_dependency
from app.db.repositories.hosts import adopt_host_record, list_cluster_hosts

from .common import ensure_host_connection, get_required_host, logger

router = APIRouter()


@router.get("/")
def list_hosts():
    cluster = get_cluster()
    return {"hosts": list(cluster.hosts.keys())}


@router.post("/{hostname}/connect")
def connect_host(hostname: str):
    cluster = get_cluster()
    host = get_required_host(cluster, hostname)
    ok = host.connect()
    return {"host": hostname, "connected": bool(ok)}


@router.post("/{hostname}/disconnect")
def disconnect_host(hostname: str):
    cluster = get_cluster()
    host = get_required_host(cluster, hostname)
    host.disconnect()
    return {"host": hostname, "disconnected": True}


@router.get("/{hostname}/info")
def get_host_details(hostname: str):
    cluster = get_cluster()
    try:
        host = get_required_host(cluster, hostname)
        ensure_host_connection(host, hostname)
        details = cluster.get_host_details(hostname)
        return {"host": hostname, "details": details}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to gather host details for %s: %s", hostname, exc)
        raise HTTPException(status_code=500, detail=str(exc))


class AdoptableHost(BaseModel):
    hostname: str
    uri: Optional[str] = None
    user: Optional[str] = None
    ssh_options: Dict[str, Any] = Field(default_factory=dict)


class AdoptableHostsResponse(BaseModel):
    hosts: List[AdoptableHost]


@router.get("/adoptable", response_model=AdoptableHostsResponse)
async def list_adoptable_hosts(db_session=Depends(async_session_dependency())):
    cluster = get_cluster()
    known_hosts = await list_cluster_hosts(db_session)
    adoptable: List[AdoptableHost] = []
    for hostname, host in cluster.hosts.items():
        if hostname in known_hosts:
            continue
        adoptable.append(
            AdoptableHost(
                hostname=hostname,
                uri=host.uri,
                user=host.user,
                ssh_options=host.ssh_opts or {},
            )
        )
    return {"hosts": adoptable}


class AdoptHostRequest(BaseModel):
    name: Optional[str] = None
    connection_uri: Optional[str] = None
    user: Optional[str] = None
    ssh_options: Optional[Dict[str, Any]] = None


@router.post("/{hostname}/adopt")
async def adopt_host(
    hostname: str,
    request: Optional[AdoptHostRequest] = None,
    db_session=Depends(async_session_dependency()),
):
    cluster = get_cluster()
    libvirt_host = cluster.hosts.get(hostname)
    if not libvirt_host:
        raise HTTPException(status_code=404, detail=f"Host {hostname} not found in configuration")

    known_hosts = await list_cluster_hosts(db_session)
    if hostname in known_hosts:
        raise HTTPException(status_code=409, detail=f"Host {hostname} is already managed")

    payload = request or AdoptHostRequest()
    uri = payload.connection_uri or libvirt_host.uri
    user = payload.user if payload.user is not None else libvirt_host.user
    ssh_options = payload.ssh_options or libvirt_host.ssh_opts or {}

    host_record = await adopt_host_record(
        db_session,
        hostname=hostname,
        uri=uri,
        user=user,
        ssh_options=ssh_options,
    )
    if payload.name:
        host_record.name = payload.name

    await db_session.commit()
    return {
        "host": {
            "id": str(host_record.id),
            "hostname": host_record.libvirt_id,
            "name": host_record.name,
            "status": host_record.status.value,
        }
    }


__all__ = ["router"]
