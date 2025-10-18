from fastapi import APIRouter, HTTPException

from app.deps import get_cluster

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


__all__ = ["router"]
