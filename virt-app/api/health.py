import logging
from fastapi import APIRouter, Depends, status

from ..core.config import APP_NAME, APP_VERSION
from ..db import async_session_dependency
from ..db.health import ensure_connection
from ..deps import get_cluster

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/ping", status_code=status.HTTP_200_OK)
def ping():
    """Basic liveness check."""
    return {"ping": "pong"}


@router.get("/healthz", status_code=status.HTTP_200_OK)
async def healthz(db_session=Depends(async_session_dependency())):
    """Comprehensive health check covering application, cluster, and database."""
    try:
        cluster = get_cluster()
        await ensure_connection(db_session)
        summary = {
            "app_name": APP_NAME,
            "version": APP_VERSION,
            "host_count": len(cluster.hosts),
            "connected_hosts": sum(1 for h in cluster.hosts.values() if h.conn),
            "database": "ok",
        }
        return {"status": "ok", "details": summary}
    except Exception as exc:
        logger.exception("Health check failed: %s", exc)
        return {"status": "error", "error": str(exc)}
