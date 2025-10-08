import logging
from fastapi import APIRouter, status
from ..deps import get_cluster
from ..core.config import APP_NAME, APP_VERSION

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["Health"])

@router.get("/ping", status_code=status.HTTP_200_OK)
def ping():
    """Basic liveness check."""
    return {"ping": "pong"}


@router.get("/healthz", status_code=status.HTTP_200_OK)
def healthz():
    """
    Deeper health check for orchestrators or uptime monitoring.
    Verifies that:
      - Config is loaded
      - Libvirt cluster object initialized
      - Optional host connectivity summary
    """
    try:
        cluster = get_cluster()
        summary = {
            "app_name": APP_NAME,
            "version": APP_VERSION,
            "host_count": len(cluster.hosts),
            "connected_hosts": sum(1 for h in cluster.hosts.values() if h.conn),
        }
        return {"status": "ok", "details": summary}
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        return {"status": "error", "error": str(e)}

