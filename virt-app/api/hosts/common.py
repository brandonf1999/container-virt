import logging
from typing import Any, Callable, TypeVar

from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool


logger = logging.getLogger(__name__)

T = TypeVar("T")


def get_required_host(cluster, hostname: str):
    host = cluster.hosts.get(hostname)
    if not host:
        raise HTTPException(status_code=404, detail=f"Host {hostname} not found")
    return host


def ensure_host_connection(host, hostname: str, *, error_status: int = 500) -> None:
    if host.conn:
        return
    if not host.connect():
        raise HTTPException(status_code=error_status, detail=f"Failed to connect to {hostname}")


def call_cluster_operation(operation: Callable[[], Any], *, hostname: str):
    try:
        return operation()
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Host {hostname} not found")
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


async def execute_cluster_task(
    operation: Callable[..., T],
    hostname: str,
    *args: Any,
    **kwargs: Any,
) -> T:
    return await run_in_threadpool(
        lambda: call_cluster_operation(
            lambda: operation(hostname, *args, **kwargs),
            hostname=hostname,
        )
    )


__all__ = [
    "logger",
    "T",
    "get_required_host",
    "ensure_host_connection",
    "call_cluster_operation",
    "execute_cluster_task",
]
