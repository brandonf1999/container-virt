import logging
from typing import Dict
from fastapi import APIRouter, HTTPException
from app.deps import get_cluster

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cluster", tags=["Cluster"])

@router.post("/connect")
def connect_all_hosts():
    cluster = get_cluster()
    results = cluster.connect_all()
    failed = [hostname for hostname, ok in results.items() if not ok]
    if failed:
        logger.warning("Failed to connect to hosts: %s", failed)
    connected = [h for h, host in cluster.hosts.items() if host.conn]
    logger.info("Connected hosts: %s", connected)
    return {"connected_hosts": connected}

@router.post("/disconnect")
def disconnect_all_hosts():
    cluster = get_cluster()
    cluster.disconnect_all()
    logger.info("Disconnected all hosts")
    return {"message": "Disconnected all hosts"}

@router.get("/info")
def get_cluster_info():
    cluster = get_cluster()
    results = cluster.connect_all()
    info = cluster.get_cluster_info()
    if info:
        return info

    if not cluster.hosts:
        raise HTTPException(status_code=404, detail="No hosts configured")

    failed = [hostname for hostname, ok in results.items() if not ok]
    if failed:
        detail = "Failed to connect to hosts: " + ", ".join(failed)
        raise HTTPException(status_code=503, detail=detail)

    raise HTTPException(status_code=503, detail="Hosts connected but no information available")

@router.get("/vms")
def get_cluster_vms():
    cluster = get_cluster()
    results = cluster.connect_all()
    inventory, errors = cluster.get_vm_inventory()

    response = {"hosts": inventory}

    failed_connections = [hostname for hostname, ok in results.items() if not ok]
    combined_errors: Dict[str, str] = {}
    combined_errors.update(errors)
    if failed_connections:
        for hostname in failed_connections:
            combined_errors.setdefault(hostname, "Connection failed")

    if combined_errors:
        response["errors"] = combined_errors

    vm_counts = {"online": 0, "stopped": 0, "failed": 0, "total": 0}
    for host_data in inventory.values():
        for vm in host_data.get("vms", []):
            vm_counts["total"] += 1
            state = (vm.get("state") or "").lower()
            if state in {"running", "blocked"}:
                vm_counts["online"] += 1
            elif state in {"crashed"}:
                vm_counts["failed"] += 1
            else:
                vm_counts["stopped"] += 1

    summary = {
        "host_count": len(cluster.hosts),
        "reported_hosts": len(inventory),
        "failed_hosts": len(combined_errors),
        "vm_counts": vm_counts,
    }
    response["summary"] = summary

    return response


@router.get("/networks")
def get_cluster_networks():
    cluster = get_cluster()
    results = cluster.connect_all()
    inventory, errors = cluster.get_network_inventory()

    response = {"hosts": inventory}

    failed_connections = [hostname for hostname, ok in results.items() if not ok]
    combined_errors: Dict[str, str] = {}
    combined_errors.update(errors)
    if failed_connections:
        for hostname in failed_connections:
            combined_errors.setdefault(hostname, "Connection failed")

    if combined_errors:
        response["errors"] = combined_errors

    summary = {
        "host_count": len(cluster.hosts),
        "reported_hosts": len(inventory),
        "failed_hosts": len(combined_errors),
    }
    response["summary"] = summary

    return response


@router.get("/storage")
def get_cluster_storage():
    cluster = get_cluster()
    results = cluster.connect_all()
    inventory, errors = cluster.get_storage_inventory()

    response = {"hosts": inventory}

    failed_connections = [hostname for hostname, ok in results.items() if not ok]
    combined_errors: Dict[str, str] = {}
    combined_errors.update(errors)
    if failed_connections:
        for hostname in failed_connections:
            combined_errors.setdefault(hostname, "Connection failed")

    if combined_errors:
        response["errors"] = combined_errors

    summary = {
        "host_count": len(cluster.hosts),
        "reported_hosts": len(inventory),
        "failed_hosts": len(combined_errors),
    }
    response["summary"] = summary

    return response
