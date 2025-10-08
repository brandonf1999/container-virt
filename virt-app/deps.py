import logging
from typing import Optional
from app.libvirt.cluster import LibvirtCluster
from app.core.config import CONFIG_FILE

logger = logging.getLogger(__name__)
_cluster: Optional[LibvirtCluster] = None

def get_cluster() -> LibvirtCluster:
    global _cluster
    if _cluster is None:
        logger.info("Initializing LibvirtCluster from %s", CONFIG_FILE)
        _cluster = LibvirtCluster()
        _cluster.load_from_yaml(CONFIG_FILE)
    return _cluster

