from __future__ import annotations

import logging
from typing import Callable, TYPE_CHECKING

import libvirt

if TYPE_CHECKING:
    from ..host import LibvirtHost

logger = logging.getLogger(__name__)


def lookup_domain(host: "LibvirtHost", retry_decider: Callable[[libvirt.libvirtError], bool], name: str) -> "libvirt.virDomain":
    if not host._ensure_connection():  # pylint: disable=protected-access
        raise RuntimeError(f"Not connected to {host.hostname}")

    try:
        return host.conn.lookupByName(name)  # type: ignore[union-attr]
    except libvirt.libvirtError as exc:
        if retry_decider(exc):
            logger.warning(
                "lookupByName(%s) on %s failed (%s); attempting reconnect",
                name,
                host.hostname,
                exc,
            )
            host.disconnect()
            if host.connect():
                try:
                    return host.conn.lookupByName(name)  # type: ignore[union-attr]
                except libvirt.libvirtError as retry_exc:
                    logger.error(
                        "lookupByName(%s) retry failed on %s: %s",
                        name,
                        host.hostname,
                        retry_exc,
                    )
                    raise
            else:
                logger.error(
                    "Reconnection attempt failed for %s prior to retrying domain lookup",
                    host.hostname,
                )
        logger.error("lookupByName(%s) failed on %s: %s", name, host.hostname, exc)
        raise
