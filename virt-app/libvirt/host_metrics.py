
from __future__ import annotations

import logging
import time
from typing import Dict, Optional, Tuple, TYPE_CHECKING

import libvirt

if TYPE_CHECKING:
    from .host import LibvirtHost


logger = logging.getLogger(__name__)


_CPU_TIME_FIELDS = {
    "kernel",
    "user",
    "idle",
    "iowait",
    "other",
    "nice",
    "system",
    "steal",
}


def _kb_to_mb(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    return round(value / 1024.0, 2)


class LibvirtHostMetrics:
    """Collects CPU and memory metrics for a libvirt host."""

    def __init__(self, host: "LibvirtHost") -> None:
        self._host = host
        self._cpu_sample: Optional[Tuple[Dict[str, int], float]] = None

    def prime_cpu_sample(self) -> None:
        sample = self._collect_cpu_stats()
        self._cpu_sample = (sample, time.perf_counter()) if sample else None

    def reset(self) -> None:
        self._cpu_sample = None

    def gather(self) -> Dict[str, Dict[str, object]]:
        return {
            "cpu": self._compute_cpu_metrics(),
            "memory": self._compute_memory_metrics(),
        }

    def _collect_cpu_stats(self) -> Optional[Dict[str, int]]:
        conn = self._host.conn
        if not conn:
            return None
        try:
            stats = conn.getCPUStats(-1, 0)
        except (libvirt.libvirtError, AttributeError) as exc:
            logger.debug("Unable to collect CPU stats for %s: %s", self._host.hostname, exc)
            return None

        if isinstance(stats, list):
            stats = stats[0] if stats else {}

        cleaned: Dict[str, int] = {}
        for key, value in (stats or {}).items():
            if isinstance(value, (int, float)):
                cleaned[key] = int(value)
        return cleaned or None

    def _compute_cpu_metrics(self) -> Dict[str, object]:
        metrics: Dict[str, object] = {
            "cores": None,
            "usage_percent": None,
            "sample_period_seconds": None,
            "times_ns": None,
        }

        conn = self._host.conn
        if not conn:
            return metrics

        try:
            info = conn.getInfo()
            metrics["cores"] = info[2]
        except libvirt.libvirtError as exc:
            logger.debug("Failed to read CPU core count for %s: %s", self._host.hostname, exc)

        current_stats = self._collect_cpu_stats()
        now = time.perf_counter()
        prev_sample = self._cpu_sample
        if current_stats:
            metrics["times_ns"] = current_stats
            if prev_sample:
                prev_stats, prev_time = prev_sample
                tracked = [
                    field for field in _CPU_TIME_FIELDS if field in current_stats and field in prev_stats
                ]
                if tracked:
                    delta_total = sum(
                        max(current_stats[field] - prev_stats[field], 0) for field in tracked
                    )
                    delta_idle = max(current_stats.get("idle", 0) - prev_stats.get("idle", 0), 0)
                    if delta_total > 0:
                        usage = (delta_total - delta_idle) / delta_total * 100.0
                        metrics["usage_percent"] = round(min(max(usage, 0.0), 100.0), 1)
                metrics["sample_period_seconds"] = round(max(now - prev_time, 0.0), 3)
            self._cpu_sample = (current_stats, now)
        else:
            self._cpu_sample = None

        return metrics

    def _compute_memory_metrics(self) -> Dict[str, object]:
        metrics: Dict[str, object] = {
            "total_mb": None,
            "used_mb": None,
            "free_mb": None,
            "available_mb": None,
            "usage_percent": None,
            "raw": None,
        }

        conn = self._host.conn
        if not conn:
            return metrics

        raw_stats = None
        try:
            raw_stats = conn.getMemoryStats(-1, 0)
        except (libvirt.libvirtError, AttributeError) as exc:
            logger.debug("Unable to collect memory stats for %s: %s", self._host.hostname, exc)

        if isinstance(raw_stats, list):
            raw_stats = raw_stats[0] if raw_stats else None

        cleaned_stats: Dict[str, int] = {}
        if isinstance(raw_stats, dict):
            for key, value in raw_stats.items():
                if isinstance(value, (int, float)):
                    cleaned_stats[key] = int(value)
            metrics["raw"] = cleaned_stats

        total_kib = cleaned_stats.get("total") if cleaned_stats else None
        free_kib = cleaned_stats.get("free") if cleaned_stats else None
        buffers_kib = cleaned_stats.get("buffers", 0) if cleaned_stats else 0
        cached_kib = cleaned_stats.get("cached", 0) if cleaned_stats else 0

        try:
            info = conn.getInfo()
            metrics["total_mb"] = info[1]
            if total_kib is None:
                total_kib = info[1] * 1024
        except libvirt.libvirtError as exc:
            logger.debug("Unable to read base memory info for %s: %s", self._host.hostname, exc)

        if free_kib is None:
            try:
                free_bytes = conn.getFreeMemory()
                free_kib = int(free_bytes / 1024)
            except libvirt.libvirtError as exc:
                logger.debug("Unable to read free memory for %s: %s", self._host.hostname, exc)

        available_kib = None
        if free_kib is not None:
            available_kib = free_kib + buffers_kib + cached_kib

        used_kib = None
        if total_kib is not None:
            if available_kib is not None:
                used_kib = max(total_kib - available_kib, 0)
            elif free_kib is not None:
                used_kib = max(total_kib - free_kib, 0)

        if free_kib is not None:
            metrics["free_mb"] = _kb_to_mb(free_kib)
        if available_kib is not None:
            metrics["available_mb"] = _kb_to_mb(available_kib)
        if used_kib is not None:
            metrics["used_mb"] = _kb_to_mb(used_kib)
            if total_kib:
                metrics["usage_percent"] = round((used_kib / total_kib) * 100.0, 1)

        return metrics
