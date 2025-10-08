from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, List, Set


SystemLogEnvelope = Dict[str, object]


class LogStream:
    """Shared log stream fan-out used to broadcast log entries to subscribers."""

    def __init__(self, history: int = 500, queue_size: int = 200) -> None:
        self._subscribers: Set[asyncio.Queue[SystemLogEnvelope]] = set()
        self._buffer: Deque[SystemLogEnvelope] = deque(maxlen=history)
        self._queue_size = queue_size
        self._lock = threading.Lock()

    def publish(self, record: logging.LogRecord) -> None:
        entry = self._serialise(record)
        with self._lock:
            self._buffer.append(entry)
            subscribers: Iterable[asyncio.Queue[SystemLogEnvelope]] = tuple(self._subscribers)

        for queue in subscribers:
            try:
                queue.put_nowait(entry)
            except asyncio.QueueFull:
                # Drop log entry for slow subscriber; they will continue with next item.
                continue

    def register(self) -> tuple[asyncio.Queue[SystemLogEnvelope], List[SystemLogEnvelope]]:
        queue: asyncio.Queue[SystemLogEnvelope] = asyncio.Queue(self._queue_size)
        with self._lock:
            self._subscribers.add(queue)
            history = list(self._buffer)
        return queue, history

    def unregister(self, queue: asyncio.Queue[SystemLogEnvelope]) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    @staticmethod
    def _serialise(record: logging.LogRecord) -> SystemLogEnvelope:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        message = record.getMessage()
        name_parts = record.name.split(".") if record.name else []
        source = "libvirt" if "libvirt" in name_parts else "system"
        component = name_parts[-1] if name_parts else "root"

        data: SystemLogEnvelope = {
            "type": "log",
            "id": f"{record.created:.6f}-{record.process}-{record.thread}"[:64],
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "source": source,
            "component": component,
        }

        if record.exc_info:
            formatter = logging.Formatter()
            data["traceback"] = formatter.formatException(record.exc_info)
        elif record.stack_info:
            data["traceback"] = record.stack_info

        return data


class LogStreamHandler(logging.Handler):
    """Logging handler that forwards records to the shared LogStream."""

    def __init__(self, stream: LogStream) -> None:
        super().__init__()
        self._stream = stream

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._stream.publish(record)
        except Exception:  # pragma: no cover - guard logging failures
            self.handleError(record)


log_stream = LogStream()
log_stream_handler = LogStreamHandler(log_stream)
