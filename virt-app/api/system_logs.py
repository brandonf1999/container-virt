from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.log_stream import log_stream


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


@router.websocket("/stream")
async def stream_system_logs(websocket: WebSocket) -> None:
    await websocket.accept()
    queue, history = log_stream.register()

    try:
        for item in history:
            await websocket.send_json(item)

        while True:
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=60)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "keepalive"})
                continue

            await websocket.send_json(payload)
    except WebSocketDisconnect:
        logger.debug("System log stream disconnected")
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pragma: no cover - defensive logging around websocket
        logger.exception("System log stream failed: %s", exc)
    finally:
        log_stream.unregister(queue)

