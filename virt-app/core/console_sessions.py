import asyncio
import secrets
import time
from typing import Dict, Optional


class ConsoleSessionManager:
    """Manage one-shot console sessions with TTL enforcement."""

    def __init__(self, ttl_seconds: int = 300, history_size: int = 512) -> None:
        self._ttl_seconds = ttl_seconds
        self._sessions: Dict[str, Dict[str, object]] = {}
        self._lock = asyncio.Lock()
        self._history_size = max(0, history_size)

    async def create(
        self,
        hostname: str,
        domain: str,
        *,
        host: str,
        port: int,
        password: str,
        ssh_target: Optional[str] = None,
    ) -> Dict[str, object]:
        now = time.time()
        expires_at = now + self._ttl_seconds
        token = secrets.token_urlsafe(32)
        payload: Dict[str, object] = {
            "token": token,
            "hostname": hostname,
            "domain": domain,
            "host": host,
            "port": port,
            "password": password,
            "ssh_target": ssh_target,
            "expires_at": expires_at,
        }
        async with self._lock:
            self._prune_locked(now)
            self._sessions[token] = payload
        return payload

    async def consume(self, token: str, hostname: str, domain: str) -> Optional[Dict[str, object]]:
        async with self._lock:
            payload = self._sessions.pop(token, None)

        if not payload:
            return None

        expires_at = payload.get("expires_at")
        if isinstance(expires_at, (int, float)) and expires_at < time.time():
            return None
        if payload.get("hostname") != hostname or payload.get("domain") != domain:
            return None
        return payload

    def _prune_locked(self, now: Optional[float] = None) -> None:
        current = now or time.time()
        expired = [token for token, data in self._sessions.items() if data.get("expires_at", 0) <= current]
        for token in expired:
            self._sessions.pop(token, None)
        if self._history_size and len(self._sessions) > self._history_size:
            # Drop oldest entries deterministically to cap memory usage.
            surplus = len(self._sessions) - self._history_size
            for token in list(self._sessions.keys())[:surplus]:
                self._sessions.pop(token, None)


console_session_manager = ConsoleSessionManager()

