import asyncio
import asyncio.subprocess
import contextlib
import socket
from typing import Optional, Tuple

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel

from app.core.console_sessions import console_session_manager
from app.deps import get_cluster
from app.libvirt.errors import DomainNotFoundError, DomainNotRunningError, StorageError

from .common import call_cluster_operation, logger

router = APIRouter()


class ConsoleSessionResponse(BaseModel):
    token: str
    expires_at: int
    websocket_path: str
    password: str


def _parse_ssh_target(target: str) -> Tuple[Optional[str], str, Optional[int]]:
    target = (target or "").strip()
    username: Optional[str] = None
    hostname = target
    port: Optional[int] = None

    if "@" in hostname:
        username, hostname = hostname.split("@", 1)
        username = username or None

    if ":" in hostname:
        host_part, port_part = hostname.rsplit(":", 1)
        hostname = host_part or hostname
        try:
            port = int(port_part)
        except ValueError:
            port = None

    return username, hostname, port


@router.get("/{hostname}/vms/{name}/connect")
def generate_domain_console_file(hostname: str, name: str):
    cluster = get_cluster()
    try:
        result = call_cluster_operation(
            lambda: cluster.generate_guest_console_file(hostname, name),
            hostname=hostname,
        )
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainNotRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to prepare console file for %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail="Failed to generate console connection") from exc

    content = result.get("content")
    if not content:
        raise HTTPException(status_code=500, detail="Console file rendering failed")

    filename = result.get("filename") or f"{name}-console.sh"
    safe_filename = str(filename).replace('"', "")
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
    }

    host = result.get("host")
    port = result.get("port")
    if host:
        headers["X-Console-Host"] = str(host)
    if port:
        headers["X-Console-Port"] = str(port)

    return Response(content=content, media_type="text/x-shellscript", headers=headers)


@router.post("/{hostname}/vms/{name}/console-session", response_model=ConsoleSessionResponse)
async def create_console_session(hostname: str, name: str):
    cluster = get_cluster()
    try:
        result = call_cluster_operation(
            lambda: cluster.generate_guest_console_file(hostname, name),
            hostname=hostname,
        )
    except HTTPException:
        raise
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except DomainNotRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except StorageError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to prepare console session for %s on %s: %s", name, hostname, exc)
        raise HTTPException(status_code=500, detail="Failed to create console session") from exc

    host = result.get("host")
    port = result.get("port")
    password = result.get("password")

    if not host or not port or not password:
        raise HTTPException(status_code=500, detail="Console session metadata incomplete")

    try:
        port_value = int(port)
    except (TypeError, ValueError):
        raise HTTPException(status_code=500, detail="Invalid console port reported")

    ssh_target = result.get("ssh_target")
    session_payload = await console_session_manager.create(
        hostname,
        name,
        host=str(host),
        port=port_value,
        password=str(password),
        ssh_target=str(ssh_target) if ssh_target else None,
    )

    websocket_path = f"/api/hosts/{hostname}/vms/{name}/console/{session_payload['token']}"

    return ConsoleSessionResponse(
        token=session_payload["token"],
        expires_at=int(session_payload["expires_at"]),
        websocket_path=websocket_path,
        password=str(password),
    )


@router.websocket("/{hostname}/vms/{name}/console/{token}")
async def console_websocket(websocket: WebSocket, hostname: str, name: str, token: str):
    session = await console_session_manager.consume(token, hostname, name)
    if not session:
        await websocket.close(code=4401, reason="Invalid or expired console token")
        return

    await websocket.accept()

    host = str(session.get("host"))
    port_value = session.get("port")
    try:
        port = int(port_value) if port_value is not None else None
    except (TypeError, ValueError):
        port = None

    if not host or not isinstance(port, int):
        await websocket.close(code=1011, reason="Console session missing host metadata")
        return

    ssh_target = session.get("ssh_target") or None
    tunnel_proc: Optional[asyncio.subprocess.Process] = None

    async def _open_vnc_via_ssh(target: str) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, asyncio.subprocess.Process]:
        username, ssh_host, ssh_port = _parse_ssh_target(target)
        if not ssh_host:
            raise RuntimeError("SSH target missing hostname")

        destination = ssh_host if username is None else f"{username}@{ssh_host}"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            local_port = probe.getsockname()[1]

        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=2",
            "-N",
        ]
        if ssh_port:
            cmd.extend(["-p", str(ssh_port)])
        cmd.extend(["-L", f"{local_port}:{host}:{port}", destination])

        logger.debug(
            "Launching SSH tunnel for %s@%s via %s (localhost:%s -> %s:%s)",
            name,
            hostname,
            destination,
            local_port,
            host,
            port,
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Wait for local forward to come up
        for _ in range(50):
            try:
                test_reader, test_writer = await asyncio.open_connection("127.0.0.1", local_port)
                test_writer.close()
                await test_writer.wait_closed()
                break
            except (ConnectionRefusedError, OSError):
                await asyncio.sleep(0.1)
        else:
            stderr_output = b""
            if proc.stderr is not None:
                try:
                    stderr_output = await asyncio.wait_for(proc.stderr.read(), timeout=0.5)
                except Exception:
                    pass
            proc.terminate()
            with contextlib.suppress(Exception):
                await proc.wait()
            detail = stderr_output.decode().strip() or "no details"
            raise RuntimeError(f"SSH tunnel setup failed via {destination}: {detail}")

        reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
        logger.info(
            "SSH tunnel established for %s@%s (%s:%s via %s)",
            name,
            hostname,
            host,
            port,
            destination,
        )
        return reader, writer, proc

    prefer_tunnel = bool(ssh_target) and host in {"127.0.0.1", "::1", "localhost"}

    try:
        if prefer_tunnel and ssh_target:
            reader, writer, tunnel_proc = await _open_vnc_via_ssh(str(ssh_target))
        else:
            reader, writer = await asyncio.open_connection(host, port)
            logger.debug(
                "Direct VNC connection established for %s@%s (%s:%s)",
                name,
                hostname,
                host,
                port,
            )
    except (OSError, socket.gaierror) as exc:
        if not ssh_target:
            logger.error(
                "Failed to connect to VNC endpoint %s:%s for %s on %s: %s",
                host,
                port,
                name,
                hostname,
                exc,
            )
            await websocket.close(code=1011, reason="Unable to reach VNC endpoint")
            return
        try:
            logger.info(
                "Direct VNC connection failed for %s@%s (%s:%s); attempting SSH tunnel via %s",
                name,
                hostname,
                host,
                port,
                ssh_target,
            )
            reader, writer, tunnel_proc = await _open_vnc_via_ssh(str(ssh_target))
        except Exception as ssh_exc:
            logger.error(
                "SSH tunnel establishment failed for %s on %s (%s -> %s:%s): %s",
                name,
                hostname,
                ssh_target,
                host,
                port,
                ssh_exc,
            )
            await websocket.close(code=1011, reason="Unable to reach VNC endpoint via SSH")
            return

    async def ws_to_tcp() -> None:
        try:
            while True:
                message = await websocket.receive()
                message_type = message.get("type")
                if message_type == "websocket.disconnect":
                    break
                data = message.get("bytes")
                if data is None:
                    text = message.get("text")
                    if text is None:
                        continue
                    data = text.encode("utf-8")
                writer.write(data)
                await writer.drain()
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.debug("WebSocket -> TCP relay ended for %s on %s: %s", name, hostname, exc)

    async def tcp_to_ws() -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                await websocket.send_bytes(chunk)
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.debug("TCP -> WebSocket relay ended for %s on %s: %s", name, hostname, exc)

    ws_task = asyncio.create_task(ws_to_tcp())
    tcp_task = asyncio.create_task(tcp_to_ws())

    try:
        await asyncio.wait({ws_task, tcp_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        ws_task.cancel()
        tcp_task.cancel()
        for task in (ws_task, tcp_task):
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        try:
            writer.close()
            wait_closed = getattr(writer, "wait_closed", None)
            if callable(wait_closed):
                await wait_closed()
        except Exception:
            pass
        if tunnel_proc is not None:
            try:
                tunnel_proc.terminate()
                await asyncio.wait_for(tunnel_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                tunnel_proc.kill()
                await tunnel_proc.wait()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass


__all__ = ["router", "ConsoleSessionResponse"]
