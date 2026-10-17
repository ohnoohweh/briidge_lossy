"""Private desktop Admin Web child and bounded runner RPC bridge."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import inspect
import json
import logging
import math
import socket
import struct
import sys
import threading
import time
import uuid
from typing import Any

MAX_FRAME = 1024 * 1024
SYNC_METHODS = frozenset({
    "get_connections_snapshot", "get_status_snapshot", "get_peer_connections_snapshot",
    "get_config_snapshot", "get_config_schema_snapshot", "replace_remote_services_catalog",
    "update_config", "request_secure_link_rekey", "request_secure_link_reload",
    "request_overlay_reconnect", "request_tun_helper_repair", "request_shutdown", "request_restart",
    "_restart_requires_delay", "get_async_diagnostics_snapshot", "get_debug_logs",
    "get_telemetry_client_snapshot", "fetch_logs",
})
ASYNC_METHODS = frozenset({"request_tun_enabled", "probe_tun_connectivity_verification"})


def _encode(message: dict[str, Any]) -> bytes:
    data = json.dumps(message, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not data or len(data) > MAX_FRAME:
        raise ValueError("invalid Admin worker frame size")
    return struct.pack("!I", len(data)) + data


async def _read_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    size = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("invalid Admin worker frame size")
    value = json.loads((await reader.readexactly(size)).decode("utf-8"))
    if not isinstance(value, dict) or value.get("v") != 1:
        raise ValueError("invalid Admin worker frame")
    return value


def _read_socket_frame(sock: socket.socket) -> dict[str, Any]:
    def read_exact(size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = sock.recv(size - len(result))
            if not chunk:
                raise EOFError("Admin worker control closed")
            result.extend(chunk)
        return bytes(result)
    size = struct.unpack("!I", read_exact(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("invalid Admin worker frame size")
    value = json.loads(read_exact(size).decode("utf-8"))
    if not isinstance(value, dict) or value.get("v") != 1:
        raise ValueError("invalid Admin worker frame")
    return value


def _serializable_args(args: Any) -> dict[str, Any]:
    result = {}
    for key, value in vars(args).items():
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError, OverflowError):
            continue
        result[key] = value
    return result


class _RemoteRunner:
    def __init__(self, sock: socket.socket, args: argparse.Namespace):
        self._socket = sock
        self.args = args
        self._lock = threading.Lock()
        self._failed = False

    def _call(self, method: str, *args, **kwargs):
        timeout = 4.0 if method in ASYNC_METHODS else 0.35
        deadline = time.monotonic() + timeout
        if not self._lock.acquire(timeout=timeout):
            raise TimeoutError("Admin worker runner busy")
        try:
            remaining = deadline - time.monotonic()
            if self._failed or remaining <= 0:
                raise TimeoutError("Admin worker runner unavailable")
            request_id = uuid.uuid4().hex
            self._socket.settimeout(remaining)
            self._socket.sendall(_encode({"v": 1, "kind": "admin.call", "id": request_id,
                                         "method": method, "args": args, "kwargs": kwargs, "deadline": deadline}))
            reply = _read_socket_frame(self._socket)
            if reply.get("kind") != "admin.reply" or reply.get("id") != request_id:
                raise ValueError("invalid Admin runner reply")
            if not reply.get("ok"):
                raise RuntimeError("Admin runner request failed")
            if isinstance(reply.get("args"), dict):
                vars(self.args).update(reply["args"])
            return reply.get("result")
        except (OSError, EOFError, ValueError):
            # A partial or timed-out response poisons the stream; never let a
            # later request consume a stale reply for another operation.
            self._failed = True
            with contextlib.suppress(OSError):
                self._socket.shutdown(socket.SHUT_RDWR)
            raise
        finally:
            self._lock.release()

    def fetch(self, limit):
        return self._call("fetch_logs", limit)

    def __getattr__(self, name: str):
        if name in SYNC_METHODS:
            return lambda *args, **kwargs: self._call(name, *args, **kwargs)
        if name in ASYNC_METHODS:
            async def call_async(*args, **kwargs):
                return await asyncio.to_thread(self._call, name, *args, **kwargs)
            return call_async
        raise AttributeError(name)


async def _serve_child(control_fd: int, lifetime_fd: int, log_fd: int | None) -> None:
    control = socket.socket(fileno=control_fd)
    lifetime = socket.socket(fileno=lifetime_fd)
    if (control.family != socket.AF_UNIX or control.type != socket.SOCK_STREAM
            or lifetime.family != socket.AF_UNIX or lifetime.type != socket.SOCK_STREAM
            or control_fd == lifetime_fd):
        raise ValueError("invalid Admin worker sockets")
    control.settimeout(5.0)
    bootstrap = _read_socket_frame(control)
    if bootstrap.get("kind") != "admin.start" or not isinstance(bootstrap.get("args"), dict):
        raise ValueError("invalid Admin worker startup")
    args = argparse.Namespace(**bootstrap["args"])
    log_socket = None
    if log_fd is not None:
        from .bridge_logging_worker import install_child_log_handler
        log_socket = install_child_log_handler(log_fd, int(bootstrap.get("log_root_level", logging.WARNING)),
                                               bootstrap.get("log_levels", {}))
    proxy = _RemoteRunner(control, args)
    from .bridge import AdminWebUI
    from .bridge_logging_ipc import swap_admin_log_query_client

    swap_admin_log_query_client(proxy)
    ui = AdminWebUI(args, proxy)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def watch_owner():
        with contextlib.suppress(OSError):
            lifetime.recv(1)
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(stop.set)

    watcher = threading.Thread(target=watch_owner, name="admin-worker-lifetime", daemon=True)
    watcher.start()
    try:
        await ui.start()
        sockets = ui.server.sockets if ui.server else []
        port = sockets[0].getsockname()[1] if sockets else 0
        control.sendall(_encode({"v": 1, "kind": "admin.ready", "implementation": "python", "port": port}))
        await stop.wait()
    finally:
        await ui.stop()
        lifetime.close()
        control.close()
        if log_socket is not None:
            log_socket.close()


class AdminWorker:
    implementation = "python"

    def __init__(self, runner, args):
        self.runner = runner
        self.args = args
        self.process = None
        self.writer = None
        self.lifetime = None
        self._task = None
        self.port = 0
        self.last_error = ""
        self._stopping = False
        self._log_relay = None

    async def start(self):
        if sys.platform not in {"darwin", "linux"}:
            raise RuntimeError("Admin workers require macOS or Linux")
        if callable(getattr(self.runner, "_embedded_restart_callback", None)):
            raise ValueError("Admin worker does not support embedded restart callbacks")
        control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.lifetime, child_lifetime = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except BaseException:
            control.close(); child_control.close()
            raise
        try:
            from .bridge_logging_worker import open_child_log_relay
            self._log_relay = open_child_log_relay()
            command = [sys.executable, "-m", "obstacle_bridge.bridge_admin_worker",
                       "--control-fd", str(child_control.fileno()), "--lifetime-fd", str(child_lifetime.fileno())]
            inherited = [child_control.fileno(), child_lifetime.fileno()]
            if self._log_relay is not None:
                log_fd = self._log_relay.sender.fileno()
                command.extend(["--log-fd", str(log_fd)])
                inherited.append(log_fd)
            self.process = await asyncio.create_subprocess_exec(
                *command, stdin=asyncio.subprocess.DEVNULL, pass_fds=tuple(inherited),
            )
            child_control.close(); child_lifetime.close()
            if self._log_relay is not None:
                self._log_relay.sender.close()
            control.setblocking(False)
            reader, self.writer = await asyncio.open_connection(sock=control)
            self.writer.write(_encode({"v": 1, "kind": "admin.start", "args": _serializable_args(self.args),
                                       "log_root_level": logging.getLogger().level,
                                       "log_levels": {"admin_web": logging.getLogger("admin_web").level}}))
            await asyncio.wait_for(self.writer.drain(), 1.0)
            response = await asyncio.wait_for(_read_frame(reader), 6.0)
            if response.get("kind") != "admin.ready" or response.get("implementation") != "python":
                raise ValueError("invalid Admin worker readiness")
            self.port = int(response.get("port") or 0)
            self._task = asyncio.create_task(self._dispatch(reader))
        except BaseException:
            control.close(); child_control.close(); child_lifetime.close()
            await self.stop()
            raise

    async def _dispatch(self, reader: asyncio.StreamReader):
        try:
            while True:
                request = await _read_frame(reader)
                method = request.get("method")
                request_id = request.get("id")
                if (request.get("kind") != "admin.call" or not isinstance(method, str) or method not in SYNC_METHODS | ASYNC_METHODS
                        or not isinstance(request_id, str) or not 0 < len(request_id) <= 64
                        or not isinstance(request.get("args"), list) or not isinstance(request.get("kwargs"), dict)):
                    raise ValueError("invalid Admin worker request")
                reply = {"v": 1, "kind": "admin.reply", "id": request_id, "ok": False}
                try:
                    deadline = float(request.get("deadline", 0))
                    if not math.isfinite(deadline) or not time.monotonic() < deadline <= time.monotonic() + 4.1:
                        raise TimeoutError("expired Admin request")
                    if method == "fetch_logs":
                        from .bridge_logging_ipc import fetch_remote_log_lines
                        result = await asyncio.to_thread(fetch_remote_log_lines, *request["args"], **request["kwargs"])
                    else:
                        result = getattr(self.runner, method)(*request["args"], **request["kwargs"])
                        if inspect.isawaitable(result):
                            result = await asyncio.wait_for(result, max(0.001, deadline - time.monotonic()))
                    reply.update(ok=True, result=result)
                    if method == "update_config":
                        reply["args"] = _serializable_args(self.args)
                    encoded = _encode(reply)
                except Exception:
                    encoded = _encode({"v": 1, "kind": "admin.reply", "id": request_id, "ok": False})
                self.writer.write(encoded)
                await asyncio.wait_for(self.writer.drain(), 1.0)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError, OSError, asyncio.TimeoutError):
            if not self._stopping:
                self.last_error = "Admin worker unavailable"

    async def stop(self):
        self._stopping = True
        if self.lifetime is not None:
            self.lifetime.close()
            self.lifetime = None
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self.writer is not None:
            self.writer.close()
            with contextlib.suppress(Exception):
                await self.writer.wait_closed()
            self.writer = None
        if self.process is not None:
            try:
                await asyncio.wait_for(self.process.wait(), 1.5)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self.process.kill()
                await self.process.wait()
        if self._log_relay is not None:
            await asyncio.to_thread(self._log_relay.close)
            self._log_relay = None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", required=True, type=int)
    parser.add_argument("--lifetime-fd", required=True, type=int)
    parser.add_argument("--log-fd", type=int)
    args = parser.parse_args()
    try:
        asyncio.run(_serve_child(args.control_fd, args.lifetime_fd, args.log_fd))
    except Exception:
        # Startup/control frames can contain secrets and are never logged.
        raise SystemExit(1)


if __name__ == "__main__":
    main()
