"""Private desktop Admin Web child and bounded runner RPC bridge."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import inspect
import json
import logging
import math
import os
import shutil
import socket
import sys
import threading
import time
import uuid
from typing import Any

from .worker_ipc import WorkerIPCFrameKind, decode_control, encode_control, frame_size, try_decode_frame

MAX_FRAME = 1024 * 1024
SYNC_METHODS = frozenset({
    "get_connections_snapshot", "get_status_snapshot", "get_peer_connections_snapshot",
    "get_config_snapshot", "get_onboarding_config_snapshot", "get_config_schema_snapshot", "replace_remote_services_catalog",
    "update_config", "request_secure_link_rekey", "request_secure_link_reload",
    "request_overlay_reconnect", "request_tun_helper_repair", "request_shutdown", "request_restart",
    "_restart_requires_delay", "get_async_diagnostics_snapshot", "get_debug_logs",
    "get_telemetry_client_snapshot", "fetch_logs",
})
ASYNC_METHODS = frozenset({"request_tun_enabled", "probe_tun_connectivity_verification",
                           "request_overlay_reconnect_async", "request_secure_link_rekey_async",
                           "request_secure_link_reload_async"})


def _encode(message: dict[str, Any], generation: int = 1) -> bytes:
    kind = (WorkerIPCFrameKind.HELLO if message.get("kind") == "worker.hello"
            else WorkerIPCFrameKind.READY if message.get("kind") == "admin.ready"
            else WorkerIPCFrameKind.REQUEST if message.get("kind") in {"admin.start", "admin.call"}
            else WorkerIPCFrameKind.RESPONSE)
    frame = encode_control(kind, generation, message)
    if len(frame) - 20 > MAX_FRAME:
        raise ValueError("invalid Admin worker frame size")
    return frame


async def _read_frame(reader: asyncio.StreamReader, generation: int = 1) -> dict[str, Any]:
    header = await reader.readexactly(20)
    size = frame_size(header)
    if size is None or size > MAX_FRAME:
        raise ValueError("invalid Admin worker frame size")
    decoded = try_decode_frame(header + await reader.readexactly(size))
    if decoded is None or decoded[1] or decoded[0].generation != generation:
        raise ValueError("invalid Admin worker frame")
    value = decode_control(decoded[0])
    if value.get("v") != 1:
        raise ValueError("invalid Admin worker frame")
    return value


def _read_socket_frame(sock: socket.socket, generation: int = 1) -> dict[str, Any]:
    def read_exact(size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = sock.recv(size - len(result))
            if not chunk:
                raise EOFError("Admin worker control closed")
            result.extend(chunk)
        return bytes(result)
    header = read_exact(20)
    size = frame_size(header)
    if size is None or size > MAX_FRAME:
        raise ValueError("invalid Admin worker frame size")
    decoded = try_decode_frame(header + read_exact(size))
    if decoded is None or decoded[1] or decoded[0].generation != generation:
        raise ValueError("invalid Admin worker frame")
    value = decode_control(decoded[0])
    if value.get("v") != 1:
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
    def __init__(self, sock: socket.socket, args: argparse.Namespace, generation: int = 1):
        self._socket = sock
        self.args = args
        self._lock = threading.Lock()
        self._failed = False
        self._generation = generation

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
                                         "method": method, "args": args, "kwargs": kwargs, "deadline": deadline}, self._generation))
            reply = _read_socket_frame(self._socket, self._generation)
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


async def _serve_child(control_fd: int, lifetime_fd: int, log_fd: int | None, generation: int = 1) -> None:
    control = socket.socket(fileno=control_fd)
    lifetime = socket.socket(fileno=lifetime_fd)
    if (control.family != socket.AF_UNIX or control.type != socket.SOCK_STREAM
            or lifetime.family != socket.AF_UNIX or lifetime.type != socket.SOCK_STREAM
            or control_fd == lifetime_fd):
        raise ValueError("invalid Admin worker sockets")
    control.settimeout(5.0)
    hello = _read_socket_frame(control, generation)
    if hello != {"v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["admin.control"], "generation": generation}:
        raise ValueError("invalid Admin worker hello")
    control.sendall(_encode({"v": 1, "kind": "worker.hello", "role": "admin", "capabilities": ["admin.control"], "generation": generation}, generation))
    bootstrap = _read_socket_frame(control, generation)
    if bootstrap.get("kind") != "admin.start" or not isinstance(bootstrap.get("args"), dict):
        raise ValueError("invalid Admin worker startup")
    args = argparse.Namespace(**bootstrap["args"])
    log_socket = None
    if log_fd is not None:
        from .bridge_logging_worker import install_child_log_handler
        log_socket = install_child_log_handler(log_fd, int(bootstrap.get("log_root_level", logging.WARNING)),
                                               bootstrap.get("log_levels", {}))
    proxy = _RemoteRunner(control, args, generation)
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
        control.sendall(_encode({"v": 1, "kind": "admin.ready", "implementation": "python", "port": port}, generation))
        await stop.wait()
    finally:
        await ui.stop()
        lifetime.close()
        control.close()
        if log_socket is not None:
            log_socket.close()


class AdminWorker:
    def __init__(self, runner, args, *, implementation="python", native_executable=None, supervised=False):
        if implementation not in {"python", "native"}:
            raise ValueError("unsupported Admin worker implementation")
        self.runner = runner
        self.args = args
        self.implementation = implementation
        self.native_executable = native_executable
        self.process = None
        self.writer = None
        self.lifetime = None
        self._task = None
        self.port = 0
        self.last_error = ""
        self._stopping = False
        self._log_relay = None
        self._supervised = supervised
        self._monitor = None
        self.generation = 0
        self.restarts = 0
        self.failed_starts = 0

    async def start(self):
        if self._monitor is not None or self.process is not None:
            raise RuntimeError("Admin worker already started")
        self._stopping = False
        await self._start_child()
        if self._supervised:
            self._monitor = asyncio.create_task(self._supervise(), name="admin-worker-supervisor")

    async def _start_child(self):
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
            next_generation = self.generation + 1
            if self.implementation == "native":
                command = self._native_command(child_control.fileno(), child_lifetime.fileno(), next_generation)
            else:
                command = [sys.executable, "-m", "obstacle_bridge.bridge_admin_worker",
                           "--control-fd", str(child_control.fileno()), "--lifetime-fd", str(child_lifetime.fileno()), "--generation", str(next_generation)]
            inherited = [child_control.fileno(), child_lifetime.fileno()]
            if self._log_relay is not None:
                log_fd = self._log_relay.sender.fileno()
                command.extend([("--log-fd" if self.implementation == "python" else "--log-fd"), str(log_fd)])
                inherited.append(log_fd)
            self.process = await asyncio.create_subprocess_exec(
                *command, stdin=asyncio.subprocess.DEVNULL, pass_fds=tuple(inherited),
            )
            child_control.close(); child_lifetime.close()
            if self._log_relay is not None:
                self._log_relay.sender.close()
            control.setblocking(False)
            reader, self.writer = await asyncio.open_connection(sock=control)
            child_args = _serializable_args(self.args)
            # Preserve an ephemeral first bind across replacement without
            # changing the runner's persisted configuration.
            if self.generation and int(child_args.get("admin_web_port") or 0) == 0:
                child_args["admin_web_port"] = self.port
            self.writer.write(_encode({"v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["admin.control"], "generation": next_generation}, next_generation))
            await asyncio.wait_for(self.writer.drain(), 1.0)
            hello = await asyncio.wait_for(_read_frame(reader, next_generation), 5.0)
            if hello != {"v": 1, "kind": "worker.hello", "role": "admin", "capabilities": ["admin.control"], "generation": next_generation}:
                raise ValueError("invalid Admin worker hello")
            self.writer.write(_encode({"v": 1, "kind": "admin.start", "args": child_args,
                                       "log_root_level": logging.getLogger().level,
                                       "log_levels": {"admin_web": logging.getLogger("admin_web").level}}, next_generation))
            await asyncio.wait_for(self.writer.drain(), 1.0)
            while True:
                response = await asyncio.wait_for(_read_frame(reader, next_generation), 6.0)
                if response.get("kind") != "admin.call":
                    break
                await self._reply_to_request(response, next_generation)
            if response.get("kind") != "admin.ready" or response.get("implementation") != self.implementation:
                raise ValueError("invalid Admin worker readiness")
            self.port = int(response.get("port") or 0)
            self._task = asyncio.create_task(self._dispatch(reader))
            self.generation += 1
            self.last_error = ""
        except BaseException:
            control.close(); child_control.close(); child_lifetime.close()
            await self._stop_child()
            raise

    def _native_command(self, control_fd: int, lifetime_fd: int, generation: int) -> list[str]:
        default_executable = "ObstacleBridgeHostRunner" if sys.platform == "darwin" else "ObstacleBridgeLinux"
        executable = self.native_executable or os.environ.get("OBSTACLEBRIDGE_NATIVE_ADMIN_WORKER") or shutil.which(default_executable)
        if not executable or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            raise RuntimeError("native Admin worker executable is unavailable")
        return [
            executable,
            "--admin-worker-control-fd", str(control_fd),
            "--admin-worker-lifetime-fd", str(lifetime_fd),
            "--generation", str(generation),
        ]

    async def _supervise(self):
        while not self._stopping:
            waiter = asyncio.create_task(self.process.wait())
            try:
                await asyncio.wait((waiter, self._task), return_when=asyncio.FIRST_COMPLETED)
            finally:
                if not waiter.done():
                    waiter.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await waiter
            if self._stopping:
                return
            self.last_error = "Admin worker unavailable"
            await self._stop_child()
            delay = 0.25
            while not self._stopping:
                await asyncio.sleep(delay)
                try:
                    await self._start_child()
                except Exception:
                    self.failed_starts += 1
                    self.last_error = "Admin worker unavailable"
                    delay = min(delay * 2, 5.0)
                else:
                    self.restarts += 1
                    break

    async def _reply_to_request(self, request, generation: int):
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
            encoded = _encode(reply, generation)
        except Exception:
            encoded = _encode({"v": 1, "kind": "admin.reply", "id": request_id, "ok": False}, generation)
        self.writer.write(encoded)
        await asyncio.wait_for(self.writer.drain(), 1.0)

    async def _dispatch(self, reader: asyncio.StreamReader):
        try:
            while True:
                await self._reply_to_request(await _read_frame(reader, self.generation), self.generation)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError, OSError, asyncio.TimeoutError):
            if not self._stopping:
                self.last_error = "Admin worker unavailable"

    async def stop(self):
        self._stopping = True
        if self._monitor is not None:
            self._monitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor
            self._monitor = None
        await self._stop_child()

    async def _stop_child(self):
        if self.lifetime is not None:
            self.lifetime.close()
            self.lifetime = None
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
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
    parser.add_argument("--generation", type=int, default=1)
    args = parser.parse_args()
    try:
        asyncio.run(_serve_child(args.control_fd, args.lifetime_fd, args.log_fd, args.generation))
    except Exception:
        # Startup/control frames can contain secrets and are never logged.
        raise SystemExit(1)


if __name__ == "__main__":
    main()
