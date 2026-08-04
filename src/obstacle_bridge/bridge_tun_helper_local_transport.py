from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
from functools import partial
from multiprocessing.connection import Client as PipeClient
from multiprocessing.connection import Listener as PipeListener
from multiprocessing.connection import Connection as PipeConnection
from typing import Any, Awaitable, Callable, Optional


def is_windows_pipe_path(path: str) -> bool:
    text = str(path or "").strip()
    return text.startswith("\\\\.\\pipe\\")


def is_local_tcp_endpoint(path: str) -> bool:
    text = str(path or "").strip().lower()
    return text.startswith("tcp://")


def parse_local_tcp_endpoint(path: str) -> tuple[str, int]:
    text = str(path or "").strip()
    if not is_local_tcp_endpoint(text):
        raise ValueError(f"not a local TCP endpoint: {path!r}")
    host, sep, port_text = text[6:].rpartition(":")
    if not sep:
        raise ValueError(f"TCP endpoint is missing port: {path!r}")
    host = str(host or "").strip() or "127.0.0.1"
    port = int(str(port_text or "0").strip())
    if port <= 0:
        raise ValueError(f"TCP endpoint port must be positive: {path!r}")
    return host, port


def allocate_local_tcp_endpoint(host: str = "127.0.0.1") -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((str(host or "127.0.0.1"), 0))
        port = int(sock.getsockname()[1])
    return f"tcp://{str(host or '127.0.0.1')}:{port}"


async def _run_blocking(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(func, *args, **kwargs))


class PipeStreamReader:
    def __init__(self, conn: PipeConnection, io_lock: threading.Lock, *, background_pump: bool = True) -> None:
        self._conn = conn
        self._io_lock = io_lock
        self._background_pump = bool(background_pump)
        self._queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue()
        self._buffer = bytearray()
        self._closed = False
        self._failure: Optional[BaseException] = None
        self._pump_task: Optional[asyncio.Task] = None
        if self._background_pump:
            self._pump_task = asyncio.create_task(self._pump())

    def _recv_bytes_locked(self) -> bytes:
        with self._io_lock:
            return self._conn.recv_bytes()

    def _poll_locked(self, timeout_s: float) -> bool:
        with self._io_lock:
            return bool(self._conn.poll(timeout_s))

    async def _pump(self) -> None:
        try:
            while not self._closed:
                ready = await _run_blocking(self._poll_locked, 0.1)
                if not ready:
                    continue
                chunk = await _run_blocking(self._recv_bytes_locked)
                if chunk:
                    await self._queue.put(bytes(chunk))
        except (EOFError, BrokenPipeError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            self._failure = exc
        finally:
            self._closed = True
            await self._queue.put(None)

    async def read(self, size: int = -1) -> bytes:
        requested = int(size)
        while True:
            if self._buffer:
                if requested is None or requested < 0:
                    data = bytes(self._buffer)
                    self._buffer.clear()
                    return data
                data = bytes(self._buffer[:requested])
                del self._buffer[:requested]
                return data
            if self._closed:
                if self._failure is not None:
                    raise ConnectionError(str(self._failure))
                return b""
            if not self._background_pump:
                try:
                    chunk = await _run_blocking(self._recv_bytes_locked)
                except (EOFError, BrokenPipeError, OSError):
                    self._closed = True
                    continue
                except BaseException as exc:
                    self._failure = exc
                    self._closed = True
                    continue
                if chunk:
                    self._buffer.extend(chunk)
                continue
            chunk = await self._queue.get()
            if chunk is None:
                self._closed = True
                continue
            self._buffer.extend(chunk)

    def close(self) -> None:
        self._closed = True
        if self._pump_task is not None:
            self._pump_task.cancel()

    async def wait_closed(self) -> None:
        if self._pump_task is None:
            return
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._pump_task


class PipeStreamWriter:
    def __init__(self, conn: PipeConnection, reader: PipeStreamReader, io_lock: threading.Lock) -> None:
        self._conn = conn
        self._reader = reader
        self._io_lock = io_lock
        self._pending = bytearray()
        self._closed = False
        self._drain_lock = asyncio.Lock()
        self.transport = None

    def _send_bytes_locked(self, payload: bytes) -> None:
        with self._io_lock:
            self._conn.send_bytes(payload)

    def write(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("named pipe writer is closed")
        if data:
            self._pending.extend(bytes(data))

    async def drain(self) -> None:
        async with self._drain_lock:
            if self._closed:
                raise ConnectionError("named pipe writer is closed")
            if not self._pending:
                return
            payload = bytes(self._pending)
            self._pending.clear()
            try:
                await _run_blocking(self._send_bytes_locked, payload)
            except BaseException as exc:
                self._closed = True
                raise ConnectionError(str(exc)) from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self._conn.close()
        self._reader.close()

    async def wait_closed(self) -> None:
        self.close()
        await self._reader.wait_closed()


async def open_windows_pipe_connection(pipe_path: str) -> tuple[PipeStreamReader, PipeStreamWriter]:
    conn = await _run_blocking(PipeClient, str(pipe_path or ""), family="AF_PIPE", authkey=None)
    io_lock = threading.Lock()
    reader = PipeStreamReader(conn, io_lock, background_pump=True)
    writer = PipeStreamWriter(conn, reader, io_lock)
    return reader, writer


async def open_local_tcp_connection(endpoint: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    host, port = parse_local_tcp_endpoint(endpoint)
    return await asyncio.open_connection(host=host, port=port)


class WindowsPipeServer:
    def __init__(
        self,
        handler: Callable[[PipeStreamReader, PipeStreamWriter], Awaitable[None]],
        pipe_path: str,
        listener: PipeListener,
    ) -> None:
        self._handler = handler
        self._pipe_path = str(pipe_path or "")
        self._listener = listener
        self._closed = False
        self._client_tasks: set[asyncio.Task] = set()
        self._accept_task = asyncio.create_task(self._accept_loop())

    async def _accept_loop(self) -> None:
        while not self._closed:
            try:
                conn = await _run_blocking(self._listener.accept)
            except (EOFError, OSError):
                if self._closed:
                    return
                raise
            except asyncio.CancelledError:
                raise
            if self._closed:
                with contextlib.suppress(Exception):
                    conn.close()
                return
            io_lock = threading.Lock()
            reader = PipeStreamReader(conn, io_lock, background_pump=False)
            writer = PipeStreamWriter(conn, reader, io_lock)
            task = asyncio.create_task(self._handler(reader, writer))
            self._client_tasks.add(task)
            task.add_done_callback(self._client_tasks.discard)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        def _wake_acceptor() -> None:
            with contextlib.suppress(Exception):
                probe = PipeClient(self._pipe_path, family="AF_PIPE", authkey=None)
                probe.close()

        threading.Thread(target=_wake_acceptor, daemon=True).start()
        with contextlib.suppress(Exception):
            self._listener.close()

    async def wait_closed(self) -> None:
        self.close()
        if self._accept_task is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._accept_task
        for task in list(self._client_tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def start_windows_pipe_server(
    handler: Callable[[PipeStreamReader, PipeStreamWriter], Awaitable[None]],
    pipe_path: str,
) -> WindowsPipeServer:
    listener = await _run_blocking(PipeListener, str(pipe_path or ""), family="AF_PIPE", authkey=None)
    return WindowsPipeServer(handler, pipe_path, listener)


async def start_local_tcp_server(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    endpoint: str,
) -> asyncio.AbstractServer:
    host, port = parse_local_tcp_endpoint(endpoint)
    return await asyncio.start_server(handler, host=host, port=port)