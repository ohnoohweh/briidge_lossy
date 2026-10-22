from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import sys
from typing import Any, Optional

from .bridge_tun_helper_local_transport import (
    is_local_tcp_endpoint,
    is_windows_pipe_path,
    open_local_tcp_connection,
    open_windows_pipe_connection,
)

from .bridge_tun_helper_protocol import (
    TUN_HELPER_CAPABILITIES,
    TUN_HELPER_SERVER_ROLE,
    TunHelperControlMessage,
    TunHelperFrameKind,
    decode_control_payload,
    encode_control_frame,
    encode_hello,
    encode_frame,
    negotiated_hello,
    try_decode_frame,
)


async def _open_local_helper_connection(socket_path: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if is_local_tcp_endpoint(socket_path):
        return await open_local_tcp_connection(socket_path)
    if sys.platform == "win32" and is_windows_pipe_path(socket_path):
        return await open_windows_pipe_connection(socket_path)
    opener = getattr(asyncio, "open_unix_connection", None)
    if callable(opener):
        return await opener(socket_path)
    if sys.platform == "win32":
        raise RuntimeError(
            "Windows helper transport is not implemented yet: current helper client supports only Unix-domain sockets."
        )
    raise RuntimeError("Local helper client transport is unavailable on this platform.")


class TunHelperClient:
    def __init__(
        self,
        *,
        socket_path: str,
        session_token: str,
        response_timeout_s: float = 1.0,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._socket_path = str(socket_path or "")
        self._session_token = str(session_token or "")
        self._log = logger or logging.getLogger("tun_helper_client")
        self._response_timeout_s = float(response_timeout_s)
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._request_lock = asyncio.Lock()
        self._response_queue: asyncio.Queue[TunHelperControlMessage] = asyncio.Queue()
        self._packet_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._event_queue: asyncio.Queue[str] = asyncio.Queue()
        self._closed = False
        self._read_failed: Optional[BaseException] = None
        self._last_runtime_snapshot: dict[str, Any] = {}
        self._generation = secrets.randbits(64) or 1
        self._hello_queue: asyncio.Queue = asyncio.Queue()
        self._common_ready = False

    async def connect(self) -> None:
        if self._reader is not None and self._writer is not None:
            return
        self._reader, self._writer = await _open_local_helper_connection(self._socket_path)
        self._reader_task = asyncio.create_task(self._read_loop())
        self._writer.write(encode_hello(self._generation))
        await self._writer.drain()
        try:
            peer_hello = await asyncio.wait_for(self._hello_queue.get(), timeout=self._response_timeout_s)
            ready = await asyncio.wait_for(self._hello_queue.get(), timeout=self._response_timeout_s)
            role, capabilities = negotiated_hello(peer_hello)
            if peer_hello.kind != TunHelperFrameKind.HELLO or role != TUN_HELPER_SERVER_ROLE or set(capabilities) != set(TUN_HELPER_CAPABILITIES):
                raise ConnectionError("TUN helper rejected common IPC capability negotiation")
            if ready.kind != TunHelperFrameKind.READY or decode_control_payload(ready.payload).op != "READY":
                raise ConnectionError("TUN helper did not confirm common IPC readiness")
            self._common_ready = True
        except Exception:
            await self.close()
            raise
        hello = await self.request("HELLO", {"token": self._session_token})
        if hello.op != "HELLO_OK":
            raise ConnectionError(f"unexpected HELLO response: {hello.op}")

    async def close(self) -> None:
        self._closed = True
        if self._writer is not None:
            self._writer.close()
            transport = self._writer.transport if hasattr(self._writer, "transport") else None
            with contextlib.suppress(Exception):
                if transport is not None:
                    transport.abort()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer.wait_closed(), timeout=0.5)
        self._writer = None
        self._reader = None
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
        self._reader_task = None
        self._common_ready = False

    async def request(self, op: str, payload: Optional[dict[str, Any]] = None) -> TunHelperControlMessage:
        if self._writer is None:
            raise ConnectionError("TUN helper client is not connected")
        async with self._request_lock:
            self._raise_if_read_failed()
            self._log.info("[TUN/HELPER/CLIENT] request start op=%s payload_keys=%s", op, sorted((payload or {}).keys()))
            self._writer.write(
                encode_control_frame(
                    TunHelperFrameKind.REQUEST,
                    self._generation,
                    TunHelperControlMessage(op=str(op), payload=payload or {}),
                )
            )
            self._log.info("[TUN/HELPER/CLIENT] request drain start op=%s", op)
            await self._writer.drain()
            self._log.info("[TUN/HELPER/CLIENT] request drain done op=%s", op)
            try:
                message = await asyncio.wait_for(
                    self._response_queue.get(),
                    timeout=self._response_timeout_s,
                )
            except asyncio.CancelledError:
                self._log.warning("[TUN/HELPER/CLIENT] request cancelled op=%s", op)
                raise
            except asyncio.TimeoutError as exc:
                self._raise_if_read_failed()
                raise ConnectionError(f"TUN helper request timed out waiting for response to {op}") from exc
            self._log.info("[TUN/HELPER/CLIENT] request response op=%s reply=%s", op, message.op)
            if message.op == "ERROR":
                raise RuntimeError(str((message.payload or {}).get("detail") or "helper request failed"))
            return message

    async def open_tun(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        message = await self.request("OPEN_TUN", payload or {})
        opened = dict(message.payload)
        self._last_runtime_snapshot.update(opened)
        return opened

    async def apply_network(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        message = await self.request("APPLY_NETWORK", payload or {})
        applied = dict(message.payload)
        self._last_runtime_snapshot.update(applied)
        return applied

    async def remove_network(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        message = await self.request("REMOVE_NETWORK", payload or {})
        removed = dict(message.payload)
        self._last_runtime_snapshot.update(removed)
        return removed

    async def set_tun_enabled(self, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        message = await self.request("SET_TUN_ENABLED", payload or {})
        updated = dict(message.payload)
        self._last_runtime_snapshot.update(updated)
        return updated

    async def write_packet(self, packet: bytes) -> None:
        if self._writer is None:
            raise ConnectionError("TUN helper client is not connected")
        self._raise_if_read_failed()
        self._writer.write(encode_frame(TunHelperFrameKind.DATA, self._generation, bytes(packet)))
        await self._writer.drain()
        self._last_runtime_snapshot["packets_from_runtime"] = int(
            self._last_runtime_snapshot.get("packets_from_runtime") or 0
        ) + 1

    async def snapshot(self) -> dict[str, Any]:
        message = await self.request("SNAPSHOT", {})
        snap = dict(message.payload)
        self._last_runtime_snapshot = dict(snap)
        return snap

    def cached_snapshot(self) -> dict[str, Any]:
        return dict(self._last_runtime_snapshot)

    def connection_status(self) -> dict[str, Any]:
        error = ""
        if self._read_failed is not None:
            error = str(self._read_failed)
        connected = bool(
            not self._closed
            and self._writer is not None
            and self._reader is not None
            and self._read_failed is None
        )
        return {
            "connected": connected,
            "closed": bool(self._closed),
            "last_error": error,
        }

    async def read_packet(self) -> bytes:
        self._raise_if_read_failed()
        packet = await self._packet_queue.get()
        self._raise_if_read_failed()
        return packet

    async def read_event(self) -> str:
        self._raise_if_read_failed()
        event = await self._event_queue.get()
        self._raise_if_read_failed()
        return event

    def _raise_if_read_failed(self) -> None:
        if self._read_failed is None:
            return
        if isinstance(self._read_failed, ConnectionError):
            raise self._read_failed
        raise ConnectionError(str(self._read_failed))

    async def _read_loop(self) -> None:
        assert self._reader is not None
        buffer = b""
        try:
            while not self._closed:
                chunk = await self._reader.read(65536)
                if not chunk:
                    raise ConnectionError("TUN helper connection closed")
                buffer += chunk
                while True:
                    decoded = try_decode_frame(buffer)
                    if decoded is None:
                        break
                    frame, remainder = decoded
                    buffer = remainder
                    if frame.generation != self._generation:
                        raise ConnectionError("TUN helper sent a stale-generation frame")
                    if frame.kind in {TunHelperFrameKind.HELLO, TunHelperFrameKind.READY}:
                        await self._hello_queue.put(frame)
                    elif frame.kind == TunHelperFrameKind.RESPONSE:
                        await self._response_queue.put(decode_control_payload(frame.payload))
                    elif frame.kind == TunHelperFrameKind.ERROR:
                        await self._response_queue.put(TunHelperControlMessage(op="ERROR", payload=decode_control_payload(frame.payload).payload))
                    elif frame.kind == TunHelperFrameKind.DATA:
                        self._last_runtime_snapshot["packets_to_runtime"] = int(
                            self._last_runtime_snapshot.get("packets_to_runtime") or 0
                        ) + 1
                        await self._packet_queue.put(bytes(frame.payload))
                    elif frame.kind == TunHelperFrameKind.EVENT:
                        await self._event_queue.put(str(decode_control_payload(frame.payload).payload.get("detail") or ""))
                    else:
                        await self._event_queue.put(f"unexpected_frame_kind:{int(frame.kind)}")
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            self._read_failed = exc
            await self._response_queue.put(
                TunHelperControlMessage(
                    op="ERROR",
                    payload={"detail": str(exc)},
                )
            )
