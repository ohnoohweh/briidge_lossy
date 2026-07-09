from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from typing import Any, Optional

from .bridge_tun_helper_local_transport import (
    is_local_tcp_endpoint,
    is_windows_pipe_path,
    open_local_tcp_connection,
    open_windows_pipe_connection,
)

from .bridge_tun_helper_protocol import (
    TunHelperControlMessage,
    TunHelperFrameKind,
    decode_control_payload,
    encode_control_frame,
    encode_frame,
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

    async def connect(self) -> None:
        if self._reader is not None and self._writer is not None:
            return
        self._reader, self._writer = await _open_local_helper_connection(self._socket_path)
        self._reader_task = asyncio.create_task(self._read_loop())
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

    async def request(self, op: str, payload: Optional[dict[str, Any]] = None) -> TunHelperControlMessage:
        if self._writer is None:
            raise ConnectionError("TUN helper client is not connected")
        async with self._request_lock:
            self._raise_if_read_failed()
            self._log.info("[TUN/HELPER/CLIENT] request start op=%s payload_keys=%s", op, sorted((payload or {}).keys()))
            self._writer.write(
                encode_control_frame(
                    TunHelperFrameKind.CONTROL_REQUEST,
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

    async def write_packet(self, packet: bytes) -> None:
        if self._writer is None:
            raise ConnectionError("TUN helper client is not connected")
        self._raise_if_read_failed()
        self._writer.write(encode_frame(TunHelperFrameKind.PACKET_TO_HELPER, bytes(packet)))
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
                    kind, payload, remainder = decoded
                    buffer = remainder
                    if kind == TunHelperFrameKind.CONTROL_RESPONSE:
                        await self._response_queue.put(decode_control_payload(payload))
                    elif kind == TunHelperFrameKind.PACKET_FROM_HELPER:
                        self._last_runtime_snapshot["packets_to_runtime"] = int(
                            self._last_runtime_snapshot.get("packets_to_runtime") or 0
                        ) + 1
                        await self._packet_queue.put(bytes(payload))
                    elif kind == TunHelperFrameKind.EVENT:
                        await self._event_queue.put(payload.decode("utf-8", errors="replace"))
                    else:
                        await self._event_queue.put(f"unexpected_frame_kind:{int(kind)}")
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
