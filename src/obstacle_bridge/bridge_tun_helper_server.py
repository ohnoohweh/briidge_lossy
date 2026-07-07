from __future__ import annotations

import argparse
import asyncio
import contextlib
import inspect
import json
import logging
import os
import signal
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Protocol

from .bridge_tun_helper_protocol import (
    TunHelperControlMessage,
    TunHelperFrameKind,
    decode_control_payload,
    encode_control_frame,
    encode_frame,
    try_decode_frame,
)
from .bridge_tun_helper_linux import LinuxTunHelperBackend, LinuxTunHelperInMemoryBackend
from .bridge_tun_helper_macos import DarwinTunHelperBackend
from .bridge_tun_helper_settings import DEFAULT_TUN_HELPER_BACKEND


class TunHelperBackend(Protocol):
    def set_packet_sink(self, sink: Callable[[bytes], Awaitable[None] | None]) -> None: ...
    async def open_tun(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    async def apply_network(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    async def remove_network(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    async def write_packet(self, packet: bytes) -> dict[str, Any]: ...
    async def snapshot(self) -> dict[str, Any]: ...
    async def stop(self) -> None: ...


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


@dataclass
class _HelperConnectionState:
    authenticated: bool = False


class TunHelperServer:
    def __init__(
        self,
        *,
        backend: TunHelperBackend,
        session_token: str,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._backend = backend
        self._session_token = str(session_token or "")
        self._log = logger or logging.getLogger("tun_helper_server")
        self._server: Optional[asyncio.AbstractServer] = None
        self._socket_path = ""
        self._active_writers: set[asyncio.StreamWriter] = set()
        self._closed = False
        self._backend.set_packet_sink(self.emit_packet)

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter, *, timeout_s: float = 0.5) -> None:
        writer.close()
        transport = writer.transport if hasattr(writer, "transport") else None
        with contextlib.suppress(Exception):
            if transport is not None:
                transport.abort()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=timeout_s)

    @property
    def socket_path(self) -> str:
        return self._socket_path

    @staticmethod
    def _socket_owner_ids() -> tuple[Optional[int], Optional[int]]:
        uid_text = str(os.environ.get("SUDO_UID") or "").strip()
        gid_text = str(os.environ.get("SUDO_GID") or "").strip()
        uid: Optional[int] = None
        gid: Optional[int] = None
        with contextlib.suppress(Exception):
            if uid_text:
                uid = int(uid_text)
        with contextlib.suppress(Exception):
            if gid_text:
                gid = int(gid_text)
        return uid, gid

    def _apply_socket_permissions(self) -> None:
        if not self._socket_path:
            return
        uid, gid = self._socket_owner_ids()
        if uid is not None or gid is not None:
            with contextlib.suppress(Exception):
                os.chown(self._socket_path, uid if uid is not None else -1, gid if gid is not None else -1)
        mode = 0o600 if uid is not None else 0o660
        with contextlib.suppress(Exception):
            os.chmod(self._socket_path, mode)

    async def start(self, socket_path: str) -> None:
        if self._server is not None:
            return
        self._socket_path = str(socket_path or "")
        parent = os.path.dirname(self._socket_path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._socket_path)
        self._server = await asyncio.start_unix_server(self._handle_client, path=self._socket_path)
        self._apply_socket_permissions()

    async def stop(self) -> None:
        self._closed = True
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=0.5)
            self._server = None
        for writer in list(self._active_writers):
            await self._close_writer(writer)
        self._active_writers.clear()
        await self._backend.stop()
        if self._socket_path:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self._socket_path)

    async def emit_packet(self, packet: bytes) -> None:
        if not self._active_writers:
            return
        frame = encode_frame(TunHelperFrameKind.PACKET_FROM_HELPER, bytes(packet))
        dead: list[asyncio.StreamWriter] = []
        for writer in list(self._active_writers):
            try:
                writer.write(frame)
                await writer.drain()
            except Exception:
                dead.append(writer)
        for writer in dead:
            self._active_writers.discard(writer)
            await self._close_writer(writer)

    async def _send_event(self, writer: asyncio.StreamWriter, text: str) -> None:
        writer.write(encode_frame(TunHelperFrameKind.EVENT, str(text).encode("utf-8")))
        await writer.drain()

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        *,
        op: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> None:
        writer.write(
            encode_control_frame(
                TunHelperFrameKind.CONTROL_RESPONSE,
                TunHelperControlMessage(op=op, payload=payload or {}),
            )
        )
        await writer.drain()

    async def _handle_control(
        self,
        state: _HelperConnectionState,
        writer: asyncio.StreamWriter,
        message: TunHelperControlMessage,
    ) -> None:
        op = str(message.op or "").strip().upper()
        payload = dict(message.payload)
        if op == "HELLO":
            token = str(payload.get("token") or "")
            if token != self._session_token:
                await self._send_response(
                    writer,
                    op="ERROR",
                    payload={"code": "auth_failed", "detail": "invalid session token"},
                )
                return
            state.authenticated = True
            await self._send_response(
                writer,
                op="HELLO_OK",
                payload={"authenticated": True},
            )
            return
        if not state.authenticated:
            await self._send_response(
                writer,
                op="ERROR",
                payload={"code": "not_authenticated", "detail": "HELLO required before helper commands"},
            )
            return
        async def _run_backend_call(reply_op: str, awaitable: Any, *, code: str) -> bool:
            try:
                reply = await _maybe_await(awaitable)
            except Exception as exc:
                self._log.warning("[TUN/HELPER] backend %s failed err=%r", op, exc)
                await self._send_response(
                    writer,
                    op="ERROR",
                    payload={"code": code, "detail": str(exc)},
                )
                return False
            await self._send_response(writer, op=reply_op, payload=dict(reply or {}))
            return True
        if op == "OPEN_TUN":
            await _run_backend_call("OPEN_TUN_OK", self._backend.open_tun(payload), code="open_tun_failed")
            return
        if op == "APPLY_NETWORK":
            await _run_backend_call("APPLY_NETWORK_OK", self._backend.apply_network(payload), code="apply_network_failed")
            return
        if op == "REMOVE_NETWORK":
            await _run_backend_call("REMOVE_NETWORK_OK", self._backend.remove_network(payload), code="remove_network_failed")
            return
        if op == "SNAPSHOT":
            await _run_backend_call("SNAPSHOT_OK", self._backend.snapshot(), code="snapshot_failed")
            return
        if op == "STOP":
            await self._send_response(writer, op="STOP_OK", payload={"stopping": True})
            await self._send_event(writer, "helper stopping")
            asyncio.get_running_loop().create_task(self.stop())
            return
        await self._send_response(
            writer,
            op="ERROR",
            payload={"code": "unsupported_op", "detail": op},
        )

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        state = _HelperConnectionState()
        self._active_writers.add(writer)
        buffer = b""
        try:
            while not self._closed:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buffer += chunk
                while True:
                    decoded = try_decode_frame(buffer)
                    if decoded is None:
                        break
                    kind, payload, remainder = decoded
                    buffer = remainder
                    if kind == TunHelperFrameKind.CONTROL_REQUEST:
                        try:
                            message = decode_control_payload(payload)
                        except Exception as exc:
                            await self._send_response(
                                writer,
                                op="ERROR",
                                payload={"code": "bad_control_payload", "detail": str(exc)},
                            )
                            continue
                        await self._handle_control(state, writer, message)
                    elif kind == TunHelperFrameKind.PACKET_TO_HELPER:
                        if not state.authenticated:
                            await self._send_response(
                                writer,
                                op="ERROR",
                                payload={"code": "not_authenticated", "detail": "HELLO required before helper packet writes"},
                            )
                            continue
                        await _maybe_await(self._backend.write_packet(bytes(payload)))
                    else:
                        await self._send_response(
                            writer,
                            op="ERROR",
                            payload={"code": "unexpected_frame_kind", "detail": int(kind)},
                        )
        finally:
            self._active_writers.discard(writer)
            await self._close_writer(writer)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ObstacleBridge local TUN helper server")
    parser.add_argument("--config-path", default="", help="Optional JSON launch config path for compact helper handoff")
    parser.add_argument("--socket-path", default="", help="Unix socket path for the helper control channel")
    parser.add_argument("--session-token", default="", help="Session token required by the runtime client")
    parser.add_argument(
        "--backend",
        default=DEFAULT_TUN_HELPER_BACKEND,
        help="Helper backend identifier. Supported values include linux-native, linux-python, and darwin-native.",
    )
    parser.add_argument(
        "--log-tun-helper",
        dest="tun_helper_log_level",
        default="INFO",
        help="Log level for helper-side logging.",
    )
    return parser


def _load_launch_config(path: str) -> dict[str, Any]:
    config_path = str(path or "").strip()
    if not config_path:
        return {}
    with open(config_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("helper launch config must be a JSON object")
    return dict(payload)


def _resolve_helper_launch_args(args: argparse.Namespace) -> dict[str, str]:
    payload = _load_launch_config(str(getattr(args, "config_path", "") or ""))
    socket_path = str(payload.get("socket_path") or getattr(args, "socket_path", "") or "").strip()
    session_token = str(payload.get("session_token") or getattr(args, "session_token", "") or "").strip()
    backend = str(payload.get("backend") or getattr(args, "backend", "") or DEFAULT_TUN_HELPER_BACKEND).strip()
    log_level = str(payload.get("log_level") or getattr(args, "tun_helper_log_level", "") or "INFO").strip()
    if not socket_path:
        raise ValueError("helper socket path is required")
    if not session_token:
        raise ValueError("helper session token is required")
    return {
        "socket_path": socket_path,
        "session_token": session_token,
        "backend": backend,
        "log_level": log_level,
    }


def _backend_from_name(name: str) -> TunHelperBackend:
    normalized = str(name or "").strip().lower()
    if normalized in {"linux-python", "linux_python", "linux-python-memory"}:
        return LinuxTunHelperInMemoryBackend()
    if normalized in {"linux-native", "linux_native", "linux-real"}:
        return LinuxTunHelperBackend()
    if normalized in {"darwin-native", "darwin_native", "macos-native", "macos_native"}:
        return DarwinTunHelperBackend()
    raise ValueError(f"unsupported tun helper backend: {name}")


async def run_helper_server(
    *,
    socket_path: str,
    session_token: str,
    backend_name: str = DEFAULT_TUN_HELPER_BACKEND,
    log_level: str = "INFO",
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    logging.getLogger("tun_helper_server").setLevel(str(log_level or "INFO").upper())
    server = TunHelperServer(
        backend=_backend_from_name(backend_name),
        session_token=session_token,
        logger=logging.getLogger("tun_helper_server"),
    )
    stopper = stop_event if stop_event is not None else asyncio.Event()
    await server.start(socket_path)
    try:
        await stopper.wait()
    finally:
        await server.stop()


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    launch = _resolve_helper_launch_args(args)
    logging.basicConfig(level=str(launch["log_level"] or "INFO").upper())

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        stop_event = asyncio.Event()

        def _request_stop() -> None:
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, _request_stop)
        loop.run_until_complete(
            run_helper_server(
                socket_path=str(launch["socket_path"]),
                session_token=str(launch["session_token"]),
                backend_name=str(launch["backend"]),
                log_level=str(launch["log_level"]),
                stop_event=stop_event,
            )
        )
    finally:
        with contextlib.suppress(Exception):
            loop.run_until_complete(loop.shutdown_asyncgens())
        asyncio.set_event_loop(None)
        loop.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
