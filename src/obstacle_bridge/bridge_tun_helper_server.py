from __future__ import annotations

import argparse
import asyncio
import contextlib
import inspect
import json
import logging
import os
import signal
import sys
import time
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
from .bridge_tun_helper_local_transport import (
    is_local_tcp_endpoint,
    is_windows_pipe_path,
    start_local_tcp_server,
    start_windows_pipe_server,
)
from .bridge_tun_helper_windows import WindowsTunHelperBackend
from .bridge_tun_helper_settings import DEFAULT_TUN_HELPER_BACKEND
from .bridge_tun_ping import parse_internal_probe_packet


async def _start_local_helper_server(handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]], socket_path: str) -> asyncio.AbstractServer:
    if is_local_tcp_endpoint(socket_path):
        return await start_local_tcp_server(handler, socket_path)
    if sys.platform == "win32" and is_windows_pipe_path(socket_path):
        return await start_windows_pipe_server(handler, socket_path)
    starter = getattr(asyncio, "start_unix_server", None)
    if callable(starter):
        return await starter(handler, path=socket_path)
    if sys.platform == "win32":
        raise RuntimeError(
            "Windows helper transport is not implemented yet: current helper server supports only Unix-domain sockets."
        )
    raise RuntimeError("Local helper server transport is unavailable on this platform.")


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
    AUTHENTICATED_CLIENT_IDLE_TIMEOUT_S = 5.0

    def __init__(
        self,
        *,
        backend: TunHelperBackend,
        session_token: str,
        authenticated_client_idle_timeout_s: float = AUTHENTICATED_CLIENT_IDLE_TIMEOUT_S,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._backend = backend
        self._session_token = str(session_token or "")
        self._log = logger or logging.getLogger("tun_helper_server")
        self._authenticated_client_idle_timeout_s = max(float(authenticated_client_idle_timeout_s), 0.5)
        self._server: Optional[asyncio.AbstractServer] = None
        self._socket_path = ""
        self._active_writers: set[asyncio.StreamWriter] = set()
        self._authenticated_writers: set[asyncio.StreamWriter] = set()
        self._writer_locks: dict[asyncio.StreamWriter, asyncio.Lock] = {}
        self._closed = False
        self._watchdog_task: Optional[asyncio.Task] = None
        self._last_authenticated_client_at = time.monotonic()
        self._backend.set_packet_sink(self.emit_packet)

    def _log_probe_trace(self, *, stage: str, packet: bytes, note: str = "") -> None:
        parsed = parse_internal_probe_packet(bytes(packet or b""))
        if not isinstance(parsed, dict):
            return
        self._log.info(
            "[TUN/HELPER/PROBE] stage=%s dir=%s kind=%s key=%s/%s/%s/%s src=%s dst=%s note=%s",
            stage,
            str(parsed.get("direction") or ""),
            int(parsed.get("probe_kind") or 0),
            int(parsed.get("family") or 0),
            int(parsed.get("identifier") or 0),
            int(parsed.get("sequence") or 0),
            bytes(parsed.get("nonce") or b"").hex(),
            str(parsed.get("source_ip") or ""),
            str(parsed.get("destination_ip") or ""),
            note,
        )

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
        if is_windows_pipe_path(self._socket_path) or is_local_tcp_endpoint(self._socket_path):
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
        if not is_windows_pipe_path(self._socket_path) and not is_local_tcp_endpoint(self._socket_path):
            parent = os.path.dirname(self._socket_path)
            if parent:
                os.makedirs(parent, mode=0o700, exist_ok=True)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self._socket_path)
        self._server = await _start_local_helper_server(self._handle_client, self._socket_path)
        self._apply_socket_permissions()
        if self._watchdog_task is None:
            self._watchdog_task = asyncio.create_task(self._authenticated_client_watchdog())

    async def stop(self) -> None:
        self._closed = True
        current = asyncio.current_task()
        watchdog = self._watchdog_task
        self._watchdog_task = None
        if watchdog is not None and watchdog is not current:
            watchdog.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await watchdog
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=0.5)
            self._server = None
        for writer in list(self._active_writers):
            await self._close_writer(writer)
        self._active_writers.clear()
        await self._backend.stop()
        if self._socket_path and not is_windows_pipe_path(self._socket_path) and not is_local_tcp_endpoint(self._socket_path):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self._socket_path)

    def _mark_authenticated_client_activity(self) -> None:
        self._last_authenticated_client_at = time.monotonic()

    @staticmethod
    def _process_identity_snapshot() -> dict[str, Any]:
        uid: Optional[int] = None
        gid: Optional[int] = None
        user = ""
        group = ""
        geteuid = getattr(os, "geteuid", None)
        getegid = getattr(os, "getegid", None)
        with contextlib.suppress(Exception):
            if callable(geteuid):
                uid = int(geteuid())
        with contextlib.suppress(Exception):
            if callable(getegid):
                gid = int(getegid())
        if uid is not None:
            with contextlib.suppress(Exception):
                import pwd

                user = str(pwd.getpwuid(uid).pw_name or "")
        if gid is not None:
            with contextlib.suppress(Exception):
                import grp

                group = str(grp.getgrgid(gid).gr_name or "")
        return {
            "uid": uid,
            "gid": gid,
            "user": user,
            "group": group,
            "is_root": bool(uid == 0),
        }

    async def _authenticated_client_watchdog(self) -> None:
        while not self._closed:
            await asyncio.sleep(0.5)
            if self._closed:
                return
            if self._authenticated_writers:
                self._mark_authenticated_client_activity()
                continue
            if (time.monotonic() - self._last_authenticated_client_at) < self._authenticated_client_idle_timeout_s:
                continue
            self._log.warning(
                "[TUN/HELPER] no authenticated client for %.1fs; stopping helper and releasing resources",
                self._authenticated_client_idle_timeout_s,
            )
            asyncio.get_running_loop().create_task(self.stop())
            return

    async def emit_packet(self, packet: bytes) -> None:
        if not self._active_writers:
            return
        self._log_probe_trace(
            stage="server_emit_packet",
            packet=packet,
            note=f"writers={len(self._active_writers)}",
        )
        frame = encode_frame(TunHelperFrameKind.PACKET_FROM_HELPER, bytes(packet))
        dead: list[asyncio.StreamWriter] = []
        for writer in list(self._active_writers):
            try:
                await self._write_frame(writer, frame)
            except Exception:
                dead.append(writer)
        for writer in dead:
            self._active_writers.discard(writer)
            self._authenticated_writers.discard(writer)
            self._writer_locks.pop(writer, None)
            await self._close_writer(writer)

    async def _send_event(self, writer: asyncio.StreamWriter, text: str) -> None:
        await self._write_frame(writer, encode_frame(TunHelperFrameKind.EVENT, str(text).encode("utf-8")))

    async def _write_frame(self, writer: asyncio.StreamWriter, frame: bytes) -> None:
        lock = self._writer_locks.get(writer)
        if lock is None:
            lock = asyncio.Lock()
            self._writer_locks[writer] = lock
        async with lock:
            writer.write(frame)
            await writer.drain()

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        *,
        op: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> None:
        await self._write_frame(
            writer,
            encode_control_frame(
                TunHelperFrameKind.CONTROL_RESPONSE,
                TunHelperControlMessage(op=op, payload=payload or {}),
            ),
        )

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
            self._authenticated_writers.add(writer)
            self._mark_authenticated_client_activity()
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
        self._mark_authenticated_client_activity()
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
            async def _snapshot_with_server_state() -> dict[str, Any]:
                reply = dict(await _maybe_await(self._backend.snapshot()) or {})
                reply["active_authenticated_clients"] = int(len(self._authenticated_writers))
                reply["process_identity"] = self._process_identity_snapshot()
                return reply

            await _run_backend_call("SNAPSHOT_OK", _snapshot_with_server_state(), code="snapshot_failed")
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
        self._writer_locks.setdefault(writer, asyncio.Lock())
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
                        self._mark_authenticated_client_activity()
                        self._log_probe_trace(
                            stage="server_recv_packet_to_helper",
                            packet=bytes(payload),
                            note=f"authenticated={int(state.authenticated)}",
                        )
                        await _maybe_await(self._backend.write_packet(bytes(payload)))
                    else:
                        await self._send_response(
                            writer,
                            op="ERROR",
                            payload={"code": "unexpected_frame_kind", "detail": int(kind)},
                        )
        finally:
            self._active_writers.discard(writer)
            self._authenticated_writers.discard(writer)
            self._writer_locks.pop(writer, None)
            if not self._authenticated_writers:
                self._last_authenticated_client_at = time.monotonic()
            await self._close_writer(writer)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ObstacleBridge local TUN helper server")
    parser.add_argument("--config-path", default="", help="Optional JSON launch config path for compact helper handoff")
    parser.add_argument("--socket-path", default="", help="Unix socket path for the helper control channel")
    parser.add_argument("--session-token", default="", help="Session token required by the runtime client")
    parser.add_argument(
        "--backend",
        default=DEFAULT_TUN_HELPER_BACKEND,
        help="Helper backend identifier. Supported values include linux-native, linux-python, darwin-native, and windows-native.",
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


def _resolve_helper_launch_args(args: argparse.Namespace) -> dict[str, Any]:
    payload = _load_launch_config(str(getattr(args, "config_path", "") or ""))
    socket_path = str(payload.get("socket_path") or getattr(args, "socket_path", "") or "").strip()
    session_token = str(payload.get("session_token") or getattr(args, "session_token", "") or "").strip()
    backend = str(payload.get("backend") or getattr(args, "backend", "") or DEFAULT_TUN_HELPER_BACKEND).strip()
    log_level = str(payload.get("log_level") or getattr(args, "tun_helper_log_level", "") or "INFO").strip()
    idle_timeout_s = payload.get("authenticated_client_idle_timeout_s")
    if idle_timeout_s is None:
        idle_timeout_s = payload.get("client_idle_timeout_s")
    if idle_timeout_s is None:
        idle_timeout_s = TunHelperServer.AUTHENTICATED_CLIENT_IDLE_TIMEOUT_S
    if not socket_path:
        raise ValueError("helper socket path is required")
    if not session_token:
        raise ValueError("helper session token is required")
    return {
        "socket_path": socket_path,
        "session_token": session_token,
        "backend": backend,
        "log_level": log_level,
        "authenticated_client_idle_timeout_s": float(idle_timeout_s),
    }


def _backend_from_name(name: str) -> TunHelperBackend:
    normalized = str(name or "").strip().lower()
    if normalized in {"linux-python", "linux_python", "linux-python-memory"}:
        return LinuxTunHelperInMemoryBackend()
    if normalized in {"linux-native", "linux_native", "linux-real"}:
        return LinuxTunHelperBackend()
    if normalized in {"darwin-native", "darwin_native", "macos-native", "macos_native"}:
        from .bridge_tun_helper_macos import DarwinTunHelperBackend

        return DarwinTunHelperBackend()
    if normalized in {"windows-native", "windows_native", "wintun-native", "wintun_native"}:
        return WindowsTunHelperBackend()
    raise ValueError(f"unsupported tun helper backend: {name}")


async def run_helper_server(
    *,
    socket_path: str,
    session_token: str,
    backend_name: str = DEFAULT_TUN_HELPER_BACKEND,
    log_level: str = "INFO",
    authenticated_client_idle_timeout_s: float = TunHelperServer.AUTHENTICATED_CLIENT_IDLE_TIMEOUT_S,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    logging.getLogger("tun_helper_server").setLevel(str(log_level or "INFO").upper())
    server = TunHelperServer(
        backend=_backend_from_name(backend_name),
        session_token=session_token,
        authenticated_client_idle_timeout_s=authenticated_client_idle_timeout_s,
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
                authenticated_client_idle_timeout_s=float(launch["authenticated_client_idle_timeout_s"]),
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
